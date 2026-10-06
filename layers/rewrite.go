package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

// PacketRewrite describes optional field replacements applied by
// RewritePacket. A nil IP address or nil port pointer leaves the
// corresponding field untouched.
type PacketRewrite struct {
	// SrcIP and DstIP, when non-nil, replace the source and destination
	// addresses of the IP header. The address family must match the
	// packet: IPv4 packets only accept IPv4 addresses and IPv6 packets
	// only accept IPv6 addresses.
	SrcIP net.IP
	DstIP net.IP
	// SrcPort and DstPort, when non-nil, replace the source and
	// destination ports of the TCP or UDP header.
	SrcPort *uint16
	DstPort *uint16
}

// PacketRewriteChanges reports which fields RewritePacket actually
// modified. A field flag is true only when the configured replacement
// differs from the original value. Checksum flags indicate that the
// corresponding checksum was recomputed.
type PacketRewriteChanges struct {
	SrcIP             bool
	DstIP             bool
	SrcPort           bool
	DstPort           bool
	IPv4Checksum      bool
	TransportChecksum bool
}

// Changed reports whether any field was modified.
func (c *PacketRewriteChanges) Changed() bool {
	return c.SrcIP || c.DstIP || c.SrcPort || c.DstPort ||
		c.IPv4Checksum || c.TransportChecksum
}

// RewritePacket rewrites the source/destination addresses and
// source/destination ports of a complete TCP or UDP packet, for offline
// preparation of test traffic. packet must start at the IP header (IPv4
// or IPv6) and may contain trailing bytes beyond the IP payload (for
// example capture padding); those bytes are preserved verbatim.
//
// The returned slice is an independent copy of the input; the input is
// never modified, and on error both the returned slice and the changes
// report are nil. Only the requested fields and the checksums covering
// them are touched: payload, IP/TCP options, extension header layouts
// and any trailing bytes are preserved byte for byte.
//
// The IPv4 header checksum is recomputed when an address changes, and
// the TCP/UDP checksum is recomputed with a pseudo-header built from the
// new addresses whenever any rewritten field changes. An IPv4 UDP
// checksum of zero is preserved as zero (RFC 768); for IPv6 the UDP
// checksum is always computed, and a computed value of zero is
// transmitted as 0xffff as required on the wire.
//
// Fragmented packets (other than IPv6 atomic fragments, which are
// treated as complete packets) and truncated packets are rejected. IPv6
// packets carrying a Routing, AH or ESP header, a jumbogram, or an
// upper-layer protocol that cannot be located unambiguously are also
// rejected, since rewriting them would require semantics this function
// does not implement.
func RewritePacket(packet []byte, rw *PacketRewrite) ([]byte, *PacketRewriteChanges, error) {
	if len(packet) == 0 {
		return nil, nil, errors.New("cannot rewrite empty packet")
	}
	changes := &PacketRewriteChanges{}
	var out []byte
	var err error
	switch version := packet[0] >> 4; version {
	case 4:
		out, err = rewriteIPv4Packet(packet, rw, changes)
	case 6:
		out, err = rewriteIPv6Packet(packet, rw, changes)
	default:
		return nil, nil, fmt.Errorf("cannot rewrite packet with IP version %d", version)
	}
	if err != nil {
		return nil, nil, err
	}
	return out, changes, nil
}

// rewriteAddrs validates the configured addresses against the packet
// address family and returns them in wire form. Nil addresses are
// returned as nil.
func rewriteAddrs(rw *PacketRewrite, ipv6 bool) (src, dst net.IP, err error) {
	if rw == nil {
		return nil, nil, nil
	}
	convert := func(ip net.IP, what string) (net.IP, error) {
		if ip == nil {
			return nil, nil
		}
		if ipv6 {
			if ip.To4() != nil {
				return nil, fmt.Errorf("%s address %v is not an IPv6 address", what, ip)
			}
			if ip16 := ip.To16(); ip16 != nil {
				return ip16, nil
			}
			return nil, fmt.Errorf("invalid %s IPv6 address %v", what, ip)
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return nil, fmt.Errorf("%s address %v is not an IPv4 address", what, ip)
	}
	if src, err = convert(rw.SrcIP, "source"); err != nil {
		return nil, nil, err
	}
	if dst, err = convert(rw.DstIP, "destination"); err != nil {
		return nil, nil, err
	}
	return src, dst, nil
}

// checkTransportBounds verifies that a complete TCP or UDP header (and,
// for UDP, the full datagram) is present within packet[off:ipEnd].
func checkTransportBounds(packet []byte, off, ipEnd int, proto IPProtocol) error {
	switch proto {
	case IPProtocolTCP:
		if ipEnd-off < 20 {
			return fmt.Errorf("truncated TCP header: %d bytes available", ipEnd-off)
		}
	case IPProtocolUDP:
		if ipEnd-off < 8 {
			return fmt.Errorf("truncated UDP header: %d bytes available", ipEnd-off)
		}
		udpLen := int(binary.BigEndian.Uint16(packet[off+4:]))
		if udpLen == 0 {
			return errors.New("cannot rewrite UDP jumbogram (UDP length 0)")
		}
		if udpLen < 8 {
			return fmt.Errorf("invalid UDP length %d", udpLen)
		}
		if off+udpLen > ipEnd {
			return fmt.Errorf("truncated UDP datagram: length %d exceeds %d available bytes", udpLen, ipEnd-off)
		}
	}
	return nil
}

// rewritePorts applies the configured port replacements to the
// transport header at the start of transport.
func rewritePorts(transport []byte, rw *PacketRewrite, changes *PacketRewriteChanges) (changed bool) {
	if rw == nil {
		return false
	}
	if rw.SrcPort != nil && binary.BigEndian.Uint16(transport[0:2]) != *rw.SrcPort {
		binary.BigEndian.PutUint16(transport[0:2], *rw.SrcPort)
		changes.SrcPort = true
		changed = true
	}
	if rw.DstPort != nil && binary.BigEndian.Uint16(transport[2:4]) != *rw.DstPort {
		binary.BigEndian.PutUint16(transport[2:4], *rw.DstPort)
		changes.DstPort = true
		changed = true
	}
	return changed
}

// transportChecksum computes the TCP or UDP checksum over segment with
// a pseudo-header built from src, dst and proto. segment must have its
// checksum field zeroed.
func transportChecksum(src, dst net.IP, proto IPProtocol, segment []byte) uint16 {
	var csum uint32
	csum = gopacket.ComputeChecksum(src, csum)
	csum = gopacket.ComputeChecksum(dst, csum)
	length := uint32(len(segment))
	csum += uint32(proto)
	csum += length & 0xffff
	csum += length >> 16
	csum = gopacket.ComputeChecksum(segment, csum)
	return gopacket.FoldChecksum(csum)
}

// rewriteTransportChecksum recomputes the checksum of the TCP or UDP
// header at transportOff, using the (already rewritten) addresses in the
// IP header of out. ipEnd is the end of the IP payload within out.
func rewriteTransportChecksum(out []byte, transportOff, ipEnd int, proto IPProtocol, ipv6 bool, changes *PacketRewriteChanges) {
	srcOff, dstOff, addrLen := 12, 16, 4
	if ipv6 {
		srcOff, dstOff, addrLen = 8, 24, 16
	}
	src := out[srcOff : srcOff+addrLen]
	dst := out[dstOff : dstOff+addrLen]
	switch proto {
	case IPProtocolTCP:
		csumOff := transportOff + 16
		out[csumOff], out[csumOff+1] = 0, 0
		sum := transportChecksum(src, dst, proto, out[transportOff:ipEnd])
		binary.BigEndian.PutUint16(out[csumOff:], sum)
		changes.TransportChecksum = true
	case IPProtocolUDP:
		csumOff := transportOff + 6
		if !ipv6 && binary.BigEndian.Uint16(out[csumOff:]) == 0 {
			// RFC 768: a zero UDP checksum means no checksum was
			// generated; keep it zero.
			return
		}
		udpLen := int(binary.BigEndian.Uint16(out[transportOff+4:]))
		out[csumOff], out[csumOff+1] = 0, 0
		sum := transportChecksum(src, dst, proto, out[transportOff:transportOff+udpLen])
		if sum == 0 {
			// A computed checksum of zero is transmitted as all
			// ones; zero means "no checksum" on the wire.
			sum = 0xffff
		}
		binary.BigEndian.PutUint16(out[csumOff:], sum)
		changes.TransportChecksum = true
	}
}

func rewriteIPv4Packet(packet []byte, rw *PacketRewrite, changes *PacketRewriteChanges) ([]byte, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("truncated IPv4 header: %d bytes available", len(packet))
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 {
		return nil, fmt.Errorf("invalid IPv4 header length %d", ihl)
	}
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLen < ihl {
		return nil, fmt.Errorf("invalid IPv4 total length %d smaller than header length %d", totalLen, ihl)
	}
	if totalLen > len(packet) {
		return nil, fmt.Errorf("truncated IPv4 packet: total length %d exceeds %d available bytes", totalLen, len(packet))
	}
	if frag := binary.BigEndian.Uint16(packet[6:8]); frag&0x3fff != 0 {
		return nil, errors.New("cannot rewrite fragmented IPv4 packet")
	}
	proto := IPProtocol(packet[9])
	if proto != IPProtocolTCP && proto != IPProtocolUDP {
		return nil, fmt.Errorf("cannot rewrite IPv4 protocol %v: only TCP and UDP are supported", proto)
	}
	src, dst, err := rewriteAddrs(rw, false)
	if err != nil {
		return nil, err
	}
	if err := checkTransportBounds(packet, ihl, totalLen, proto); err != nil {
		return nil, err
	}

	out := make([]byte, len(packet))
	copy(out, packet)

	addrChanged := false
	if src != nil && !bytes.Equal(out[12:16], src) {
		copy(out[12:16], src)
		changes.SrcIP = true
		addrChanged = true
	}
	if dst != nil && !bytes.Equal(out[16:20], dst) {
		copy(out[16:20], dst)
		changes.DstIP = true
		addrChanged = true
	}
	if addrChanged {
		out[10], out[11] = 0, 0
		sum := gopacket.FoldChecksum(gopacket.ComputeChecksum(out[:ihl], 0))
		binary.BigEndian.PutUint16(out[10:], sum)
		changes.IPv4Checksum = true
	}
	portChanged := rewritePorts(out[ihl:], rw, changes)
	if addrChanged || portChanged {
		rewriteTransportChecksum(out, ihl, totalLen, proto, false, changes)
	}
	return out, nil
}

// checkIPv6HopByHopJumbogram rejects hop-by-hop headers carrying a
// Jumbo Payload option (RFC 2675), whose length semantics this rewriter
// does not implement. hbh starts at the hop-by-hop header and extends to
// the end of the IPv6 payload.
func checkIPv6HopByHopJumbogram(hbh []byte) error {
	hdrLen := (int(hbh[1]) + 1) * 8
	if hdrLen > len(hbh) {
		hdrLen = len(hbh) // bounds are validated by the caller
	}
	for offset := 2; offset < hdrLen; {
		optType := hbh[offset]
		if optType == 0 { // Pad1
			offset++
			continue
		}
		if offset+2 > hdrLen {
			break
		}
		if optType == IPv6HopByHopOptionJumbogram {
			return errors.New("cannot rewrite IPv6 jumbogram (Jumbo Payload option present)")
		}
		offset += 2 + int(hbh[offset+1])
	}
	return nil
}

func rewriteIPv6Packet(packet []byte, rw *PacketRewrite, changes *PacketRewriteChanges) ([]byte, error) {
	if len(packet) < 40 {
		return nil, fmt.Errorf("truncated IPv6 header: %d bytes available", len(packet))
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	if payloadLen == 0 {
		return nil, errors.New("cannot rewrite IPv6 jumbogram (payload length 0)")
	}
	if payloadLen > len(packet)-40 {
		return nil, fmt.Errorf("truncated IPv6 packet: payload length %d exceeds %d available bytes", payloadLen, len(packet)-40)
	}
	ipEnd := 40 + payloadLen
	src, dst, err := rewriteAddrs(rw, true)
	if err != nil {
		return nil, err
	}

	// Walk the extension header chain to locate the transport header.
	offset := 40
	next := IPProtocol(packet[6])
walk:
	for {
		switch next {
		case IPProtocolTCP, IPProtocolUDP:
			break walk
		case IPProtocolIPv6HopByHop, IPProtocolIPv6Destination:
			if offset+2 > ipEnd {
				return nil, errors.New("truncated IPv6 extension header")
			}
			if next == IPProtocolIPv6HopByHop {
				if err := checkIPv6HopByHopJumbogram(packet[offset:ipEnd]); err != nil {
					return nil, err
				}
			}
			hdrLen := (int(packet[offset+1]) + 1) * 8
			if offset+hdrLen > ipEnd {
				return nil, errors.New("truncated IPv6 extension header")
			}
			next = IPProtocol(packet[offset])
			offset += hdrLen
		case IPProtocolIPv6Fragment:
			if offset+8 > ipEnd {
				return nil, errors.New("truncated IPv6 fragment header")
			}
			// An atomic fragment (offset 0, M flag clear) is a
			// complete packet per RFC 6946 and may be rewritten.
			if frag := binary.BigEndian.Uint16(packet[offset+2:]); frag&0xfff9 != 0 {
				return nil, errors.New("cannot rewrite fragmented IPv6 packet")
			}
			next = IPProtocol(packet[offset])
			offset += 8
		case IPProtocolIPv6Routing, IPProtocolAH, IPProtocolESP:
			return nil, fmt.Errorf("cannot rewrite IPv6 packet with %v header", next)
		default:
			return nil, fmt.Errorf("cannot locate IPv6 upper-layer header: unsupported next header %v", next)
		}
	}
	if err := checkTransportBounds(packet, offset, ipEnd, next); err != nil {
		return nil, err
	}

	out := make([]byte, len(packet))
	copy(out, packet)

	addrChanged := false
	if src != nil && !bytes.Equal(out[8:24], src) {
		copy(out[8:24], src)
		changes.SrcIP = true
		addrChanged = true
	}
	if dst != nil && !bytes.Equal(out[24:40], dst) {
		copy(out[24:40], dst)
		changes.DstIP = true
		addrChanged = true
	}
	portChanged := rewritePorts(out[offset:], rw, changes)
	if addrChanged || portChanged {
		rewriteTransportChecksum(out, offset, ipEnd, next, true, changes)
	}
	return out, nil
}
