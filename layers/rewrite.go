package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

// PacketRewrite describes optional field replacements for RewritePacket.
// Any nil field keeps its original value.
type PacketRewrite struct {
	// SrcIP and DstIP replace the IP source/destination addresses. The
	// address family must match the packet: an IPv4 packet only accepts
	// IPv4 addresses, an IPv6 packet only IPv6 addresses.
	SrcIP net.IP
	DstIP net.IP
	// SrcPort and DstPort replace the TCP/UDP source/destination ports.
	// They only apply when the transport header is reachable.
	SrcPort *uint16
	DstPort *uint16
}

// PacketRewriteChange describes a single requested field that RewritePacket
// actually modified. Checksum updates derived from those fields are not
// listed.
type PacketRewriteChange struct {
	Field string
	Old   string
	New   string
}

func (c PacketRewriteChange) String() string {
	return fmt.Sprintf("%s: %s -> %s", c.Field, c.Old, c.New)
}

// RewritePacket rewrites the addresses and/or ports of a serialized IP
// packet, offline, without decoding or re-encoding any other part of it.
//
// pkt must start at the IP header. TCP and UDP over IPv4 and IPv6 are
// supported. The returned byte slice is an independent copy; pkt is never
// modified, not even on error. The returned changes list contains every
// requested field whose value actually differed from the original.
//
// Only the requested address/port fields and the checksums covering them
// are touched: the IPv4 header checksum is recomputed when an address
// changes, and the TCP/UDP checksum is recomputed (with a pseudo-header
// built from the new addresses) when an address or port changes. Payload,
// TCP/IP option layouts, and any buffer bytes beyond the IP total/payload
// length are preserved byte for byte.
//
// An IPv4 UDP checksum of zero is preserved as zero. An IPv6 UDP checksum
// is always computed; a computed value of zero is written as 0xffff on the
// wire, as required by RFC 768.
//
// Real fragments (IPv4 MF/offset, IPv6 fragment header with offset or M
// flag) and truncated packets are rejected; an IPv6 atomic fragment
// (offset 0, M clear) is treated as a whole packet. IPv6 packets carrying
// a Routing header, AH, ESP, a Jumbogram, or an upper-layer position that
// cannot be determined are rejected rather than risk emitting a wrong
// checksum.
func RewritePacket(pkt []byte, rw *PacketRewrite) ([]byte, []PacketRewriteChange, error) {
	if rw == nil {
		rw = &PacketRewrite{}
	}
	if len(pkt) == 0 {
		return nil, nil, errors.New("rewrite: empty packet")
	}
	switch pkt[0] >> 4 {
	case 4:
		return rewriteIPv4Packet(pkt, rw)
	case 6:
		return rewriteIPv6Packet(pkt, rw)
	default:
		return nil, nil, fmt.Errorf("rewrite: unsupported IP version %d", pkt[0]>>4)
	}
}

// rewritePorts applies the configured port changes to the transport header
// at out[off:]. It reports whether any port actually changed.
func rewritePorts(out []byte, off int, rw *PacketRewrite, changes *[]PacketRewriteChange) bool {
	changed := false
	if rw.SrcPort != nil {
		if old := binary.BigEndian.Uint16(out[off:]); old != *rw.SrcPort {
			*changes = append(*changes, PacketRewriteChange{
				Field: "SrcPort",
				Old:   fmt.Sprint(old),
				New:   fmt.Sprint(*rw.SrcPort),
			})
			binary.BigEndian.PutUint16(out[off:], *rw.SrcPort)
			changed = true
		}
	}
	if rw.DstPort != nil {
		if old := binary.BigEndian.Uint16(out[off+2:]); old != *rw.DstPort {
			*changes = append(*changes, PacketRewriteChange{
				Field: "DstPort",
				Old:   fmt.Sprint(old),
				New:   fmt.Sprint(*rw.DstPort),
			})
			binary.BigEndian.PutUint16(out[off+2:], *rw.DstPort)
			changed = true
		}
	}
	return changed
}

// transportLayout locates and validates the TCP or UDP header at
// out[off:], where the containing IP payload ends at total. It returns the
// offset of the transport checksum field and the transport length to use
// for the pseudo-header.
func transportLayout(out []byte, off, total int, proto IPProtocol) (csumOff, transLen int, err error) {
	switch proto {
	case IPProtocolTCP:
		if total-off < 20 {
			return 0, 0, fmt.Errorf("rewrite: truncated TCP header (%d bytes available)", total-off)
		}
		dataOff := int(out[off+12]>>4) * 4
		if dataOff < 20 || off+dataOff > total {
			return 0, 0, fmt.Errorf("rewrite: invalid TCP data offset %d", dataOff)
		}
		return off + 16, total - off, nil
	case IPProtocolUDP:
		if total-off < 8 {
			return 0, 0, fmt.Errorf("rewrite: truncated UDP header (%d bytes available)", total-off)
		}
		udpLen := int(binary.BigEndian.Uint16(out[off+4:]))
		if udpLen < 8 || off+udpLen > total {
			return 0, 0, fmt.Errorf("rewrite: invalid UDP length %d", udpLen)
		}
		return off + 6, udpLen, nil
	}
	return 0, 0, fmt.Errorf("rewrite: unsupported transport protocol %s", proto)
}

// pseudoChecksum sums src, dst, the protocol number and the transport
// length into the start of a TCP/UDP pseudo-header checksum.
func pseudoChecksum(src, dst []byte, proto IPProtocol, length uint32) uint32 {
	csum := gopacket.ComputeChecksum(src, 0)
	csum = gopacket.ComputeChecksum(dst, csum)
	csum += uint32(proto)
	csum += length & 0xffff
	csum += length >> 16
	return csum
}

// rewriteTransportChecksum recomputes the checksum of the TCP/UDP header
// at out[off:] using the addresses already written into the IP header at
// out[srcOff:srcOff+addrLen] and out[dstOff:dstOff+addrLen]. For IPv4 UDP
// a zero checksum in the original packet is preserved; otherwise a
// computed checksum of zero is written as 0xffff on the wire.
func rewriteTransportChecksum(out, pkt []byte, off, csumOff, transLen int, proto IPProtocol, srcOff, dstOff, addrLen int, ipv4 bool) {
	if ipv4 && proto == IPProtocolUDP && binary.BigEndian.Uint16(pkt[csumOff:]) == 0 {
		// RFC 768: a zero IPv4 UDP checksum means "no checksum"; keep it.
		return
	}
	out[csumOff], out[csumOff+1] = 0, 0
	csum := pseudoChecksum(out[srcOff:srcOff+addrLen], out[dstOff:dstOff+addrLen], proto, uint32(transLen))
	csum = gopacket.ComputeChecksum(out[off:off+transLen], csum)
	folded := gopacket.FoldChecksum(csum)
	if folded == 0 {
		folded = 0xffff
	}
	binary.BigEndian.PutUint16(out[csumOff:], folded)
}

func rewriteIPv4Packet(pkt []byte, rw *PacketRewrite) ([]byte, []PacketRewriteChange, error) {
	if len(pkt) < 20 {
		return nil, nil, fmt.Errorf("rewrite: truncated IPv4 header (%d bytes)", len(pkt))
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, nil, fmt.Errorf("rewrite: truncated IPv4 header (IHL %d, %d bytes)", ihl, len(pkt))
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl {
		return nil, nil, fmt.Errorf("rewrite: IPv4 total length %d smaller than header %d", totalLen, ihl)
	}
	if totalLen > len(pkt) {
		return nil, nil, fmt.Errorf("rewrite: truncated IPv4 packet (total length %d, %d bytes)", totalLen, len(pkt))
	}
	if frag := binary.BigEndian.Uint16(pkt[6:8]); frag&0x3fff != 0 {
		// MF flag or non-zero fragment offset: a real fragment.
		return nil, nil, errors.New("rewrite: fragmented IPv4 packets are not supported")
	}
	proto := IPProtocol(pkt[9])
	if proto != IPProtocolTCP && proto != IPProtocolUDP {
		return nil, nil, fmt.Errorf("rewrite: unsupported IPv4 protocol %s", proto)
	}
	var src, dst net.IP
	if rw.SrcIP != nil {
		if src = rw.SrcIP.To4(); src == nil {
			return nil, nil, errors.New("rewrite: cannot put a non-IPv4 source address into an IPv4 packet")
		}
	}
	if rw.DstIP != nil {
		if dst = rw.DstIP.To4(); dst == nil {
			return nil, nil, errors.New("rewrite: cannot put a non-IPv4 destination address into an IPv4 packet")
		}
	}
	if _, _, err := transportLayout(pkt, ihl, totalLen, proto); err != nil {
		return nil, nil, err
	}

	out := make([]byte, len(pkt))
	copy(out, pkt)
	var changes []PacketRewriteChange
	addrChanged := false
	if src != nil {
		if old := net.IP(out[12:16]); !old.Equal(src) {
			changes = append(changes, PacketRewriteChange{Field: "SrcIP", Old: old.String(), New: src.String()})
			copy(out[12:16], src)
			addrChanged = true
		}
	}
	if dst != nil {
		if old := net.IP(out[16:20]); !old.Equal(dst) {
			changes = append(changes, PacketRewriteChange{Field: "DstIP", Old: old.String(), New: dst.String()})
			copy(out[16:20], dst)
			addrChanged = true
		}
	}
	portChanged := rewritePorts(out, ihl, rw, &changes)

	if addrChanged || portChanged {
		csumOff, transLen, _ := transportLayout(out, ihl, totalLen, proto)
		rewriteTransportChecksum(out, pkt, ihl, csumOff, transLen, proto, 12, 16, 4, true)
	}
	if addrChanged {
		out[10], out[11] = 0, 0
		csum := gopacket.ComputeChecksum(out[:ihl], 0)
		binary.BigEndian.PutUint16(out[10:], gopacket.FoldChecksum(csum))
	}
	return out, changes, nil
}

// locateIPv6Transport walks the IPv6 extension header chain starting at
// pkt[40:] and returns the offset of the TCP/UDP header. total is the end
// of the IPv6 payload. Headers whose semantics RewritePacket cannot honor
// are rejected.
func locateIPv6Transport(pkt []byte, total int) (off int, proto IPProtocol, err error) {
	next := IPProtocol(pkt[6])
	off = 40
	for {
		switch next {
		case IPProtocolTCP, IPProtocolUDP:
			return off, next, nil
		case IPProtocolIPv6HopByHop, IPProtocolIPv6Destination:
			if off+2 > total {
				return 0, 0, fmt.Errorf("rewrite: truncated IPv6 extension header at offset %d", off)
			}
			hlen := (int(pkt[off+1]) + 1) * 8
			if off+hlen > total {
				return 0, 0, fmt.Errorf("rewrite: truncated IPv6 extension header at offset %d", off)
			}
			next = IPProtocol(pkt[off])
			off += hlen
		case IPProtocolIPv6Fragment:
			if off+8 > total {
				return 0, 0, fmt.Errorf("rewrite: truncated IPv6 fragment header at offset %d", off)
			}
			if frag := binary.BigEndian.Uint16(pkt[off+2:]); frag&0xfff9 != 0 {
				// Non-zero offset or M flag: a real fragment. Atomic
				// fragments (offset 0, M clear) are whole packets.
				return 0, 0, errors.New("rewrite: fragmented IPv6 packets are not supported")
			}
			next = IPProtocol(pkt[off])
			off += 8
		case IPProtocolIPv6Routing:
			return 0, 0, errors.New("rewrite: IPv6 routing headers are not supported")
		case IPProtocolAH:
			return 0, 0, errors.New("rewrite: IPv6 AH is not supported")
		case IPProtocolESP:
			return 0, 0, errors.New("rewrite: IPv6 ESP is not supported")
		case IPProtocolNoNextHeader:
			return 0, 0, errors.New("rewrite: IPv6 packet has no upper-layer header")
		default:
			return 0, 0, fmt.Errorf("rewrite: cannot locate upper-layer header behind IPv6 next header %s", next)
		}
	}
}

func rewriteIPv6Packet(pkt []byte, rw *PacketRewrite) ([]byte, []PacketRewriteChange, error) {
	if len(pkt) < 40 {
		return nil, nil, fmt.Errorf("rewrite: truncated IPv6 header (%d bytes)", len(pkt))
	}
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	if payloadLen == 0 {
		return nil, nil, errors.New("rewrite: IPv6 jumbograms are not supported")
	}
	total := 40 + payloadLen
	if total > len(pkt) {
		return nil, nil, fmt.Errorf("rewrite: truncated IPv6 packet (payload length %d, %d bytes)", payloadLen, len(pkt)-40)
	}
	off, proto, err := locateIPv6Transport(pkt, total)
	if err != nil {
		return nil, nil, err
	}
	var src, dst net.IP
	if rw.SrcIP != nil {
		if rw.SrcIP.To4() != nil {
			return nil, nil, errors.New("rewrite: cannot put an IPv4 source address into an IPv6 packet")
		}
		if src = rw.SrcIP.To16(); src == nil {
			return nil, nil, errors.New("rewrite: invalid source address")
		}
	}
	if rw.DstIP != nil {
		if rw.DstIP.To4() != nil {
			return nil, nil, errors.New("rewrite: cannot put an IPv4 destination address into an IPv6 packet")
		}
		if dst = rw.DstIP.To16(); dst == nil {
			return nil, nil, errors.New("rewrite: invalid destination address")
		}
	}
	if _, _, err := transportLayout(pkt, off, total, proto); err != nil {
		return nil, nil, err
	}

	out := make([]byte, len(pkt))
	copy(out, pkt)
	var changes []PacketRewriteChange
	addrChanged := false
	if src != nil {
		if old := net.IP(out[8:24]); !old.Equal(src) {
			changes = append(changes, PacketRewriteChange{Field: "SrcIP", Old: old.String(), New: src.String()})
			copy(out[8:24], src)
			addrChanged = true
		}
	}
	if dst != nil {
		if old := net.IP(out[24:40]); !old.Equal(dst) {
			changes = append(changes, PacketRewriteChange{Field: "DstIP", Old: old.String(), New: dst.String()})
			copy(out[24:40], dst)
			addrChanged = true
		}
	}
	portChanged := rewritePorts(out, off, rw, &changes)

	if addrChanged || portChanged {
		csumOff, transLen, _ := transportLayout(out, off, total, proto)
		rewriteTransportChecksum(out, pkt, off, csumOff, transLen, proto, 8, 24, 16, false)
	}
	return out, changes, nil
}
