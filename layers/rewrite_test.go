package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

func u16ptr(v uint16) *uint16 { return &v }

func mustSerialize(t *testing.T, opts gopacket.SerializeOptions, layers ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, opts, layers...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// foldSum folds a 32 bit sum to 16 bits without complementing it.
func foldSum(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

// transportChecksumOf independently computes the TCP/UDP checksum of
// segment (checksum field already zeroed) with a pseudo-header built
// from src, dst and proto.
func transportChecksumOf(src, dst net.IP, proto IPProtocol, segment []byte) uint16 {
	var csum uint32
	csum = gopacket.ComputeChecksum(src, csum)
	csum = gopacket.ComputeChecksum(dst, csum)
	csum += uint32(proto)
	csum += uint32(len(segment)) & 0xffff
	csum += uint32(len(segment)) >> 16
	csum = gopacket.ComputeChecksum(segment, csum)
	return gopacket.FoldChecksum(csum)
}

// ipv4HeaderChecksumOf independently computes the IPv4 header checksum.
func ipv4HeaderChecksumOf(hdr []byte) uint16 {
	c := append([]byte(nil), hdr...)
	c[10], c[11] = 0, 0
	return gopacket.FoldChecksum(gopacket.ComputeChecksum(c, 0))
}

// wireTCPChecksum reports whether the TCP checksum found on the wire
// matches an independent recomputation.
func wireTCPChecksum(pkt []byte, tportOff, ipEnd int, src, dst net.IP) bool {
	seg := append([]byte(nil), pkt[tportOff:ipEnd]...)
	want := binary.BigEndian.Uint16(seg[16:18])
	seg[16], seg[17] = 0, 0
	return transportChecksumOf(src, dst, IPProtocolTCP, seg) == want
}

// wireUDPChecksum reports whether the UDP checksum found on the wire
// matches an independent recomputation over the UDP datagram.
func wireUDPChecksum(pkt []byte, tportOff int, src, dst net.IP) bool {
	udpLen := int(binary.BigEndian.Uint16(pkt[tportOff+4:]))
	seg := append([]byte(nil), pkt[tportOff:tportOff+udpLen]...)
	want := binary.BigEndian.Uint16(seg[6:8])
	seg[6], seg[7] = 0, 0
	return transportChecksumOf(src, dst, IPProtocolUDP, seg) == want
}

type byteRange struct{ start, end int }

// assertOnlyRangesDiffer fails the test if orig and out differ in
// length or in any byte outside the given [start, end) ranges.
func assertOnlyRangesDiffer(t *testing.T, orig, out []byte, ranges []byteRange) {
	t.Helper()
	if len(orig) != len(out) {
		t.Fatalf("packet length changed: %d -> %d", len(orig), len(out))
	}
	allowed := func(i int) bool {
		for _, r := range ranges {
			if i >= r.start && i < r.end {
				return true
			}
		}
		return false
	}
	for i := range orig {
		if orig[i] != out[i] && !allowed(i) {
			t.Errorf("byte %d changed outside allowed ranges: 0x%02x -> 0x%02x", i, orig[i], out[i])
		}
	}
}

func TestRewritePacketIPv4TCP(t *testing.T) {
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	ip := &IPv4{
		Version: 4, TTL: 64, Protocol: IPProtocolTCP,
		SrcIP: srcIP, DstIP: dstIP,
		Options: []IPv4Option{
			{OptionType: 1},
			{OptionType: 131, OptionLength: 4, OptionData: []byte{0xde, 0xad}},
		},
	}
	tcp := &TCP{
		SrcPort: 1234, DstPort: 80,
		Seq: 12345, SYN: true, Window: 65535,
		Options: []TCPOption{
			{OptionType: TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello payload")
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	pkt := mustSerialize(t, opts, ip, tcp, gopacket.Payload(payload))
	pkt = append(pkt, 0xaa, 0xbb, 0xcc, 0xdd) // trailing sentinel beyond IP length
	orig := append([]byte(nil), pkt...)

	newSrc := net.IP{192, 0, 2, 1}
	newDst := net.IP{198, 51, 100, 7}
	rw := &PacketRewrite{
		SrcIP: newSrc, DstIP: newDst,
		SrcPort: u16ptr(40000), DstPort: u16ptr(8080),
	}
	out, changes, err := RewritePacket(pkt, rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if !bytes.Equal(pkt, orig) {
		t.Fatal("input packet was modified")
	}
	wantChanges := &PacketRewriteChanges{
		SrcIP: true, DstIP: true, SrcPort: true, DstPort: true,
		IPv4Checksum: true, TransportChecksum: true,
	}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}

	ihl := int(out[0]&0x0f) * 4
	ipEnd := int(binary.BigEndian.Uint16(out[2:4]))
	// Only the IPv4 checksum, the addresses, the TCP ports and the TCP
	// checksum may differ; options, payload and the sentinel must be
	// preserved byte for byte.
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{10, 12},
		{12, 20},
		{ihl, ihl + 4},
		{ihl + 16, ihl + 18},
	})

	if got := out[12:16]; !bytes.Equal(got, newSrc) {
		t.Errorf("src IP = %v, want %v", got, newSrc)
	}
	if got := out[16:20]; !bytes.Equal(got, newDst) {
		t.Errorf("dst IP = %v, want %v", got, newDst)
	}
	if got := binary.BigEndian.Uint16(out[ihl:]); got != 40000 {
		t.Errorf("src port = %d, want 40000", got)
	}
	if got := binary.BigEndian.Uint16(out[ihl+2:]); got != 8080 {
		t.Errorf("dst port = %d, want 8080", got)
	}
	if got, want := binary.BigEndian.Uint16(out[10:12]), ipv4HeaderChecksumOf(out[:ihl]); got != want {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0x%04x", got, want)
	}
	if !wireTCPChecksum(out, ihl, ipEnd, newSrc, newDst) {
		t.Error("TCP checksum does not match independent recomputation")
	}

	p := gopacket.NewPacket(out, LayerTypeIPv4, gopacket.DecodeOptions{})
	if p.ErrorLayer() != nil {
		t.Fatalf("rewritten packet does not decode: %v", p.ErrorLayer().Error())
	}
	gotTCP := p.Layer(LayerTypeTCP).(*TCP)
	if gotTCP.SrcPort != 40000 || gotTCP.DstPort != 8080 {
		t.Errorf("decoded ports = %v/%v, want 40000/8080", gotTCP.SrcPort, gotTCP.DstPort)
	}
	if got := p.Layer(LayerTypeIPv4).(*IPv4); !got.SrcIP.Equal(newSrc) || !got.DstIP.Equal(newDst) {
		t.Errorf("decoded IPs = %v/%v, want %v/%v", got.SrcIP, got.DstIP, newSrc, newDst)
	}

	// Rewriting the original values back must restore the original
	// valid packet byte for byte.
	back, _, err := RewritePacket(out, &PacketRewrite{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: u16ptr(1234), DstPort: u16ptr(80),
	})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting original values back did not restore the original packet")
	}
}

func serializeIPv4UDP(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort UDPPort, payload []byte) []byte {
	t.Helper()
	ip := &IPv4{Version: 4, TTL: 64, Protocol: IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &UDP{SrcPort: srcPort, DstPort: dstPort}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	return mustSerialize(t, opts, ip, udp, gopacket.Payload(payload))
}

func TestRewritePacketIPv4UDPZeroChecksumPreserved(t *testing.T) {
	srcIP := net.IP{172, 16, 0, 1}
	dstIP := net.IP{172, 16, 0, 2}
	pkt := serializeIPv4UDP(t, srcIP, dstIP, 53, 5353, []byte("dns-ish"))
	// A zero UDP checksum is legal for IPv4 and means "no checksum".
	pkt[26], pkt[27] = 0, 0
	orig := append([]byte(nil), pkt...)

	out, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcIP: net.IP{192, 0, 2, 9}, DstIP: net.IP{192, 0, 2, 10},
		DstPort: u16ptr(8053),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if !bytes.Equal(pkt, orig) {
		t.Fatal("input packet was modified")
	}
	wantChanges := &PacketRewriteChanges{
		SrcIP: true, DstIP: true, DstPort: true, IPv4Checksum: true,
	}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}
	if got := binary.BigEndian.Uint16(out[26:28]); got != 0 {
		t.Errorf("UDP checksum = 0x%04x, want preserved zero", got)
	}
	ihl := int(out[0]&0x0f) * 4
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{10, 12},
		{12, 20},
		{ihl, ihl + 4},
	})
	if got, want := binary.BigEndian.Uint16(out[10:12]), ipv4HeaderChecksumOf(out[:ihl]); got != want {
		t.Errorf("IPv4 header checksum = 0x%04x, want 0x%04x", got, want)
	}
}

func TestRewritePacketIPv4UDPPortOnly(t *testing.T) {
	srcIP := net.IP{10, 1, 1, 1}
	dstIP := net.IP{10, 1, 1, 2}
	pkt := serializeIPv4UDP(t, srcIP, dstIP, 1000, 2000, []byte("some udp payload"))
	orig := append([]byte(nil), pkt...)

	out, changes, err := RewritePacket(pkt, &PacketRewrite{SrcPort: u16ptr(4500)})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := &PacketRewriteChanges{SrcPort: true, TransportChecksum: true}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}
	ihl := int(out[0]&0x0f) * 4
	// Only the source port and the UDP checksum may change; in
	// particular the IPv4 header checksum must be untouched.
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{ihl, ihl + 2},
		{ihl + 6, ihl + 8},
	})
	if !wireUDPChecksum(out, ihl, srcIP, dstIP) {
		t.Error("UDP checksum does not match independent recomputation")
	}
	if got := binary.BigEndian.Uint16(out[ihl+6:]); got == 0 {
		t.Error("UDP checksum must not be zero after rewrite")
	}
}

func TestRewritePacketUDPChecksumTransmittedAsAllOnes(t *testing.T) {
	src6 := net.ParseIP("2001:db8::1")
	dst6 := net.ParseIP("2001:db8::2")
	newSrc6 := net.ParseIP("2001:db8:ffff::1234")
	build := func(payloadWord uint16) []byte {
		ip6 := &IPv6{
			Version: 6, HopLimit: 64, NextHeader: IPProtocolUDP,
			SrcIP: src6, DstIP: dst6,
		}
		udp := &UDP{SrcPort: 1000, DstPort: 2000}
		if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte(payloadWord >> 8), byte(payloadWord)}
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		return mustSerialize(t, opts, ip6, udp, gopacket.Payload(payload))
	}
	rw := &PacketRewrite{SrcIP: newSrc6}

	// Tune the 2-byte payload so that the checksum computed over the
	// rewritten packet is exactly zero; on the wire that must be
	// transmitted as 0xffff.
	out, _, err := RewritePacket(build(0), rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	seg := append([]byte(nil), out[40:]...)
	seg[6], seg[7] = 0, 0
	var csum uint32
	csum = gopacket.ComputeChecksum(newSrc6, csum)
	csum = gopacket.ComputeChecksum(dst6, csum)
	csum += uint32(IPProtocolUDP)
	csum += uint32(len(seg))
	csum = gopacket.ComputeChecksum(seg, csum)
	payloadWord := ^foldSum(csum)

	pkt := build(payloadWord)
	out, changes, err := RewritePacket(pkt, rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if !changes.TransportChecksum {
		t.Error("expected transport checksum recomputation")
	}
	if got := binary.BigEndian.Uint16(out[46:48]); got != 0xffff {
		t.Errorf("UDP checksum = 0x%04x, want 0xffff (computed checksum of zero)", got)
	}
	// Independently confirm that the computed checksum really is zero.
	seg = append([]byte(nil), out[40:]...)
	seg[6], seg[7] = 0, 0
	if got := transportChecksumOf(newSrc6, dst6, IPProtocolUDP, seg); got != 0 {
		t.Errorf("independently computed UDP checksum = 0x%04x, want 0", got)
	}
}

func serializeIPv6TCP(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort TCPPort, payload []byte) []byte {
	t.Helper()
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolTCP,
		SrcIP: srcIP, DstIP: dstIP,
	}
	tcp := &TCP{SrcPort: srcPort, DstPort: dstPort, Seq: 999, ACK: true, Window: 4096}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	return mustSerialize(t, opts, ip6, tcp, gopacket.Payload(payload))
}

func TestRewritePacketIPv6TCP(t *testing.T) {
	src6 := net.ParseIP("2001:db8::1")
	dst6 := net.ParseIP("2001:db8::2")
	pkt := serializeIPv6TCP(t, src6, dst6, 443, 50000, []byte("ipv6 tcp payload"))
	pkt = append(pkt, 0x5e, 0x6e, 0x7e) // trailing sentinel beyond IP payload
	orig := append([]byte(nil), pkt...)

	newSrc6 := net.ParseIP("2001:db8:aaaa::1")
	newDst6 := net.ParseIP("2001:db8:bbbb::2")
	out, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcIP: newSrc6, DstIP: newDst6,
		SrcPort: u16ptr(8443), DstPort: u16ptr(50001),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if !bytes.Equal(pkt, orig) {
		t.Fatal("input packet was modified")
	}
	wantChanges := &PacketRewriteChanges{
		SrcIP: true, DstIP: true, SrcPort: true, DstPort: true,
		TransportChecksum: true,
	}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}

	ipEnd := 40 + int(binary.BigEndian.Uint16(out[4:6]))
	// Only the addresses, TCP ports and TCP checksum may differ.
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{8, 40},
		{40, 44},
		{56, 58},
	})
	if got := net.IP(out[8:24]); !got.Equal(newSrc6) {
		t.Errorf("src IP = %v, want %v", got, newSrc6)
	}
	if got := net.IP(out[24:40]); !got.Equal(newDst6) {
		t.Errorf("dst IP = %v, want %v", got, newDst6)
	}
	if !wireTCPChecksum(out, 40, ipEnd, newSrc6, newDst6) {
		t.Error("TCP checksum does not match independent recomputation")
	}

	p := gopacket.NewPacket(out, LayerTypeIPv6, gopacket.DecodeOptions{})
	if p.ErrorLayer() != nil {
		t.Fatalf("rewritten packet does not decode: %v", p.ErrorLayer().Error())
	}
	gotTCP := p.Layer(LayerTypeTCP).(*TCP)
	if gotTCP.SrcPort != 8443 || gotTCP.DstPort != 50001 {
		t.Errorf("decoded ports = %v/%v, want 8443/50001", gotTCP.SrcPort, gotTCP.DstPort)
	}

	back, _, err := RewritePacket(out, &PacketRewrite{
		SrcIP: src6, DstIP: dst6,
		SrcPort: u16ptr(443), DstPort: u16ptr(50000),
	})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting original values back did not restore the original packet")
	}
}

func TestRewritePacketIPv6UDP(t *testing.T) {
	src6 := net.ParseIP("fd00::1")
	dst6 := net.ParseIP("fd00::2")
	ip6 := &IPv6{Version: 6, HopLimit: 32, NextHeader: IPProtocolUDP, SrcIP: src6, DstIP: dst6}
	udp := &UDP{SrcPort: 123, DstPort: 456}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	pkt := mustSerialize(t, opts, ip6, udp, gopacket.Payload([]byte("ntp-ish")))
	orig := append([]byte(nil), pkt...)

	newDst6 := net.ParseIP("fd00::dead:beef")
	out, changes, err := RewritePacket(pkt, &PacketRewrite{DstIP: newDst6})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := &PacketRewriteChanges{DstIP: true, TransportChecksum: true}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}
	// Only the destination address and the UDP checksum may differ.
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{24, 40},
		{46, 48},
	})
	if got := binary.BigEndian.Uint16(out[46:48]); got == 0 {
		t.Error("IPv6 UDP checksum must be computed, not zero")
	}
	if !wireUDPChecksum(out, 40, src6, newDst6) {
		t.Error("UDP checksum does not match independent recomputation")
	}
}

func TestRewritePacketIPv6AtomicFragment(t *testing.T) {
	src6 := net.ParseIP("2001:db8:1::1")
	dst6 := net.ParseIP("2001:db8:1::2")
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Fragment,
		SrcIP: src6, DstIP: dst6,
	}
	// An atomic fragment (offset 0, M flag clear) is a complete packet.
	frag := &IPv6Fragment{NextHeader: IPProtocolTCP, Identification: 0xdeadbeef}
	tcp := &TCP{SrcPort: 22, DstPort: 2222, SYN: true, Window: 8192}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	pkt := mustSerialize(t, opts, ip6, frag, tcp, gopacket.Payload([]byte("ssh-ish")))
	orig := append([]byte(nil), pkt...)

	newSrc6 := net.ParseIP("2001:db8:2::1")
	out, changes, err := RewritePacket(pkt, &PacketRewrite{SrcIP: newSrc6})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := &PacketRewriteChanges{SrcIP: true, TransportChecksum: true}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}
	// Only the source address and the TCP checksum may differ; the
	// fragment header must be preserved byte for byte.
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{8, 24},
		{64, 66},
	})
	ipEnd := 40 + int(binary.BigEndian.Uint16(out[4:6]))
	if !wireTCPChecksum(out, 48, ipEnd, newSrc6, dst6) {
		t.Error("TCP checksum does not match independent recomputation")
	}

	back, _, err := RewritePacket(out, &PacketRewrite{SrcIP: src6})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting original values back did not restore the original packet")
	}
}

func TestRewritePacketIPv6ExtensionHeaders(t *testing.T) {
	src6 := net.ParseIP("2001:db8:3::1")
	dst6 := net.ParseIP("2001:db8:3::2")
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6HopByHop,
		SrcIP: src6, DstIP: dst6,
	}
	hbh := &IPv6HopByHop{
		ipv6ExtensionBase: ipv6ExtensionBase{NextHeader: IPProtocolIPv6Destination},
		Options:           []*IPv6HopByHopOption{{OptionType: 0x1e, OptionData: []byte{1, 2, 3, 4}}},
	}
	dst := &IPv6Destination{
		ipv6ExtensionBase: ipv6ExtensionBase{NextHeader: IPProtocolUDP},
		Options:           []*IPv6DestinationOption{{OptionType: 0x3c, OptionData: []byte{5, 6, 7, 8}}},
	}
	udp := &UDP{SrcPort: 5000, DstPort: 5001}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	pkt := mustSerialize(t, opts, ip6, hbh, dst, udp, gopacket.Payload([]byte("ext chain")))
	orig := append([]byte(nil), pkt...)

	newSrc6 := net.ParseIP("2001:db8:4::1")
	newDst6 := net.ParseIP("2001:db8:4::2")
	out, changes, err := RewritePacket(pkt, &PacketRewrite{SrcIP: newSrc6, DstIP: newDst6})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := &PacketRewriteChanges{SrcIP: true, DstIP: true, TransportChecksum: true}
	if *changes != *wantChanges {
		t.Errorf("changes = %+v, want %+v", changes, wantChanges)
	}

	// Locate the UDP header by walking the extension chain, then check
	// that only the addresses and the UDP checksum changed.
	udpOff := 40
	for next := IPProtocol(out[6]); next != IPProtocolUDP; {
		next = IPProtocol(out[udpOff])
		udpOff += (int(out[udpOff+1]) + 1) * 8
	}
	assertOnlyRangesDiffer(t, orig, out, []byteRange{
		{8, 40},
		{udpOff + 6, udpOff + 8},
	})
	if !wireUDPChecksum(out, udpOff, newSrc6, newDst6) {
		t.Error("UDP checksum does not match independent recomputation")
	}
}

func TestRewritePacketNoFieldsConfigured(t *testing.T) {
	pkt := serializeIPv4UDP(t, net.IP{10, 9, 9, 1}, net.IP{10, 9, 9, 2}, 1, 2, []byte("x"))
	pkt = append(pkt, 0x01, 0x02)
	samePort := binary.BigEndian.Uint16(pkt[20:22])
	rws := []*PacketRewrite{
		nil,
		{},
		// Configuring the current values must also be a no-op.
		{SrcIP: net.IP{10, 9, 9, 1}, SrcPort: u16ptr(samePort)},
	}
	for i, rw := range rws {
		out, changes, err := RewritePacket(pkt, rw)
		if err != nil {
			t.Fatalf("case %d: RewritePacket: %v", i, err)
		}
		if !bytes.Equal(out, pkt) {
			t.Errorf("case %d: packet changed without configured fields", i)
		}
		if *changes != (PacketRewriteChanges{}) || changes.Changed() {
			t.Errorf("case %d: changes = %+v, want all false", i, changes)
		}
		// The output must be an independent copy.
		out[0] ^= 0xff
		if pkt[0] == out[0] {
			t.Errorf("case %d: output aliases the input", i)
		}
	}
}

func TestRewritePacketRejections(t *testing.T) {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	v4TCP := func() []byte {
		ip := &IPv4{Version: 4, TTL: 64, Protocol: IPProtocolTCP, SrcIP: net.IP{10, 0, 0, 1}, DstIP: net.IP{10, 0, 0, 2}}
		tcp := &TCP{SrcPort: 1, DstPort: 2, SYN: true}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		return mustSerialize(t, opts, ip, tcp, gopacket.Payload([]byte("data")))
	}
	v6TCP := func() []byte {
		return serializeIPv6TCP(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1, 2, []byte("data"))
	}
	v6WithNextHeader := func(next IPProtocol, payload []byte) []byte {
		ip6 := &IPv6{
			Version: 6, HopLimit: 64, NextHeader: next,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
		}
		return mustSerialize(t, opts, ip6, gopacket.Payload(payload))
	}
	v6Fragment := func(offset uint16, more bool) []byte {
		ip6 := &IPv6{
			Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Fragment,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
		}
		frag := &IPv6Fragment{
			NextHeader: IPProtocolTCP, FragmentOffset: offset,
			MoreFragments: more, Identification: 1,
		}
		tcp := &TCP{SrcPort: 1, DstPort: 2}
		if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
		return mustSerialize(t, opts, ip6, frag, tcp, gopacket.Payload([]byte("data")))
	}

	rw4 := &PacketRewrite{SrcIP: net.IP{192, 0, 2, 1}, DstPort: u16ptr(9999)}
	rw6 := &PacketRewrite{SrcIP: net.ParseIP("2001:db8::ffff"), DstPort: u16ptr(9999)}

	truncatedV4 := v4TCP()
	truncatedV4 = truncatedV4[:len(truncatedV4)-1]
	truncatedV4TCP := v4TCP()
	binary.BigEndian.PutUint16(truncatedV4TCP[2:4], 20+10)
	truncatedV4TCP = truncatedV4TCP[:30]
	mfV4 := v4TCP()
	mfV4[6] |= 0x20
	offsetV4 := v4TCP()
	offsetV4[7] = 1
	icmpV4 := v4TCP()
	icmpV4[9] = 1
	badUDP := serializeIPv4UDP(t, net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}, 1, 2, []byte("data"))
	binary.BigEndian.PutUint16(badUDP[24:26], uint16(len(badUDP)))
	truncatedV6 := v6TCP()
	truncatedV6 = truncatedV6[:len(truncatedV6)-1]
	jumboLenV6 := v6TCP()
	jumboLenV6[4], jumboLenV6[5] = 0, 0

	jumboOpt := &IPv6HopByHopOption{}
	jumboOpt.SetJumboLength(100000)
	jumboOptV6 := mustSerialize(t, opts,
		&IPv6{
			Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6HopByHop,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
		},
		&IPv6HopByHop{
			ipv6ExtensionBase: ipv6ExtensionBase{NextHeader: IPProtocolTCP},
			Options:           []*IPv6HopByHopOption{jumboOpt},
		},
		gopacket.Payload(make([]byte, 24)))

	routingV6 := mustSerialize(t, opts,
		&IPv6{
			Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Routing,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
		},
		&IPv6Routing{ipv6ExtensionBase: ipv6ExtensionBase{NextHeader: IPProtocolTCP}},
		gopacket.Payload(make([]byte, 24)))

	tests := []struct {
		name string
		pkt  []byte
		rw   *PacketRewrite
		want string
	}{
		{"empty packet", nil, rw4, "empty"},
		{"unknown IP version", []byte{0x50, 0, 0, 0}, rw4, "IP version"},
		{"ipv4 truncated header", v4TCP()[:10], rw4, "truncated IPv4 header"},
		{"ipv4 truncated packet", truncatedV4, rw4, "truncated IPv4 packet"},
		{"ipv4 truncated tcp", truncatedV4TCP, rw4, "truncated TCP"},
		{"ipv4 more-fragments", mfV4, rw4, "fragmented"},
		{"ipv4 fragment offset", offsetV4, rw4, "fragmented"},
		{"ipv4 unsupported protocol", icmpV4, rw4, "only TCP and UDP"},
		{"ipv4 truncated udp", badUDP, rw4, "truncated UDP"},
		{"ipv4 with ipv6 address", v4TCP(), &PacketRewrite{SrcIP: net.ParseIP("2001:db8::1")}, "not an IPv4 address"},
		{"ipv6 with ipv4 address", v6TCP(), &PacketRewrite{SrcIP: net.ParseIP("192.0.2.1")}, "not an IPv6 address"},
		{"ipv6 truncated packet", truncatedV6, rw6, "truncated IPv6 packet"},
		{"ipv6 jumbogram zero length", jumboLenV6, rw6, "jumbogram"},
		{"ipv6 jumbogram option", jumboOptV6, rw6, "jumbogram"},
		{"ipv6 routing header", routingV6, rw6, "Routing"},
		{"ipv6 ah", v6WithNextHeader(IPProtocolAH, make([]byte, 16)), rw6, "AH"},
		{"ipv6 esp", v6WithNextHeader(IPProtocolESP, make([]byte, 16)), rw6, "ESP"},
		{"ipv6 fragment offset", v6Fragment(8, false), rw6, "fragmented"},
		{"ipv6 fragment more", v6Fragment(0, true), rw6, "fragmented"},
		{"ipv6 unknown next header", v6WithNextHeader(IPProtocol(99), make([]byte, 8)), rw6, "unsupported next header"},
	}
	for _, test := range tests {
		orig := append([]byte(nil), test.pkt...)
		out, changes, err := RewritePacket(test.pkt, test.rw)
		if err == nil {
			t.Errorf("%s: expected error, got none", test.name)
			continue
		}
		if !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error %q does not contain %q", test.name, err, test.want)
		}
		if out != nil || changes != nil {
			t.Errorf("%s: expected nil output and changes on error", test.name)
		}
		if !bytes.Equal(test.pkt, orig) {
			t.Errorf("%s: input packet was modified on error", test.name)
		}
	}
}
