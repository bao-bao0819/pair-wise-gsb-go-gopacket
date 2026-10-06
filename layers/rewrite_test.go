package layers

import (
	"bytes"
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

func portPtr(v uint16) *uint16 { return &v }

var rewriteTestSentinel = []byte{0xde, 0xad, 0xbe, 0xef}

func serializeRewriteTestPacket(t *testing.T, computeChecksums bool, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: computeChecksums}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("SerializeLayers: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// withSentinel appends marker bytes beyond the IP total/payload length.
// RewritePacket must never touch them.
func withSentinel(pkt []byte) []byte {
	out := make([]byte, len(pkt)+len(rewriteTestSentinel))
	copy(out, pkt)
	copy(out[len(pkt):], rewriteTestSentinel)
	return out
}

func ipv4TCPRewriteBase(t *testing.T) []byte {
	t.Helper()
	ip4 := &IPv4{
		Version: 4, TTL: 64, Protocol: IPProtocolTCP,
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("198.51.100.1"),
		Options: []IPv4Option{{OptionType: 7, OptionLength: 4, OptionData: []byte{0xaa, 0xbb}}},
	}
	tcp := &TCP{
		SrcPort: 12345, DstPort: 80, SYN: true, Window: 65535,
		Options: []TCPOption{{OptionType: TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatal(err)
	}
	pkt := serializeRewriteTestPacket(t, true, ip4, tcp, gopacket.Payload([]byte("leave the payload alone")))
	return withSentinel(pkt)
}

func ipv4UDPRewriteBase(t *testing.T, computeChecksums bool) []byte {
	t.Helper()
	ip4 := &IPv4{
		Version: 4, TTL: 64, Protocol: IPProtocolUDP,
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("198.51.100.1"),
	}
	udp := &UDP{SrcPort: 12345, DstPort: 9999}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatal(err)
	}
	pkt := serializeRewriteTestPacket(t, computeChecksums, ip4, udp, gopacket.Payload([]byte("udp payload bytes")))
	return withSentinel(pkt)
}

func ipv6TCPRewriteBase(t *testing.T) []byte {
	t.Helper()
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolTCP,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	tcp := &TCP{SrcPort: 12345, DstPort: 443, ACK: true, Window: 1024}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	pkt := serializeRewriteTestPacket(t, true, ip6, tcp, gopacket.Payload([]byte("v6 payload")))
	return withSentinel(pkt)
}

// foldSum folds a 32-bit sum to 16 bits without complementing it.
func foldSum(csum uint32) uint16 {
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return uint16(csum)
}

// verifyIPv4HeaderChecksum independently verifies the IPv4 header checksum.
func verifyIPv4HeaderChecksum(t *testing.T, pkt []byte) {
	t.Helper()
	ihl := int(pkt[0]&0x0f) * 4
	if got := foldSum(gopacket.ComputeChecksum(pkt[:ihl], 0)); got != 0xffff {
		t.Errorf("IPv4 header checksum verification failed: folded sum %#x, want 0xffff", got)
	}
}

// verifyTransportChecksum independently verifies a TCP/UDP checksum,
// pseudo-header included, against the given addresses.
func verifyTransportChecksum(t *testing.T, src, dst net.IP, proto IPProtocol, trans []byte) {
	t.Helper()
	csum := gopacket.ComputeChecksum(src, 0)
	csum = gopacket.ComputeChecksum(dst, csum)
	csum += uint32(proto)
	length := uint32(len(trans))
	csum += length & 0xffff
	csum += length >> 16
	csum = gopacket.ComputeChecksum(trans, csum)
	if got := foldSum(csum); got != 0xffff {
		t.Errorf("%s checksum verification failed: folded sum %#x, want 0xffff", proto, got)
	}
}

type byteRange struct{ start, end int }

// assertOnlyRangesDiffer fails the test if orig and got differ anywhere
// outside the given half-open byte ranges.
func assertOnlyRangesDiffer(t *testing.T, orig, got []byte, ranges ...byteRange) {
	t.Helper()
	if len(orig) != len(got) {
		t.Fatalf("length changed: %d -> %d", len(orig), len(got))
	}
	for i := range orig {
		if orig[i] == got[i] {
			continue
		}
		allowed := false
		for _, r := range ranges {
			if i >= r.start && i < r.end {
				allowed = true
				break
			}
		}
		if !allowed {
			t.Errorf("byte %d changed outside allowed ranges: %#02x -> %#02x", i, orig[i], got[i])
		}
	}
}

func mutatePacket(pkt []byte, f func([]byte)) []byte {
	out := append([]byte(nil), pkt...)
	f(out)
	return out
}

func TestRewriteIPv4TCP(t *testing.T) {
	pkt := ipv4TCPRewriteBase(t)
	orig := append([]byte(nil), pkt...)
	const ihl = 24 // 20 bytes + one 4-byte option

	rw := &PacketRewrite{
		SrcIP:   net.ParseIP("203.0.113.7"),
		DstIP:   net.ParseIP("203.0.113.200"),
		SrcPort: portPtr(40000),
		DstPort: portPtr(8080),
	}
	got, changes, err := RewritePacket(pkt, rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := []PacketRewriteChange{
		{Field: "SrcIP", Old: "192.0.2.1", New: "203.0.113.7"},
		{Field: "DstIP", Old: "198.51.100.1", New: "203.0.113.200"},
		{Field: "SrcPort", Old: "12345", New: "40000"},
		{Field: "DstPort", Old: "80", New: "8080"},
	}
	if !reflect.DeepEqual(changes, wantChanges) {
		t.Errorf("changes = %v, want %v", changes, wantChanges)
	}
	if !bytes.Equal(pkt, orig) {
		t.Error("input packet was modified")
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{10, 12},             // IPv4 header checksum
		byteRange{12, 20},             // IPv4 addresses
		byteRange{ihl, ihl + 4},       // TCP ports
		byteRange{ihl + 16, ihl + 18}, // TCP checksum
	)
	verifyIPv4HeaderChecksum(t, got)
	verifyTransportChecksum(t, rw.SrcIP.To4(), rw.DstIP.To4(), IPProtocolTCP,
		got[ihl:len(got)-len(rewriteTestSentinel)])

	// Rewriting the original values back must restore the original packet.
	back, changes, err := RewritePacket(got, &PacketRewrite{
		SrcIP:   net.ParseIP("192.0.2.1"),
		DstIP:   net.ParseIP("198.51.100.1"),
		SrcPort: portPtr(12345),
		DstPort: portPtr(80),
	})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if len(changes) != 4 {
		t.Errorf("rewrite back: changes = %v, want 4 entries", changes)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting back did not restore the original packet")
	}

	// The result must be an independent copy.
	got[0] ^= 0xff
	if !bytes.Equal(pkt, orig) {
		t.Error("output aliases the input packet")
	}
}

func TestRewriteIPv4TCPPortsOnly(t *testing.T) {
	pkt := ipv4TCPRewriteBase(t)
	orig := append([]byte(nil), pkt...)
	const ihl = 24

	got, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcPort: portPtr(5000),
		DstPort: portPtr(5001),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := []PacketRewriteChange{
		{Field: "SrcPort", Old: "12345", New: "5000"},
		{Field: "DstPort", Old: "80", New: "5001"},
	}
	if !reflect.DeepEqual(changes, wantChanges) {
		t.Errorf("changes = %v, want %v", changes, wantChanges)
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{ihl, ihl + 4},       // TCP ports
		byteRange{ihl + 16, ihl + 18}, // TCP checksum
	)
	if !bytes.Equal(got[:ihl], orig[:ihl]) {
		t.Error("IPv4 header changed on a ports-only rewrite")
	}
	verifyTransportChecksum(t, net.ParseIP("192.0.2.1").To4(), net.ParseIP("198.51.100.1").To4(),
		IPProtocolTCP, got[ihl:len(got)-len(rewriteTestSentinel)])
}

func TestRewriteIPv4UDPChecksum(t *testing.T) {
	pkt := ipv4UDPRewriteBase(t, true)
	orig := append([]byte(nil), pkt...)

	rw := &PacketRewrite{
		SrcIP:   net.ParseIP("203.0.113.7"),
		DstIP:   net.ParseIP("203.0.113.200"),
		SrcPort: portPtr(40000),
		DstPort: portPtr(8080),
	}
	got, changes, err := RewritePacket(pkt, rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if len(changes) != 4 {
		t.Errorf("changes = %v, want 4 entries", changes)
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{10, 12}, // IPv4 header checksum
		byteRange{12, 20}, // IPv4 addresses
		byteRange{20, 24}, // UDP ports
		byteRange{26, 28}, // UDP checksum
	)
	verifyIPv4HeaderChecksum(t, got)
	verifyTransportChecksum(t, rw.SrcIP.To4(), rw.DstIP.To4(), IPProtocolUDP,
		got[20:len(got)-len(rewriteTestSentinel)])

	back, _, err := RewritePacket(got, &PacketRewrite{
		SrcIP:   net.ParseIP("192.0.2.1"),
		DstIP:   net.ParseIP("198.51.100.1"),
		SrcPort: portPtr(12345),
		DstPort: portPtr(9999),
	})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting back did not restore the original packet")
	}
}

func TestRewriteIPv4UDPZeroChecksumPreserved(t *testing.T) {
	pkt := ipv4UDPRewriteBase(t, false)
	orig := append([]byte(nil), pkt...)
	if c := binary.BigEndian.Uint16(pkt[26:]); c != 0 {
		t.Fatalf("test setup: UDP checksum = %#x, want 0", c)
	}

	got, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcIP:   net.ParseIP("203.0.113.7"),
		DstIP:   net.ParseIP("203.0.113.200"),
		SrcPort: portPtr(40000),
		DstPort: portPtr(8080),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if len(changes) != 4 {
		t.Errorf("changes = %v, want 4 entries", changes)
	}
	if c := binary.BigEndian.Uint16(got[26:]); c != 0 {
		t.Errorf("zero IPv4 UDP checksum not preserved: %#x", c)
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{10, 12}, // IPv4 header checksum
		byteRange{12, 20}, // IPv4 addresses
		byteRange{20, 24}, // UDP ports
	)
	verifyIPv4HeaderChecksum(t, got)
}

func TestRewriteIPv4UDPComputedZeroChecksum(t *testing.T) {
	ip4 := &IPv4{
		Version: 4, TTL: 64, Protocol: IPProtocolUDP,
		SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("198.51.100.1"),
	}
	udp := &UDP{SrcPort: 12345, DstPort: 1111}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatal(err)
	}
	// The last payload word is adjusted below so that the checksum of the
	// rewritten packet folds to zero.
	pkt := serializeRewriteTestPacket(t, true, ip4, udp,
		gopacket.Payload([]byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00}))

	crafted := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(crafted[22:], 9999) // new destination port
	crafted[26], crafted[27] = 0, 0                // zero checksum field
	csum := gopacket.ComputeChecksum(crafted[12:16], 0)
	csum = gopacket.ComputeChecksum(crafted[16:20], csum)
	csum += uint32(IPProtocolUDP)
	csum += uint32(len(crafted) - 20)
	csum = gopacket.ComputeChecksum(crafted[20:], csum)
	delta := uint16(0xffff) - foldSum(csum)
	binary.BigEndian.PutUint16(pkt[len(pkt)-2:], delta)

	got, _, err := RewritePacket(pkt, &PacketRewrite{DstPort: portPtr(9999)})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if c := binary.BigEndian.Uint16(got[26:]); c != 0xffff {
		t.Errorf("computed zero UDP checksum written as %#04x, want 0xffff", c)
	}
	// Prove the correct checksum really is zero (and 0xffff is not just a
	// naturally occurring checksum value).
	zeroed := append([]byte(nil), got...)
	zeroed[26], zeroed[27] = 0, 0
	csum = gopacket.ComputeChecksum(zeroed[12:16], 0)
	csum = gopacket.ComputeChecksum(zeroed[16:20], csum)
	csum += uint32(IPProtocolUDP)
	csum += uint32(len(zeroed) - 20)
	csum = gopacket.ComputeChecksum(zeroed[20:], csum)
	if s := foldSum(csum); s != 0xffff {
		t.Fatalf("test setup: folded sum = %#x, want 0xffff (zero checksum)", s)
	}
}
func TestRewriteIPv6TCPWithDestinationOptions(t *testing.T) {
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Destination,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	dst := &IPv6Destination{
		Options: []*IPv6DestinationOption{
			{OptionType: 0x01, OptionData: []byte{0x00, 0x00, 0x00, 0x00}},
		},
	}
	dst.NextHeader = IPProtocolTCP
	tcp := &TCP{
		SrcPort: 12345, DstPort: 443, ACK: true, Window: 1024,
		Options: []TCPOption{{OptionType: TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	pkt := withSentinel(serializeRewriteTestPacket(t, true, ip6, dst, tcp,
		gopacket.Payload([]byte("v6 payload with options"))))
	orig := append([]byte(nil), pkt...)
	const transOff = 48 // 40 byte header + 8 byte destination options

	rw := &PacketRewrite{
		SrcIP:   net.ParseIP("2001:db8:1::7"),
		DstIP:   net.ParseIP("2001:db8:2::200"),
		SrcPort: portPtr(40000),
		DstPort: portPtr(8443),
	}
	got, changes, err := RewritePacket(pkt, rw)
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if len(changes) != 4 {
		t.Errorf("changes = %v, want 4 entries", changes)
	}
	if !bytes.Equal(pkt, orig) {
		t.Error("input packet was modified")
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{8, 40},                        // IPv6 addresses
		byteRange{transOff, transOff + 4},       // TCP ports
		byteRange{transOff + 16, transOff + 18}, // TCP checksum
	)
	verifyTransportChecksum(t, rw.SrcIP.To16(), rw.DstIP.To16(), IPProtocolTCP,
		got[transOff:len(got)-len(rewriteTestSentinel)])

	back, _, err := RewritePacket(got, &PacketRewrite{
		SrcIP:   net.ParseIP("2001:db8::1"),
		DstIP:   net.ParseIP("2001:db8::2"),
		SrcPort: portPtr(12345),
		DstPort: portPtr(443),
	})
	if err != nil {
		t.Fatalf("RewritePacket back: %v", err)
	}
	if !bytes.Equal(back, orig) {
		t.Error("rewriting back did not restore the original packet")
	}
}

func TestRewriteIPv6AtomicFragment(t *testing.T) {
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Fragment,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	// Offset 0, M clear: an atomic fragment is a whole packet.
	frag := &IPv6Fragment{NextHeader: IPProtocolTCP, Identification: 0xdeadbeef}
	tcp := &TCP{SrcPort: 12345, DstPort: 443, SYN: true, Window: 4096}
	if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	pkt := withSentinel(serializeRewriteTestPacket(t, true, ip6, frag, tcp,
		gopacket.Payload([]byte("atomic fragment payload"))))
	orig := append([]byte(nil), pkt...)
	const transOff = 48 // 40 byte header + 8 byte fragment header

	got, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcIP:   net.ParseIP("2001:db8:1::7"),
		DstPort: portPtr(8443),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	wantChanges := []PacketRewriteChange{
		{Field: "SrcIP", Old: "2001:db8::1", New: "2001:db8:1::7"},
		{Field: "DstPort", Old: "443", New: "8443"},
	}
	if !reflect.DeepEqual(changes, wantChanges) {
		t.Errorf("changes = %v, want %v", changes, wantChanges)
	}
	assertOnlyRangesDiffer(t, orig, got,
		byteRange{8, 24},                        // IPv6 source address
		byteRange{transOff + 2, transOff + 4},   // TCP destination port
		byteRange{transOff + 16, transOff + 18}, // TCP checksum
	)
	verifyTransportChecksum(t, net.ParseIP("2001:db8:1::7").To16(), net.ParseIP("2001:db8::2").To16(),
		IPProtocolTCP, got[transOff:len(got)-len(rewriteTestSentinel)])
}

func TestRewriteIPv6UDPChecksumMandatory(t *testing.T) {
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolUDP,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	udp := &UDP{SrcPort: 12345, DstPort: 9999}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	// Serialize without checksums: the original UDP checksum is zero, which
	// is not a valid "no checksum" marker for IPv6. The rewrite must compute
	// it anyway.
	pkt := withSentinel(serializeRewriteTestPacket(t, false, ip6, udp,
		gopacket.Payload([]byte("v6 udp payload"))))
	if c := binary.BigEndian.Uint16(pkt[46:]); c != 0 {
		t.Fatalf("test setup: UDP checksum = %#x, want 0", c)
	}

	got, _, err := RewritePacket(pkt, &PacketRewrite{SrcPort: portPtr(2222)})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if c := binary.BigEndian.Uint16(got[46:]); c == 0 {
		t.Error("IPv6 UDP checksum must be computed, got 0")
	}
	verifyTransportChecksum(t, net.ParseIP("2001:db8::1").To16(), net.ParseIP("2001:db8::2").To16(),
		IPProtocolUDP, got[40:len(got)-len(rewriteTestSentinel)])
}

func TestRewriteIPv6UDPComputedZeroChecksum(t *testing.T) {
	ip6 := &IPv6{
		Version: 6, HopLimit: 64, NextHeader: IPProtocolUDP,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
	}
	udp := &UDP{SrcPort: 12345, DstPort: 1111}
	if err := udp.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	pkt := serializeRewriteTestPacket(t, true, ip6, udp,
		gopacket.Payload([]byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00}))

	crafted := append([]byte(nil), pkt...)
	binary.BigEndian.PutUint16(crafted[42:], 9999) // new destination port
	crafted[46], crafted[47] = 0, 0                // zero checksum field
	csum := gopacket.ComputeChecksum(crafted[8:24], 0)
	csum = gopacket.ComputeChecksum(crafted[24:40], csum)
	csum += uint32(IPProtocolUDP)
	csum += uint32(len(crafted) - 40)
	csum = gopacket.ComputeChecksum(crafted[40:], csum)
	delta := uint16(0xffff) - foldSum(csum)
	binary.BigEndian.PutUint16(pkt[len(pkt)-2:], delta)

	got, _, err := RewritePacket(pkt, &PacketRewrite{DstPort: portPtr(9999)})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if c := binary.BigEndian.Uint16(got[46:]); c != 0xffff {
		t.Errorf("computed zero UDP checksum written as %#04x, want 0xffff", c)
	}
	// Prove the correct checksum really is zero.
	zeroed := append([]byte(nil), got...)
	zeroed[46], zeroed[47] = 0, 0
	csum = gopacket.ComputeChecksum(zeroed[8:24], 0)
	csum = gopacket.ComputeChecksum(zeroed[24:40], csum)
	csum += uint32(IPProtocolUDP)
	csum += uint32(len(zeroed) - 40)
	csum = gopacket.ComputeChecksum(zeroed[40:], csum)
	if s := foldSum(csum); s != 0xffff {
		t.Fatalf("test setup: folded sum = %#x, want 0xffff (zero checksum)", s)
	}
}

func TestRewriteNoChanges(t *testing.T) {
	pkt := ipv4TCPRewriteBase(t)
	orig := append([]byte(nil), pkt...)

	for _, rw := range []*PacketRewrite{nil, {}} {
		got, changes, err := RewritePacket(pkt, rw)
		if err != nil {
			t.Fatalf("RewritePacket(%v): %v", rw, err)
		}
		if len(changes) != 0 {
			t.Errorf("RewritePacket(%v): changes = %v, want none", rw, changes)
		}
		if !bytes.Equal(got, orig) {
			t.Errorf("RewritePacket(%v): packet changed", rw)
		}
		got[0] ^= 0xff
		if !bytes.Equal(pkt, orig) {
			t.Error("output aliases the input packet")
		}
	}

	// Configured values equal to the current ones: no changes, identical copy.
	got, changes, err := RewritePacket(pkt, &PacketRewrite{
		SrcIP:   net.ParseIP("192.0.2.1"),
		DstPort: portPtr(80),
	})
	if err != nil {
		t.Fatalf("RewritePacket: %v", err)
	}
	if len(changes) != 0 {
		t.Errorf("changes = %v, want none", changes)
	}
	if !bytes.Equal(got, orig) {
		t.Error("packet changed by a no-op rewrite")
	}
}

func TestRewriteRejects(t *testing.T) {
	v4 := func() []byte { return ipv4TCPRewriteBase(t) }
	v6 := func() []byte { return ipv6TCPRewriteBase(t) }
	v6Frag := func(mut func(*IPv6Fragment)) []byte {
		ip6 := &IPv6{
			Version: 6, HopLimit: 64, NextHeader: IPProtocolIPv6Fragment,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"),
		}
		frag := &IPv6Fragment{NextHeader: IPProtocolTCP, Identification: 1}
		mut(frag)
		tcp := &TCP{SrcPort: 12345, DstPort: 443, SYN: true, Window: 4096}
		if err := tcp.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
		return serializeRewriteTestPacket(t, true, ip6, frag, tcp, gopacket.Payload([]byte("x")))
	}

	tests := []struct {
		name string
		pkt  []byte
		rw   *PacketRewrite
	}{
		{"empty packet", nil, nil},
		{"unsupported ip version", []byte{0x50, 0, 0, 0}, nil},
		{"ipv4 truncated header", v4()[:10], nil},
		{"ipv4 truncated packet", v4()[:len(v4())-10], nil},
		{"ipv4 truncated tcp header", mutatePacket(v4(), func(p []byte) {
			binary.BigEndian.PutUint16(p[2:], 34) // 24 byte header + 10 bytes of TCP
		}), nil},
		{"ipv4 more fragments", mutatePacket(v4(), func(p []byte) { p[6] |= 0x20 }), nil},
		{"ipv4 fragment offset", mutatePacket(v4(), func(p []byte) { p[7] = 0x08 }), nil},
		{"ipv4 unsupported protocol", mutatePacket(v4(), func(p []byte) {
			p[9] = byte(IPProtocolICMPv4)
		}), nil},
		{"ipv4 with ipv6 source", v4(), &PacketRewrite{SrcIP: net.ParseIP("2001:db8::1")}},
		{"ipv4 with ipv6 destination", v4(), &PacketRewrite{DstIP: net.ParseIP("2001:db8::2")}},
		{"ipv6 truncated header", v6()[:30], nil},
		{"ipv6 truncated packet", v6()[:len(v6())-5], nil},
		{"ipv6 jumbogram", mutatePacket(v6(), func(p []byte) { p[4], p[5] = 0, 0 }), nil},
		{"ipv6 routing header", mutatePacket(v6(), func(p []byte) {
			p[6] = byte(IPProtocolIPv6Routing)
		}), nil},
		{"ipv6 ah", mutatePacket(v6(), func(p []byte) { p[6] = byte(IPProtocolAH) }), nil},
		{"ipv6 esp", mutatePacket(v6(), func(p []byte) { p[6] = byte(IPProtocolESP) }), nil},
		{"ipv6 no next header", mutatePacket(v6(), func(p []byte) {
			p[6] = byte(IPProtocolNoNextHeader)
		}), nil},
		{"ipv6 unknown next header", mutatePacket(v6(), func(p []byte) { p[6] = 254 }), nil},
		{"ipv6 with ipv4 source", v6(), &PacketRewrite{SrcIP: net.ParseIP("192.0.2.1")}},
		{"ipv6 with ipv4 destination", v6(), &PacketRewrite{DstIP: net.ParseIP("198.51.100.1")}},
		{"ipv6 fragment offset", v6Frag(func(f *IPv6Fragment) { f.FragmentOffset = 5 }), nil},
		{"ipv6 fragment more", v6Frag(func(f *IPv6Fragment) { f.MoreFragments = true }), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := append([]byte(nil), tc.pkt...)
			got, changes, err := RewritePacket(tc.pkt, tc.rw)
			if err == nil {
				t.Fatal("expected an error, got none")
			}
			if got != nil || changes != nil {
				t.Errorf("expected nil outputs on error, got %v, %v", got, changes)
			}
			if !bytes.Equal(tc.pkt, orig) {
				t.Error("input packet modified on error")
			}
		})
	}
}
