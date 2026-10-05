// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
)

var (
	quoteV4Src = net.IP{10, 0, 0, 1}
	quoteV4Dst = net.IP{192, 168, 0, 2}
	quoteV6Src = net.ParseIP("2001:db8::1")
	quoteV6Dst = net.ParseIP("2001:db8::2")
)

// testIPv4Header builds an IPv4 header of ihlWords*4 bytes (option space is
// filled with NOP options) with the given protocol, fragment offset and
// declared total length.
func testIPv4Header(src, dst net.IP, proto IPProtocol, ihlWords int, fragOffset uint16, totalLen uint16) []byte {
	hdr := make([]byte, ihlWords*4)
	hdr[0] = 0x40 | byte(ihlWords)
	binary.BigEndian.PutUint16(hdr[2:4], totalLen)
	binary.BigEndian.PutUint16(hdr[6:8], fragOffset&0x1FFF)
	hdr[8] = 64
	hdr[9] = byte(proto)
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	for i := 20; i < len(hdr); i++ {
		hdr[i] = 1 // NOP options
	}
	return hdr
}

func testIPv6Header(src, dst net.IP, next IPProtocol) []byte {
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], 100) // declared payload length
	hdr[6] = byte(next)
	hdr[7] = 64
	copy(hdr[8:24], src.To16())
	copy(hdr[24:40], dst.To16())
	return hdr
}

func testTCPHeader(srcPort, dstPort uint16, seq uint32) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint32(b[4:8], seq)
	b[12] = 5 << 4 // data offset
	return b
}

func testUDPHeader(srcPort, dstPort uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], 8)
	return b
}

// testIPv6ExtHeader builds a length-prefixed IPv6 extension header of the
// given total length (a multiple of 8) pointing at next.
func testIPv6ExtHeader(next IPProtocol, totalLen int) []byte {
	b := make([]byte, totalLen)
	b[0] = byte(next)
	b[1] = byte(totalLen/8 - 1)
	return b
}

func testIPv6FragmentHeader(next IPProtocol, fragOffset uint16, more bool) []byte {
	b := make([]byte, 8)
	b[0] = byte(next)
	off := fragOffset << 3
	if more {
		off |= 1
	}
	binary.BigEndian.PutUint16(b[2:4], off)
	return b
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestICMPQuoteNotApplicable(t *testing.T) {
	v4Info := []ICMPv4TypeCode{
		CreateICMPv4TypeCode(ICMPv4TypeEchoRequest, 0),
		CreateICMPv4TypeCode(ICMPv4TypeEchoReply, 0),
		CreateICMPv4TypeCode(ICMPv4TypeTimestampRequest, 0),
		CreateICMPv4TypeCode(ICMPv4TypeRouterSolicitation, 0),
	}
	for _, tc := range v4Info {
		if _, err := ParseICMPv4Quote(tc, nil, 0); !errors.Is(err, ErrICMPQuoteNotApplicable) {
			t.Errorf("ICMPv4 %s: got %v, want ErrICMPQuoteNotApplicable", tc, err)
		}
	}
	v6Info := []ICMPv6TypeCode{
		CreateICMPv6TypeCode(ICMPv6TypeEchoRequest, 0),
		CreateICMPv6TypeCode(ICMPv6TypeEchoReply, 0),
		CreateICMPv6TypeCode(ICMPv6TypeRouterSolicitation, 0),
		CreateICMPv6TypeCode(ICMPv6TypeNeighborAdvertisement, 0),
	}
	for _, tc := range v6Info {
		if _, err := ParseICMPv6Quote(tc, nil, 0); !errors.Is(err, ErrICMPQuoteNotApplicable) {
			t.Errorf("ICMPv6 %s: got %v, want ErrICMPQuoteNotApplicable", tc, err)
		}
	}
	v4Err := []ICMPv4TypeCode{
		CreateICMPv4TypeCode(ICMPv4TypeDestinationUnreachable, ICMPv4CodeHost),
		CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, ICMPv4CodeTTLExceeded),
		CreateICMPv4TypeCode(ICMPv4TypeSourceQuench, 0),
		CreateICMPv4TypeCode(ICMPv4TypeRedirect, 0),
		CreateICMPv4TypeCode(ICMPv4TypeParameterProblem, 0),
	}
	for _, tc := range v4Err {
		if _, err := ParseICMPv4Quote(tc, nil, 0); err != nil {
			t.Errorf("ICMPv4 %s: unexpected error %v", tc, err)
		}
	}
	v6Err := []ICMPv6TypeCode{
		CreateICMPv6TypeCode(ICMPv6TypeDestinationUnreachable, ICMPv6CodePortUnreachable),
		CreateICMPv6TypeCode(ICMPv6TypePacketTooBig, 0),
		CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, ICMPv6CodeHopLimitExceeded),
		CreateICMPv6TypeCode(ICMPv6TypeParameterProblem, ICMPv6CodeErroneousHeaderField),
	}
	for _, tc := range v6Err {
		if _, err := ParseICMPv6Quote(tc, nil, 0); err != nil {
			t.Errorf("ICMPv6 %s: unexpected error %v", tc, err)
		}
	}
}

func TestICMPv4QuoteFull(t *testing.T) {
	// IPv4 header with 4 bytes of options (IHL 6) + TCP, declared total
	// length deliberately larger than the quote: that is the normal case
	// and must not discard anything.
	quote := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 6, 0, 1500),
		testTCPHeader(12345, 80, 0xdeadbeef),
	)
	q, err := ParseICMPv4Quote(CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0), quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.IPVersion != 4 {
		t.Errorf("IPVersion = %d, want 4", q.IPVersion)
	}
	if q.AddressesStatus != ICMPQuoteFieldKnown || !q.SrcIP.Equal(quoteV4Src) || !q.DstIP.Equal(quoteV4Dst) {
		t.Errorf("addresses = %v -> %v (%s)", q.SrcIP, q.DstIP, q.AddressesStatus)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolTCP {
		t.Errorf("protocol = %v (%s)", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 12345 || q.DstPort != 80 {
		t.Errorf("ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}
	if q.TCPSeqStatus != ICMPQuoteFieldKnown || q.TCPSeq != 0xdeadbeef {
		t.Errorf("tcp seq = %#x (%s)", q.TCPSeq, q.TCPSeqStatus)
	}
	if q.MissingReason != "" {
		t.Errorf("MissingReason = %q, want empty", q.MissingReason)
	}
}

func TestICMPv6QuoteFull(t *testing.T) {
	quote := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolUDP),
		testUDPHeader(53, 5353),
	)
	q, err := ParseICMPv6Quote(CreateICMPv6TypeCode(ICMPv6TypePacketTooBig, 0), quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.IPVersion != 6 {
		t.Errorf("IPVersion = %d, want 6", q.IPVersion)
	}
	if q.AddressesStatus != ICMPQuoteFieldKnown || !q.SrcIP.Equal(quoteV6Src) || !q.DstIP.Equal(quoteV6Dst) {
		t.Errorf("addresses = %v -> %v (%s)", q.SrcIP, q.DstIP, q.AddressesStatus)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolUDP {
		t.Errorf("protocol = %v (%s)", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 53 || q.DstPort != 5353 {
		t.Errorf("ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}
}

// quoteSnapshot captures the recovered state of a quote so monotonicity can
// be checked across truncation boundaries.
type quoteSnapshot struct {
	addresses bool
	protocol  bool
	ports     bool
	tcpSeq    bool
	srcIP     net.IP
	dstIP     net.IP
	proto     IPProtocol
	srcPort   uint16
	dstPort   uint16
	seq       uint32
}

func snapshotQuote(q *ICMPQuote) quoteSnapshot {
	return quoteSnapshot{
		addresses: q.AddressesStatus == ICMPQuoteFieldKnown,
		protocol:  q.ProtocolStatus == ICMPQuoteFieldKnown,
		ports:     q.PortsStatus == ICMPQuoteFieldKnown,
		tcpSeq:    q.TCPSeqStatus == ICMPQuoteFieldKnown,
		srcIP:     q.SrcIP,
		dstIP:     q.DstIP,
		proto:     q.Protocol,
		srcPort:   q.SrcPort,
		dstPort:   q.DstPort,
		seq:       q.TCPSeq,
	}
}

// checkQuoteMonotonic parses every prefix of quote and verifies that
// information only grows as evidence is added: once a field becomes known it
// must stay known with the same value, and no prefix of a well-formed quote
// may produce an error.
func checkQuoteMonotonic(t *testing.T, v6 bool, tc4 ICMPv4TypeCode, tc6 ICMPv6TypeCode, quote []byte) {
	t.Helper()
	var prev quoteSnapshot
	for n := 0; n <= len(quote); n++ {
		var (
			q   *ICMPQuote
			err error
		)
		if v6 {
			q, err = ParseICMPv6Quote(tc6, quote, n)
		} else {
			q, err = ParseICMPv4Quote(tc4, quote, n)
		}
		if err != nil {
			t.Fatalf("prefix %d/%d: unexpected error: %v", n, len(quote), err)
		}
		cur := snapshotQuote(q)
		if prev.addresses && (!cur.addresses || !prev.srcIP.Equal(cur.srcIP) || !prev.dstIP.Equal(cur.dstIP)) {
			t.Fatalf("prefix %d: addresses regressed: %+v -> %+v", n, prev, cur)
		}
		if prev.protocol && (!cur.protocol || prev.proto != cur.proto) {
			t.Fatalf("prefix %d: protocol regressed: %+v -> %+v", n, prev, cur)
		}
		if prev.ports && (!cur.ports || prev.srcPort != cur.srcPort || prev.dstPort != cur.dstPort) {
			t.Fatalf("prefix %d: ports regressed: %+v -> %+v", n, prev, cur)
		}
		if prev.tcpSeq && (!cur.tcpSeq || prev.seq != cur.seq) {
			t.Fatalf("prefix %d: TCP sequence regressed: %+v -> %+v", n, prev, cur)
		}
		// Fields become known in wire order: ports need addresses and
		// protocol, the TCP sequence needs ports.
		if cur.ports && (!cur.addresses || !cur.protocol) {
			t.Fatalf("prefix %d: ports known without addresses/protocol: %+v", n, cur)
		}
		if cur.tcpSeq && !cur.ports {
			t.Fatalf("prefix %d: TCP sequence known without ports: %+v", n, cur)
		}
		prev = cur
	}
}

func TestICMPQuoteTruncationSweep(t *testing.T) {
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, ICMPv4CodeTTLExceeded)
	tc6 := CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, ICMPv6CodeHopLimitExceeded)

	v4TCP := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 6, 0, 1500),
		testTCPHeader(12345, 80, 0xdeadbeef),
	)
	checkQuoteMonotonic(t, false, tc4, tc6, v4TCP)

	v4UDP := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolUDP, 5, 0, 1500),
		testUDPHeader(53, 5353),
	)
	checkQuoteMonotonic(t, false, tc4, tc6, v4UDP)

	v6Plain := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolTCP),
		testTCPHeader(12345, 443, 0x01020304),
	)
	checkQuoteMonotonic(t, true, tc4, tc6, v6Plain)

	v6Ext := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6HopByHop),
		testIPv6ExtHeader(IPProtocolIPv6Destination, 8),
		testIPv6ExtHeader(IPProtocolTCP, 16),
		testTCPHeader(8080, 22, 0xa5a5a5a5),
	)
	checkQuoteMonotonic(t, true, tc4, tc6, v6Ext)

	v6Frag := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6Fragment),
		testIPv6FragmentHeader(IPProtocolUDP, 0, true),
		testUDPHeader(123, 456),
	)
	checkQuoteMonotonic(t, true, tc4, tc6, v6Frag)
}

// TestICMPQuoteSentinel verifies that bytes past the caller-supplied quote
// length (ICMP extension data, or any trailing junk) are never read: parsing
// a buffer with a sentinel tail must give exactly the same result as parsing
// the isolated quote.
func TestICMPQuoteSentinel(t *testing.T) {
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, ICMPv4CodeTTLExceeded)
	tc6 := CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, ICMPv6CodeHopLimitExceeded)

	// The sentinel looks like a valid TCP header with distinctive ports; if
	// the parser ever reads past quoteLen it would report fake ports.
	sentinel := concatBytes(testTCPHeader(11111, 22222, 0x0b0b0b0b), []byte("ICMP-EXTENSIONS"))

	quotes := []struct {
		v6    bool
		quote []byte
	}{
		{false, concatBytes(
			testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500),
			testTCPHeader(12345, 80, 0xdeadbeef),
		)},
		{true, concatBytes(
			testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6HopByHop),
			testIPv6ExtHeader(IPProtocolUDP, 8),
			testUDPHeader(53, 5353),
		)},
	}
	for _, c := range quotes {
		tailed := concatBytes(c.quote, sentinel)
		for n := 0; n <= len(c.quote); n++ {
			var isolated, tailedQ *ICMPQuote
			var err error
			if c.v6 {
				isolated, err = ParseICMPv6Quote(tc6, c.quote, n)
			} else {
				isolated, err = ParseICMPv4Quote(tc4, c.quote, n)
			}
			if err != nil {
				t.Fatalf("v6=%v prefix %d: unexpected error: %v", c.v6, n, err)
			}
			if c.v6 {
				tailedQ, err = ParseICMPv6Quote(tc6, tailed, n)
			} else {
				tailedQ, err = ParseICMPv4Quote(tc4, tailed, n)
			}
			if err != nil {
				t.Fatalf("v6=%v prefix %d with tail: unexpected error: %v", c.v6, n, err)
			}
			if !reflect.DeepEqual(isolated, tailedQ) {
				t.Fatalf("v6=%v prefix %d: sentinel tail changed result:\nisolated: %+v\ntailed:   %+v", c.v6, n, isolated, tailedQ)
			}
			if tailedQ.PortsStatus == ICMPQuoteFieldKnown &&
				tailedQ.SrcPort == 11111 && tailedQ.DstPort == 22222 {
				t.Fatalf("v6=%v prefix %d: ports read from sentinel tail", c.v6, n)
			}
		}
	}
}

func TestICMPv4QuoteNonFirstFragment(t *testing.T) {
	// A non-first fragment carries no transport header; the bytes after the
	// IP header are payload and must not be read as ports.
	quote := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 185, 1500),
		testTCPHeader(12345, 80, 0xdeadbeef),
	)
	q, err := ParseICMPv4Quote(CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0), quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.AddressesStatus != ICMPQuoteFieldKnown || q.ProtocolStatus != ICMPQuoteFieldKnown {
		t.Errorf("addresses/protocol should be known: %+v", q)
	}
	if q.PortsStatus != ICMPQuoteFieldMissing || q.TCPSeqStatus != ICMPQuoteFieldMissing {
		t.Errorf("ports/seq of a non-first fragment must be missing: %+v", q)
	}
	if !strings.Contains(q.MissingReason, "fragment") {
		t.Errorf("MissingReason = %q, want a fragment explanation", q.MissingReason)
	}
}

func TestICMPv6QuoteFragment(t *testing.T) {
	tc := CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, ICMPv6CodeHopLimitExceeded)

	// First fragment: the transport header follows and ports are readable.
	first := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6Fragment),
		testIPv6FragmentHeader(IPProtocolUDP, 0, true),
		testUDPHeader(123, 456),
	)
	q, err := ParseICMPv6Quote(tc, first, len(first))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 123 || q.DstPort != 456 {
		t.Errorf("first fragment: ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}

	// Non-first fragment: protocol is known from the fragment header, but
	// the transport header is absent.
	later := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6Fragment),
		testIPv6FragmentHeader(IPProtocolUDP, 96, false),
		testUDPHeader(123, 456),
	)
	q, err = ParseICMPv6Quote(tc, later, len(later))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolUDP {
		t.Errorf("non-first fragment: protocol = %v (%s)", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldMissing {
		t.Errorf("non-first fragment: ports must be missing, got %d -> %d", q.SrcPort, q.DstPort)
	}
	if !strings.Contains(q.MissingReason, "fragment") {
		t.Errorf("MissingReason = %q, want a fragment explanation", q.MissingReason)
	}
}

func TestICMPv6QuoteExtensionCut(t *testing.T) {
	tc := CreateICMPv6TypeCode(ICMPv6TypeDestinationUnreachable, ICMPv6CodeAddressUnreachable)
	full := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolIPv6HopByHop),
		testIPv6ExtHeader(IPProtocolTCP, 16),
		testTCPHeader(8080, 22, 0xa5a5a5a5),
	)
	// Cut the hop-by-hop header in half: addresses stay known, the final
	// protocol and everything below it is missing.
	q, err := ParseICMPv6Quote(tc, full, 40+5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.AddressesStatus != ICMPQuoteFieldKnown {
		t.Errorf("addresses should be known: %+v", q)
	}
	if q.ProtocolStatus != ICMPQuoteFieldMissing || q.PortsStatus != ICMPQuoteFieldMissing {
		t.Errorf("protocol/ports should be missing: %+v", q)
	}
	if !strings.Contains(q.MissingReason, "extension header") {
		t.Errorf("MissingReason = %q, want an extension header explanation", q.MissingReason)
	}

	// The full chain parses through both extension headers.
	q, err = ParseICMPv6Quote(tc, full, len(full))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolTCP {
		t.Errorf("protocol = %v (%s)", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 8080 || q.DstPort != 22 {
		t.Errorf("ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}
	if q.TCPSeqStatus != ICMPQuoteFieldKnown || q.TCPSeq != 0xa5a5a5a5 {
		t.Errorf("tcp seq = %#x (%s)", q.TCPSeq, q.TCPSeqStatus)
	}
}

func TestICMPv6QuoteESP(t *testing.T) {
	quote := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolESP),
		[]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4},
	)
	q, err := ParseICMPv6Quote(CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, 0), quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolESP {
		t.Errorf("protocol = %v (%s), want ESP", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldMissing {
		t.Errorf("ESP ports must be missing, got %d -> %d", q.SrcPort, q.DstPort)
	}
	if !strings.Contains(q.MissingReason, "ESP") {
		t.Errorf("MissingReason = %q, want an ESP explanation", q.MissingReason)
	}
}

func TestICMPQuoteShortTransport(t *testing.T) {
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0)
	hdr4 := testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolUDP, 5, 0, 1500)
	udp := testUDPHeader(53, 5353)

	// Four bytes of a UDP header are enough for both ports.
	q, err := ParseICMPv4Quote(tc4, concatBytes(hdr4, udp), len(hdr4)+4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 53 || q.DstPort != 5353 {
		t.Errorf("4-byte UDP quote: ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}

	// TCP with 4..7 bytes: ports known, sequence number still missing.
	hdr4 = testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500)
	tcp := testTCPHeader(12345, 80, 0xdeadbeef)
	for n := 4; n < 8; n++ {
		q, err = ParseICMPv4Quote(tc4, concatBytes(hdr4, tcp), len(hdr4)+n)
		if err != nil {
			t.Fatalf("prefix %d: unexpected error: %v", n, err)
		}
		if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 12345 || q.DstPort != 80 {
			t.Errorf("prefix %d: ports = %d -> %d (%s)", n, q.SrcPort, q.DstPort, q.PortsStatus)
		}
		if q.TCPSeqStatus != ICMPQuoteFieldMissing {
			t.Errorf("prefix %d: TCP sequence must be missing, got %#x", n, q.TCPSeq)
		}
	}
	// Eight bytes: the sequence number becomes known.
	q, err = ParseICMPv4Quote(tc4, concatBytes(hdr4, tcp), len(hdr4)+8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.TCPSeqStatus != ICMPQuoteFieldKnown || q.TCPSeq != 0xdeadbeef {
		t.Errorf("8-byte TCP quote: seq = %#x (%s)", q.TCPSeq, q.TCPSeqStatus)
	}
}

func TestICMPQuoteZeroPorts(t *testing.T) {
	// Port zero is a legitimate value and must be reported as known.
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0)
	quote := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolUDP, 5, 0, 1500),
		testUDPHeader(0, 0),
	)
	q, err := ParseICMPv4Quote(tc4, quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 0 || q.DstPort != 0 {
		t.Errorf("zero ports: got %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}

	tc6 := CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, 0)
	quote6 := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolTCP),
		testTCPHeader(0, 0, 0),
	)
	q6, err := ParseICMPv6Quote(tc6, quote6, len(quote6))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q6.PortsStatus != ICMPQuoteFieldKnown || q6.SrcPort != 0 || q6.DstPort != 0 {
		t.Errorf("zero v6 ports: got %d -> %d (%s)", q6.SrcPort, q6.DstPort, q6.PortsStatus)
	}
	if q6.TCPSeqStatus != ICMPQuoteFieldKnown || q6.TCPSeq != 0 {
		t.Errorf("zero v6 seq: got %#x (%s)", q6.TCPSeq, q6.TCPSeqStatus)
	}
}

func TestICMPQuoteNoRecursion(t *testing.T) {
	// A quoted ICMP message must not be parsed recursively; its type/code
	// bytes sit where ports would be, but they are not ports.
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0)
	inner := []byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0} // ICMPv4 echo request
	quote := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolICMPv4, 5, 0, 1500),
		inner,
	)
	q, err := ParseICMPv4Quote(tc4, quote, len(quote))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.ProtocolStatus != ICMPQuoteFieldKnown || q.Protocol != IPProtocolICMPv4 {
		t.Errorf("protocol = %v (%s)", q.Protocol, q.ProtocolStatus)
	}
	if q.PortsStatus != ICMPQuoteFieldMissing {
		t.Errorf("quoted ICMP must not yield ports, got %d -> %d", q.SrcPort, q.DstPort)
	}
	if !strings.Contains(q.MissingReason, "recursively") {
		t.Errorf("MissingReason = %q, want a no-recursion explanation", q.MissingReason)
	}
}

func TestICMPQuoteInvalid(t *testing.T) {
	tc4 := CreateICMPv4TypeCode(ICMPv4TypeTimeExceeded, 0)
	tc6 := CreateICMPv6TypeCode(ICMPv6TypeTimeExceeded, 0)

	// Illegal version in the quote.
	badVersion := concatBytes(
		testIPv6Header(quoteV6Src, quoteV6Dst, IPProtocolTCP),
		testTCPHeader(1, 2, 3),
	)
	if _, err := ParseICMPv4Quote(tc4, badVersion, len(badVersion)); !errors.Is(err, ErrICMPQuoteInvalid) {
		t.Errorf("v6 packet in v4 quote: got %v, want ErrICMPQuoteInvalid", err)
	}
	v4AsV6 := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500),
		testTCPHeader(1, 2, 3),
	)
	if _, err := ParseICMPv6Quote(tc6, v4AsV6, len(v4AsV6)); !errors.Is(err, ErrICMPQuoteInvalid) {
		t.Errorf("v4 packet in v6 quote: got %v, want ErrICMPQuoteInvalid", err)
	}

	// IHL below the minimum.
	lowIHL := testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500)
	lowIHL[0] = 0x44
	if _, err := ParseICMPv4Quote(tc4, lowIHL, len(lowIHL)); !errors.Is(err, ErrICMPQuoteInvalid) {
		t.Errorf("IHL 4: got %v, want ErrICMPQuoteInvalid", err)
	}

	// Header length contradicting the declared total length.
	badLen := testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 6, 0, 1500)
	binary.BigEndian.PutUint16(badLen[2:4], 22) // total length < IHL*4 = 24
	if _, err := ParseICMPv4Quote(tc4, badLen, len(badLen)); !errors.Is(err, ErrICMPQuoteInvalid) {
		t.Errorf("total length < header length: got %v, want ErrICMPQuoteInvalid", err)
	}

	// A declared total length larger than the quote is normal, not an error.
	short := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500),
		testTCPHeader(12345, 80, 0xdeadbeef),
	)
	if _, err := ParseICMPv4Quote(tc4, short, len(short)); err != nil {
		t.Errorf("declared length > quote: unexpected error %v", err)
	}
}

// TestICMPQuoteFullPacketDecodeUnchanged ensures the existing full-packet
// decode path is untouched and composes with the quote parser: decode a
// complete ICMPv4 Time Exceeded message, then parse its quote.
func TestICMPQuoteFullPacketDecodeUnchanged(t *testing.T) {
	quote := concatBytes(
		testIPv4Header(quoteV4Src, quoteV4Dst, IPProtocolTCP, 5, 0, 1500),
		testTCPHeader(12345, 80, 0xdeadbeef),
	)
	icmp := make([]byte, 8)
	icmp[0] = ICMPv4TypeTimeExceeded
	icmp[1] = ICMPv4CodeTTLExceeded
	pkt := concatBytes(
		testIPv4Header(quoteV4Dst, quoteV4Src, IPProtocolICMPv4, 5, 0, 0),
		icmp,
		quote,
	)
	p := gopacket.NewPacket(pkt, LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	icmpLayer := p.Layer(LayerTypeICMPv4)
	if icmpLayer == nil {
		t.Fatal("ICMPv4 layer not decoded")
	}
	icmp4 := icmpLayer.(*ICMPv4)
	if icmp4.TypeCode.Type() != ICMPv4TypeTimeExceeded {
		t.Fatalf("type = %d, want TimeExceeded", icmp4.TypeCode.Type())
	}
	q, err := ParseICMPv4Quote(icmp4.TypeCode, icmp4.Payload, len(icmp4.Payload))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.PortsStatus != ICMPQuoteFieldKnown || q.SrcPort != 12345 || q.DstPort != 80 {
		t.Errorf("ports = %d -> %d (%s)", q.SrcPort, q.DstPort, q.PortsStatus)
	}
	if q.TCPSeqStatus != ICMPQuoteFieldKnown || q.TCPSeq != 0xdeadbeef {
		t.Errorf("tcp seq = %#x (%s)", q.TCPSeq, q.TCPSeqStatus)
	}
}
