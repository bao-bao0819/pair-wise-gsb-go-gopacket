// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
)

func quoteFieldReflect(quote ICMPErrorQuote, name string) (bool, any) {
	field := reflect.ValueOf(quote).FieldByName(name)
	status := field.FieldByName("Status")
	value := field.FieldByName("Value")
	return status.Interface().(ICMPQuoteFieldStatus) == ICMPQuoteFieldKnown, value.Interface()
}

func expectKnownField(t *testing.T, quote ICMPErrorQuote, name string, want any) {
	t.Helper()
	known, got := quoteFieldReflect(quote, name)
	if !known {
		field := reflect.ValueOf(quote).FieldByName(name)
		t.Fatalf("%s is not known: %s", name, field.FieldByName("Reason").String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s = %v; want %v", name, got, want)
	}
}

func expectMissingField(t *testing.T, quote ICMPErrorQuote, name string) {
	t.Helper()
	if known, _ := quoteFieldReflect(quote, name); known {
		t.Fatalf("%s is unexpectedly known", name)
	}
}

func buildIPv4TCPQuote(ihl byte, fragmentFlags uint16) []byte {
	packet := make([]byte, ihl+12)
	packet[0] = 0x40 | (ihl / 4)
	packet[1] = 0
	packet[8] = 64
	packet[9] = byte(IPProtocolTCP)
	copy(packet[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(packet[16:20], net.IPv4(192, 0, 2, 1).To4())
	packet[6] = byte(fragmentFlags >> 8)
	packet[7] = byte(fragmentFlags)
	transport := packet[ihl:]
	transport[0] = 0x00
	transport[1] = 0x50
	transport[2] = 0x01
	transport[3] = 0xbb
	transport[4] = 0x12
	transport[5] = 0x34
	transport[6] = 0x56
	transport[7] = 0x78
	totalLength := uint16(len(packet))
	packet[2] = byte(totalLength >> 8)
	packet[3] = byte(totalLength)
	return packet
}

func buildIPv6Quote(next IPProtocol, trailer []byte, trailers ...[]byte) []byte {
	var packet []byte
	packet = append(packet, trailer...)
	for i := len(trailers) - 1; i >= 0; i-- {
		packet = append(trailers[i], packet...)
	}

	header := make([]byte, 40+len(packet))
	header[0] = 0x60
	header[6] = byte(next)
	header[7] = 64
	payloadLength := uint16(len(packet))
	header[4] = byte(payloadLength >> 8)
	header[5] = byte(payloadLength)
	copy(header[8:24], net.ParseIP("2001:db8::1"))
	copy(header[24:40], net.ParseIP("2001:db8::2"))
	copy(header[40:], packet)
	return header
}

func TestParseICMPv4ErrorQuoteWithOptions(t *testing.T) {
	original := buildIPv4TCPQuote(24, 0)
	quote := append(append([]byte(nil), original...), 0xde, 0xad, 0xbe, 0xef)

	parsed, status, err := ParseICMPv4ErrorQuote(quote, len(original), ICMPv4TypeTimeExceeded)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("ParseICMPv4ErrorQuote() = status %d, err %v", status, err)
	}
	expectKnownField(t, parsed, "SrcIP", net.IPv4(10, 0, 0, 1).To4())
	expectKnownField(t, parsed, "DstIP", net.IPv4(192, 0, 2, 1).To4())
	expectKnownField(t, parsed, "Protocol", IPProtocolTCP)
	expectKnownField(t, parsed, "SrcPort", uint16(0x0050))
	expectKnownField(t, parsed, "DstPort", uint16(0x01bb))
	expectKnownField(t, parsed, "TCPSeq", uint32(0x12345678))

	shortQuote := append([]byte(nil), original[:28]...)
	binary.BigEndian.PutUint16(shortQuote[2:4], 100)
	parsed, status, err = ParseICMPv4ErrorQuote(shortQuote, len(shortQuote), ICMPv4TypeTimeExceeded)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("short quote with larger declared length = status %d, err %v", status, err)
	}
	expectKnownField(t, parsed, "Protocol", IPProtocolTCP)
	expectKnownField(t, parsed, "SrcIP", net.IPv4(10, 0, 0, 1).To4())
	expectKnownField(t, parsed, "DstIP", net.IPv4(192, 0, 2, 1).To4())
	expectKnownField(t, parsed, "SrcPort", uint16(0x0050))
	expectKnownField(t, parsed, "DstPort", uint16(0x01bb))
	expectMissingField(t, parsed, "TCPSeq")
}

func TestParseICMPv4NonFirstFragmentDoesNotReadPorts(t *testing.T) {
	quote := buildIPv4TCPQuote(20, 0x2001)
	parsed, status, err := ParseICMPv4ErrorQuote(quote, len(quote), ICMPv4TypeTimeExceeded)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("ParseICMPv4ErrorQuote() = status %d, err %v", status, err)
	}
	if !parsed.Fragmented || parsed.FirstFragment {
		t.Fatalf("Fragmented=%v, FirstFragment=%v", parsed.Fragmented, parsed.FirstFragment)
	}
	expectKnownField(t, parsed, "Protocol", IPProtocolTCP)
	expectMissingField(t, parsed, "SrcPort")
	expectMissingField(t, parsed, "DstPort")
	expectMissingField(t, parsed, "TCPSeq")
}

func TestParseICMPv6FragmentAndESP(t *testing.T) {
	tcp := []byte{0x00, 0x50, 0x01, 0xbb, 0x12, 0x34, 0x56, 0x78}
	fragment := make([]byte, 8)
	fragment[0] = byte(IPProtocolTCP)
	fragment[2] = 0x00
	fragment[3] = 0x01
	fragment[7] = 42
	quote := buildIPv6Quote(IPProtocolIPv6Fragment, fragment, tcp)

	parsed, status, err := ParseICMPv6ErrorQuote(quote, len(quote), ICMPv6TypeTimeExceeded)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("ParseICMPv6ErrorQuote() = status %d, err %v", status, err)
	}
	if !parsed.Fragmented || parsed.FirstFragment {
		t.Fatalf("Fragmented=%v, FirstFragment=%v", parsed.Fragmented, parsed.FirstFragment)
	}
	expectKnownField(t, parsed, "Protocol", IPProtocolTCP)
	expectMissingField(t, parsed, "SrcPort")
	expectMissingField(t, parsed, "DstPort")
	expectMissingField(t, parsed, "TCPSeq")

	esp := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	espQuote := buildIPv6Quote(IPProtocolESP, esp)
	parsed, status, err = ParseICMPv6ErrorQuote(espQuote, len(espQuote), ICMPv6TypePacketTooBig)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("ParseICMPv6ErrorQuote(ESP) = status %d, err %v", status, err)
	}
	expectKnownField(t, parsed, "Protocol", IPProtocolESP)
	expectMissingField(t, parsed, "SrcPort")
	expectMissingField(t, parsed, "DstPort")
	expectMissingField(t, parsed, "TCPSeq")
}

func TestParseICMPv6HalfExtensionReturnsConfirmedFields(t *testing.T) {
	extension := []byte{byte(IPProtocolTCP), 1, 0}
	quote := buildIPv6Quote(IPProtocolIPv6Destination, extension)
	binary.BigEndian.PutUint16(quote[4:6], 16)

	parsed, status, err := ParseICMPv6ErrorQuote(quote, len(quote)-1, ICMPv6TypeTimeExceeded)
	if err != nil || status != ICMPErrorQuoteDecoded {
		t.Fatalf("ParseICMPv6ErrorQuote() = status %d, err %v", status, err)
	}
	expectKnownField(t, parsed, "SrcIP", net.ParseIP("2001:db8::1"))
	expectKnownField(t, parsed, "DstIP", net.ParseIP("2001:db8::2"))
	expectKnownField(t, parsed, "Protocol", IPProtocolTCP)
	expectMissingField(t, parsed, "SrcPort")
	expectMissingField(t, parsed, "DstPort")
	expectMissingField(t, parsed, "TCPSeq")
}

func TestParseICMPQuoteZeroPortsAndTruncatedTCP(t *testing.T) {
	udp := []byte{0, 0, 0, 0}
	quote := buildIPv6Quote(IPProtocolUDP, udp)
	quoteWithTrailer := append(quote, 0xff, 0xff, 0xff, 0xff)
	parsed, _, err := ParseICMPv6ErrorQuote(quoteWithTrailer, len(quote), ICMPv6TypeDestinationUnreachable)
	if err != nil {
		t.Fatal(err)
	}
	expectKnownField(t, parsed, "Protocol", IPProtocolUDP)
	expectKnownField(t, parsed, "SrcPort", uint16(0))
	expectKnownField(t, parsed, "DstPort", uint16(0))
	expectMissingField(t, parsed, "TCPSeq")

	tcp := []byte{0, 1, 0, 2, 0, 3, 0}
	quote = buildIPv6Quote(IPProtocolTCP, tcp)
	parsed, _, err = ParseICMPv6ErrorQuote(quote, len(quote), ICMPv6TypeTimeExceeded)
	if err != nil {
		t.Fatal(err)
	}
	expectKnownField(t, parsed, "SrcPort", uint16(1))
	expectKnownField(t, parsed, "DstPort", uint16(2))
	expectMissingField(t, parsed, "TCPSeq")
}

func TestParseICMPErrorQuoteNotApplicable(t *testing.T) {
	quote := buildIPv4TCPQuote(20, 0)
	if parsed, status, err := ParseICMPv4ErrorQuote(quote, len(quote), ICMPv4TypeEchoRequest); err != nil || status != ICMPErrorQuoteNotApplicable {
		t.Fatalf("v4 echo = parsed %#v, status %d, err %v", parsed, status, err)
	}
	if parsed, status, err := ParseICMPv6ErrorQuote(quote, len(quote), ICMPv6TypeEchoRequest); err != nil || status != ICMPErrorQuoteNotApplicable {
		t.Fatalf("v6 echo = parsed %#v, status %d, err %v", parsed, status, err)
	}
}

func TestParseICMPErrorQuoteInvalidLengthsAndVersions(t *testing.T) {
	quote := buildIPv4TCPQuote(20, 0)
	if _, _, err := ParseICMPv4ErrorQuote(quote, len(quote)+1, ICMPv4TypeTimeExceeded); err == nil {
		t.Fatal("length beyond quote unexpectedly succeeded")
	}
	if _, _, err := ParseICMPv4ErrorQuote(quote, -1, ICMPv4TypeTimeExceeded); err == nil {
		t.Fatal("negative length unexpectedly succeeded")
	}

	quote[0] = 0x50 | 5
	if _, _, err := ParseICMPv4ErrorQuote(quote, len(quote), ICMPv4TypeTimeExceeded); err == nil {
		t.Fatal("invalid version unexpectedly succeeded")
	}

	quote = buildIPv4TCPQuote(20, 0)
	quote[0] = 0x40 | 4
	if _, _, err := ParseICMPv4ErrorQuote(quote, len(quote), ICMPv4TypeTimeExceeded); err == nil {
		t.Fatal("invalid IHL unexpectedly succeeded")
	}

	quote = buildIPv4TCPQuote(20, 0)
	binary.BigEndian.PutUint16(quote[2:4], 10)
	if _, _, err := ParseICMPv4ErrorQuote(quote, len(quote), ICMPv4TypeTimeExceeded); err == nil {
		t.Fatal("IPv4 total length/header length contradiction unexpectedly succeeded")
	}

	extension := []byte{byte(IPProtocolTCP), 1}
	ipv6 := buildIPv6Quote(IPProtocolIPv6Destination, extension)
	binary.BigEndian.PutUint16(ipv6[4:6], 8)
	if _, _, err := ParseICMPv6ErrorQuote(ipv6, len(ipv6), ICMPv6TypeTimeExceeded); err == nil {
		t.Fatal("IPv6 extension length contradiction unexpectedly succeeded")
	}
}

func TestICMPErrorQuoteBytePrefixMonotonicity(t *testing.T) {
	samples := []struct {
		name  string
		typ   uint8
		quote []byte
		parse func([]byte, int, uint8) (ICMPErrorQuote, ICMPErrorQuoteStatus, error)
	}{
		{"v4-options-tcp", ICMPv4TypeTimeExceeded, buildIPv4TCPQuote(24, 0), ParseICMPv4ErrorQuote},
		{"v6-zero-udp", ICMPv6TypeDestinationUnreachable, buildIPv6Quote(IPProtocolUDP, []byte{0, 0, 0, 0}), ParseICMPv6ErrorQuote},
		{"v6-fragment-tcp", ICMPv6TypeTimeExceeded, buildIPv6Quote(IPProtocolIPv6Fragment,
			[]byte{byte(IPProtocolTCP), 0, 0, 0, 0, 0, 0, 1},
			[]byte{0, 0x50, 0, 80, 1, 2, 3, 4}), ParseICMPv6ErrorQuote},
	}

	for _, sample := range samples {
		t.Run(sample.name, func(t *testing.T) {
			var previous ICMPErrorQuote
			for length := 1; length <= len(sample.quote); length++ {
				current, status, err := sample.parse(sample.quote, length, sample.typ)
				if err != nil || status != ICMPErrorQuoteDecoded {
					t.Fatalf("length %d: status %d, err %v", length, status, err)
				}
				for _, name := range []string{"SrcIP", "DstIP", "Protocol", "SrcPort", "DstPort", "TCPSeq"} {
					prevKnown, prevValue := quoteFieldReflect(previous, name)
					currKnown, currValue := quoteFieldReflect(current, name)
					if prevKnown && (!currKnown || !reflect.DeepEqual(prevValue, currValue)) {
						t.Fatalf("length %d field %s changed from known %#v to status known=%v value %#v", length, name, prevValue, currKnown, currValue)
					}
				}
				previous = current
			}
		})
	}
}

func TestExistingFullUDPPacketDecodeStillRejectsFourByteHeader(t *testing.T) {
	var udp UDP
	err := udp.DecodeFromBytes([]byte{0, 1, 0, 2}, gopacket.NilDecodeFeedback)
	if err == nil {
		t.Fatal("full UDP decoder accepted a four-byte UDP header")
	}
}
