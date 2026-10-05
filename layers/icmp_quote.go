// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ICMPErrorQuoteStatus reports whether the invocation and quote can be decoded.
type ICMPErrorQuoteStatus int

const (
	// ICMPErrorQuoteDecoded indicates that at least part of the quote was
	// decoded. Missing optional fields are reported independently.
	ICMPErrorQuoteDecoded ICMPErrorQuoteStatus = iota
	// ICMPErrorQuoteNotApplicable indicates that the ICMP message is not an
	// error message which carries a quoted packet.
	ICMPErrorQuoteNotApplicable
)

// ICMPQuoteFieldStatus reports whether an optional quoted field was observed.
type ICMPQuoteFieldStatus int

const (
	ICMPQuoteFieldMissing ICMPQuoteFieldStatus = iota
	ICMPQuoteFieldKnown
)

// ICMPQuoteField is an optional field decoded from an ICMP error quote.
type ICMPQuoteField[T any] struct {
	Status ICMPQuoteFieldStatus
	Value  T
	Reason string
}

// Known reports whether the field value was present in the quote.
func (f ICMPQuoteField[T]) Known() bool {
	return f.Status == ICMPQuoteFieldKnown
}

func knownQuoteField[T any](value T) ICMPQuoteField[T] {
	return ICMPQuoteField[T]{Status: ICMPQuoteFieldKnown, Value: value}
}

func missingQuoteField[T any](reason string) ICMPQuoteField[T] {
	return ICMPQuoteField[T]{Reason: reason}
}

// ICMPErrorQuote contains fields recovered from the packet quoted by an
// ICMPv4 or ICMPv6 error message.
type ICMPErrorQuote struct {
	SrcIP         ICMPQuoteField[net.IP]
	DstIP         ICMPQuoteField[net.IP]
	Protocol      ICMPQuoteField[IPProtocol]
	SrcPort       ICMPQuoteField[uint16]
	DstPort       ICMPQuoteField[uint16]
	TCPSeq        ICMPQuoteField[uint32]
	Fragmented    bool
	FirstFragment bool
}

func knownIP(b []byte) ICMPQuoteField[net.IP] {
	return knownQuoteField(net.IP(append(net.IP(nil), b...)))
}

// ParseICMPv4ErrorQuote decodes length bytes of the packet quoted by an
// ICMPv4 error message. quote contains the bytes following the eight-byte
// ICMPv4 header; length must not exceed len(quote).
func ParseICMPv4ErrorQuote(quote []byte, length int, typ uint8) (ICMPErrorQuote, ICMPErrorQuoteStatus, error) {
	if !isICMPv4ErrorType(typ) {
		return ICMPErrorQuote{}, ICMPErrorQuoteNotApplicable, nil
	}
	return parseIPErrorQuote(quote, length)
}

// ParseErrorQuote decodes length bytes from the packet quoted by this
// ICMPv4 error message.
func (i *ICMPv4) ParseErrorQuote(quote []byte, length int) (ICMPErrorQuote, ICMPErrorQuoteStatus, error) {
	return ParseICMPv4ErrorQuote(quote, length, i.TypeCode.Type())
}

// ParseICMPv6ErrorQuote decodes length bytes of the packet quoted by an
// ICMPv6 error message. quote contains the bytes following the eight-byte
// ICMPv6 header; length must not exceed len(quote).
func ParseICMPv6ErrorQuote(quote []byte, length int, typ uint8) (ICMPErrorQuote, ICMPErrorQuoteStatus, error) {
	if !isICMPv6ErrorType(typ) {
		return ICMPErrorQuote{}, ICMPErrorQuoteNotApplicable, nil
	}
	return parseIPErrorQuote(quote, length)
}

// ParseErrorQuote decodes length bytes from the packet quoted by this
// ICMPv6 error message.
func (i *ICMPv6) ParseErrorQuote(quote []byte, length int) (ICMPErrorQuote, ICMPErrorQuoteStatus, error) {
	return ParseICMPv6ErrorQuote(quote, length, i.TypeCode.Type())
}

func isICMPv4ErrorType(typ uint8) bool {
	switch typ {
	case ICMPv4TypeDestinationUnreachable,
		ICMPv4TypeSourceQuench,
		ICMPv4TypeRedirect,
		ICMPv4TypeTimeExceeded,
		ICMPv4TypeParameterProblem:
		return true
	default:
		return false
	}
}

func isICMPv6ErrorType(typ uint8) bool {
	switch typ {
	case ICMPv6TypeDestinationUnreachable,
		ICMPv6TypePacketTooBig,
		ICMPv6TypeTimeExceeded,
		ICMPv6TypeParameterProblem:
		return true
	default:
		return false
	}
}

func parseIPErrorQuote(quote []byte, length int) (parsed ICMPErrorQuote, status ICMPErrorQuoteStatus, err error) {
	if length < 0 {
		return ICMPErrorQuote{}, ICMPErrorQuoteDecoded, fmt.Errorf("ICMP error quote length %d is negative", length)
	}
	if length > len(quote) {
		return ICMPErrorQuote{}, ICMPErrorQuoteDecoded, fmt.Errorf("ICMP error quote length %d exceeds available data length %d", length, len(quote))
	}
	if length == 0 {
		parsed.markShortIPHeader("quoted packet is empty")
		return parsed, ICMPErrorQuoteDecoded, nil
	}

	data := quote[:length]
	version := data[0] >> 4
	switch version {
	case 4:
		err = parseIPv4ErrorQuote(data, &parsed)
	case 6:
		err = parseIPv6ErrorQuote(data, &parsed)
	default:
		return ICMPErrorQuote{}, ICMPErrorQuoteDecoded, fmt.Errorf("invalid quoted IP version %d", version)
	}
	if err != nil {
		return ICMPErrorQuote{}, ICMPErrorQuoteDecoded, err
	}
	return parsed, ICMPErrorQuoteDecoded, nil
}

func (q *ICMPErrorQuote) markShortIPHeader(reason string) {
	q.SrcIP = missingQuoteField[net.IP](reason)
	q.DstIP = missingQuoteField[net.IP](reason)
	q.Protocol = missingQuoteField[IPProtocol](reason)
	q.SrcPort = missingQuoteField[uint16](reason)
	q.DstPort = missingQuoteField[uint16](reason)
	q.TCPSeq = missingQuoteField[uint32](reason)
}

func parseIPv4ErrorQuote(data []byte, q *ICMPErrorQuote) error {
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 {
		return fmt.Errorf("invalid quoted IPv4 IHL %d", ihl/4)
	}

	var declaredLength int
	if len(data) >= 4 {
		declaredLength = int(binary.BigEndian.Uint16(data[2:4]))
		if declaredLength != 0 && declaredLength < ihl {
			return fmt.Errorf("quoted IPv4 total length %d is smaller than header length %d", declaredLength, ihl)
		}
	}

	if len(data) < ihl {
		if len(data) >= 10 {
			q.Protocol = knownQuoteField(IPProtocol(data[9]))
		} else {
			q.Protocol = missingQuoteField[IPProtocol]("quoted IPv4 header is truncated before protocol")
		}
		if len(data) >= 16 {
			q.SrcIP = knownIP(data[12:16])
		} else {
			q.SrcIP = missingQuoteField[net.IP]("quoted IPv4 header is truncated before source address")
		}
		if len(data) >= 20 {
			q.DstIP = knownIP(data[16:20])
		} else {
			q.DstIP = missingQuoteField[net.IP]("quoted IPv4 header is truncated before destination address")
		}
		q.markTransportMissing("quoted IPv4 header is truncated")
		return nil
	}

	q.Protocol = knownQuoteField(IPProtocol(data[9]))
	q.SrcIP = knownIP(data[12:16])
	q.DstIP = knownIP(data[16:20])

	frag := binary.BigEndian.Uint16(data[6:8])
	moreFragments := frag&0x2000 != 0
	fragmentOffset := frag & 0x1fff
	q.Fragmented = moreFragments || fragmentOffset != 0
	q.FirstFragment = fragmentOffset == 0

	if q.Fragmented && !q.FirstFragment {
		reason := "quoted packet is a non-first IPv4 fragment"
		q.SrcPort = missingQuoteField[uint16](reason)
		q.DstPort = missingQuoteField[uint16](reason)
		q.TCPSeq = missingQuoteField[uint32](reason)
		return nil
	}

	transportEnd := len(data)
	if declaredLength != 0 {
		if declaredLength < transportEnd {
			transportEnd = declaredLength
		}
	}
	parseQuotedTransport(data[ihl:transportEnd], q)
	return nil
}

func parseIPv6ErrorQuote(data []byte, q *ICMPErrorQuote) error {
	if len(data) < 40 {
		reason := "quoted IPv6 header is truncated"
		q.Protocol = missingQuoteField[IPProtocol](reason)
		if len(data) >= 24 {
			q.SrcIP = knownIP(data[8:24])
		} else {
			q.SrcIP = missingQuoteField[net.IP](reason)
		}
		q.DstIP = missingQuoteField[net.IP](reason)
		q.markTransportMissing(reason)
		return nil
	}

	q.SrcIP = knownIP(data[8:24])
	q.DstIP = knownIP(data[24:40])

	next := IPProtocol(data[6])
	rest := data[40:]
	declaredPayloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	packetEnd := 40 + declaredPayloadLength
	headerOffset := 40
	q.FirstFragment = true
	q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 final protocol is not present")

	for {
		switch next {
		case IPProtocolTCP, IPProtocolUDP, IPProtocolUDPLite, IPProtocolESP, IPProtocolICMPv4, IPProtocolICMPv6, IPProtocolNoNextHeader:
			q.Protocol = knownQuoteField(next)
			transport := rest
			if declaredPayloadLength > 0 && packetEnd-headerOffset < len(transport) {
				transport = transport[:packetEnd-headerOffset]
			}
			switch next {
			case IPProtocolTCP, IPProtocolUDP, IPProtocolUDPLite:
				parseQuotedTransport(transport, q)
			case IPProtocolESP:
				q.markTransportMissing("quoted payload is encrypted with ESP")
			default:
				q.markTransportMissing("quoted transport protocol has no ports")
			}
			return nil
		case IPProtocolIPv6Fragment:
			if len(rest) == 0 {
				q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 fragment header is truncated before next header")
				q.markTransportMissing("quoted IPv6 fragment header is truncated")
				return nil
			}
			innerNext := IPProtocol(rest[0])
			if declaredPayloadLength > 0 && packetEnd-headerOffset < 8 {
				return fmt.Errorf("quoted IPv6 payload length %d is smaller than fragment header length 8", declaredPayloadLength)
			}
			if len(rest) < 8 {
				if isTerminalIPv6Protocol(innerNext) {
					q.Protocol = knownQuoteField(innerNext)
				} else {
					q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 fragment header is truncated before final next header")
				}
				q.markTransportMissing("quoted IPv6 fragment header is truncated")
				return nil
			}
			next = innerNext
			fragmentOffset := binary.BigEndian.Uint16(rest[2:4]) >> 3
			more := rest[3]&1 != 0
			q.Fragmented = more || fragmentOffset != 0
			q.FirstFragment = fragmentOffset == 0
			rest = rest[8:]
			headerOffset += 8
		case IPProtocolIPv6HopByHop, IPProtocolIPv6Routing, IPProtocolIPv6Destination, IPProtocolAH:
			if len(rest) == 0 {
				q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 extension header is truncated before next header")
				q.markTransportMissing("quoted IPv6 extension header is truncated")
				return nil
			}
			innerNext := IPProtocol(rest[0])
			var headerLength int
			if next == IPProtocolAH {
				if len(rest) < 2 {
					if isTerminalIPv6Protocol(innerNext) {
						q.Protocol = knownQuoteField(innerNext)
					} else {
						q.Protocol = missingQuoteField[IPProtocol]("quoted AH header is truncated before final next header")
					}
					q.markTransportMissing("quoted AH header is truncated")
					return nil
				}
				headerLength = int(rest[1]+2) * 4
				if headerLength < 12 {
					return fmt.Errorf("invalid quoted AH header length %d", headerLength)
				}
			} else {
				if len(rest) < 2 {
					if isTerminalIPv6Protocol(innerNext) {
						q.Protocol = knownQuoteField(innerNext)
					} else {
						q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 extension header is truncated before final next header")
					}
					q.markTransportMissing("quoted IPv6 extension header is truncated")
					return nil
				}
				headerLength = int(rest[1]+1) * 8
			}

			if declaredPayloadLength > 0 && packetEnd-headerOffset < headerLength {
				return fmt.Errorf("quoted IPv6 extension header length %d exceeds declared remaining payload length %d", headerLength, packetEnd-headerOffset)
			}
			if len(rest) < headerLength {
				if isTerminalIPv6Protocol(innerNext) {
					q.Protocol = knownQuoteField(innerNext)
				} else {
					q.Protocol = missingQuoteField[IPProtocol]("quoted IPv6 extension chain is truncated before final protocol")
				}
				reason := "quoted IPv6 extension header is truncated before its declared end"
				q.markTransportMissing(reason)
				return nil
			}
			next = innerNext
			rest = rest[headerLength:]
			headerOffset += headerLength
		default:
			q.Protocol = knownQuoteField(next)
			q.markTransportMissing("quoted transport protocol has no ports")
			return nil
		}
	}
}

func isTerminalIPv6Protocol(protocol IPProtocol) bool {
	switch protocol {
	case IPProtocolTCP, IPProtocolUDP, IPProtocolUDPLite, IPProtocolESP,
		IPProtocolICMPv4, IPProtocolICMPv6, IPProtocolNoNextHeader:
		return true
	default:
		return false
	}
}

func (q *ICMPErrorQuote) markTransportMissing(reason string) {
	if q.Fragmented && !q.FirstFragment {
		reason = "quoted packet is a non-first IP fragment"
	}
	q.SrcPort = missingQuoteField[uint16](reason)
	q.DstPort = missingQuoteField[uint16](reason)
	q.TCPSeq = missingQuoteField[uint32](reason)
}

func parseQuotedTransport(data []byte, q *ICMPErrorQuote) {
	if q.Fragmented && !q.FirstFragment {
		q.markTransportMissing("quoted packet is a non-first IP fragment")
		return
	}

	switch q.Protocol.Value {
	case IPProtocolTCP:
		if len(data) < 8 {
			reason := "quoted TCP header is truncated"
			if len(data) >= 4 {
				q.SrcPort = knownQuoteField(binary.BigEndian.Uint16(data[0:2]))
				q.DstPort = knownQuoteField(binary.BigEndian.Uint16(data[2:4]))
				q.TCPSeq = missingQuoteField[uint32](reason)
				return
			}
			if len(data) >= 2 {
				q.SrcPort = knownQuoteField(binary.BigEndian.Uint16(data[0:2]))
				q.DstPort = missingQuoteField[uint16](reason)
				q.TCPSeq = missingQuoteField[uint32](reason)
				return
			}
			q.markTransportMissing(reason)
		} else {
			q.SrcPort = knownQuoteField(binary.BigEndian.Uint16(data[0:2]))
			q.DstPort = knownQuoteField(binary.BigEndian.Uint16(data[2:4]))
			q.TCPSeq = knownQuoteField(binary.BigEndian.Uint32(data[4:8]))
		}
	case IPProtocolUDP, IPProtocolUDPLite:
		if len(data) >= 4 {
			q.SrcPort = knownQuoteField(binary.BigEndian.Uint16(data[0:2]))
			q.DstPort = knownQuoteField(binary.BigEndian.Uint16(data[2:4]))
			return
		}
		if len(data) >= 2 {
			q.SrcPort = knownQuoteField(binary.BigEndian.Uint16(data[0:2]))
			q.DstPort = missingQuoteField[uint16]("quoted UDP header is truncated")
			return
		}
		q.markTransportMissing("quoted UDP header is truncated")
	default:
		q.markTransportMissing("quoted transport protocol has no ports")
	}
}
