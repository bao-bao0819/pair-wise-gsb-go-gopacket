// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// This file implements a best-effort parser for the packet quotes carried by
// ICMPv4/ICMPv6 error messages (Destination Unreachable, Time Exceeded, ...).
//
// A quote typically contains only the original IP header plus the first few
// bytes of the transport header, so decoding it as a complete packet fails
// with truncation errors and yields nothing. The parsers below instead treat
// the quote as a prefix of the original packet: every field is reported with
// a known/missing status, and parsing stops at the first byte boundary where
// evidence runs out, keeping whatever was already confirmed.
//
// The caller passes the quote length explicitly (e.g. derived from an RFC 4884
// length field) so trailing ICMP extension data is never mistaken for quoted
// packet bytes; the parsers never look beyond it.

// ErrICMPQuoteNotApplicable is returned when the ICMP message is not an error
// message and therefore does not carry a quoted packet (e.g. Echo
// Request/Reply and other informational messages).
var ErrICMPQuoteNotApplicable = errors.New("ICMP message type does not carry a quoted packet")

// ErrICMPQuoteInvalid is returned (wrapped) when the quoted bytes contradict
// themselves: an illegal IP version, an IPv4 header length below the minimum,
// or a header length exceeding the declared total length. This is distinct
// from a merely short quote, which is not an error and simply leaves the
// missing fields marked as such.
var ErrICMPQuoteInvalid = errors.New("invalid quoted packet")

// ICMPQuoteFieldStatus reports whether a field of a quoted packet could be
// recovered from the quoted bytes.
type ICMPQuoteFieldStatus int

const (
	// ICMPQuoteFieldMissing means the quote did not contain enough evidence
	// for the field; the corresponding value is zero and must be ignored.
	ICMPQuoteFieldMissing ICMPQuoteFieldStatus = iota
	// ICMPQuoteFieldKnown means the field value is valid. Note that a known
	// value may legitimately be zero (e.g. port 0).
	ICMPQuoteFieldKnown
)

func (s ICMPQuoteFieldStatus) String() string {
	switch s {
	case ICMPQuoteFieldKnown:
		return "Known"
	default:
		return "Missing"
	}
}

// ICMPQuote holds the fields recovered from the packet quote of an ICMP error
// message. Each optional field is paired with a status telling whether the
// value is valid.
type ICMPQuote struct {
	// IPVersion is 4 or 6, taken from the quoted IP header.
	IPVersion int
	// SrcIP and DstIP are the source and destination addresses of the
	// original packet. Valid when AddressesStatus is ICMPQuoteFieldKnown.
	SrcIP net.IP
	DstIP net.IP
	// Protocol is the final (upper-layer) protocol of the original packet,
	// after walking any IPv6 extension headers. Valid when ProtocolStatus is
	// ICMPQuoteFieldKnown.
	Protocol IPProtocol
	// SrcPort and DstPort are the transport ports of the original packet.
	// Valid when PortsStatus is ICMPQuoteFieldKnown. A port value of zero is
	// still a known value when the status is ICMPQuoteFieldKnown.
	SrcPort uint16
	DstPort uint16
	// TCPSeq is the TCP sequence number of the original packet. Valid when
	// TCPSeqStatus is ICMPQuoteFieldKnown.
	TCPSeq uint32

	AddressesStatus ICMPQuoteFieldStatus
	ProtocolStatus  ICMPQuoteFieldStatus
	PortsStatus     ICMPQuoteFieldStatus
	TCPSeqStatus    ICMPQuoteFieldStatus

	// MissingReason explains, in human-readable form, why the deepest
	// missing field could not be recovered (short quote, non-first fragment,
	// encrypted payload, ...). Empty when everything was recovered.
	MissingReason string
}

// ParseICMPv4Quote parses the packet quote of an ICMPv4 error message.
// payload must start at the quoted packet (i.e. right after the 8-byte ICMPv4
// error header) and quoteLen is the caller-supplied quote length in bytes;
// bytes beyond quoteLen (e.g. RFC 4884 ICMP extensions) are never examined.
// If quoteLen exceeds len(payload), only the available bytes are used.
//
// Non-error ICMPv4 messages return ErrICMPQuoteNotApplicable. A short quote is
// not an error: the returned quote holds every field that could be confirmed,
// with the rest marked ICMPQuoteFieldMissing. Contradictory headers and
// illegal IP versions return an error wrapping ErrICMPQuoteInvalid.
func ParseICMPv4Quote(typeCode ICMPv4TypeCode, payload []byte, quoteLen int) (*ICMPQuote, error) {
	switch typeCode.Type() {
	case ICMPv4TypeDestinationUnreachable,
		ICMPv4TypeSourceQuench,
		ICMPv4TypeRedirect,
		ICMPv4TypeTimeExceeded,
		ICMPv4TypeParameterProblem:
	default:
		return nil, fmt.Errorf("%w: ICMPv4 %s", ErrICMPQuoteNotApplicable, typeCode)
	}
	q := &ICMPQuote{}
	if err := q.parseIPv4Quote(icmpQuoteBytes(payload, quoteLen)); err != nil {
		return nil, err
	}
	return q, nil
}

// ParseICMPv6Quote parses the packet quote of an ICMPv6 error message.
// payload must start at the quoted packet (i.e. right after the 8-byte ICMPv6
// error header) and quoteLen is the caller-supplied quote length in bytes;
// bytes beyond quoteLen are never examined. If quoteLen exceeds len(payload),
// only the available bytes are used.
//
// Per RFC 4443 only message types 0-127 are error messages; informational
// messages (Echo, Neighbor Discovery, MLD, ...) return
// ErrICMPQuoteNotApplicable. See ParseICMPv4Quote for the error semantics.
func ParseICMPv6Quote(typeCode ICMPv6TypeCode, payload []byte, quoteLen int) (*ICMPQuote, error) {
	if typeCode.Type() >= 128 {
		return nil, fmt.Errorf("%w: ICMPv6 %s", ErrICMPQuoteNotApplicable, typeCode)
	}
	q := &ICMPQuote{}
	if err := q.parseIPv6Quote(icmpQuoteBytes(payload, quoteLen)); err != nil {
		return nil, err
	}
	return q, nil
}

// icmpQuoteBytes isolates the quoted packet from trailing ICMP extension data
// using the caller-supplied quote length, never guessing from the buffer.
func icmpQuoteBytes(payload []byte, quoteLen int) []byte {
	if quoteLen < 0 {
		quoteLen = 0
	}
	if quoteLen > len(payload) {
		quoteLen = len(payload)
	}
	return payload[:quoteLen]
}

func (q *ICMPQuote) parseIPv4Quote(quote []byte) error {
	q.IPVersion = 4
	if len(quote) < 1 {
		q.MissingReason = "quote is empty"
		return nil
	}
	if version := quote[0] >> 4; version != 4 {
		return fmt.Errorf("%w: quoted packet has IP version %d, want 4", ErrICMPQuoteInvalid, version)
	}
	ihl := int(quote[0]&0x0F) * 4
	if ihl < 20 {
		return fmt.Errorf("%w: IPv4 header length %d smaller than minimum 20", ErrICMPQuoteInvalid, ihl)
	}
	if len(quote) < 4 {
		q.MissingReason = "quote ends inside IPv4 header"
		return nil
	}
	// A declared total length larger than the quote is normal: routers only
	// quote the first bytes of the original packet. A total length smaller
	// than the header length is a contradiction. A zero total length (as
	// produced by TSO) carries no information and is not checked.
	if totalLen := int(binary.BigEndian.Uint16(quote[2:4])); totalLen != 0 && totalLen < ihl {
		return fmt.Errorf("%w: IPv4 total length %d smaller than header length %d", ErrICMPQuoteInvalid, totalLen, ihl)
	}
	if len(quote) < 10 {
		q.MissingReason = "quote ends inside IPv4 header: protocol unavailable"
		return nil
	}
	q.Protocol = IPProtocol(quote[9])
	q.ProtocolStatus = ICMPQuoteFieldKnown
	if len(quote) < 20 {
		q.MissingReason = "quote ends inside IPv4 header: addresses unavailable"
		return nil
	}
	q.SrcIP = net.IP(append([]byte(nil), quote[12:16]...))
	q.DstIP = net.IP(append([]byte(nil), quote[16:20]...))
	q.AddressesStatus = ICMPQuoteFieldKnown
	if len(quote) < ihl {
		q.MissingReason = "quote ends inside IPv4 options: transport header unavailable"
		return nil
	}
	// A non-first fragment does not contain the transport header, so ports
	// and sequence numbers cannot be read from it.
	if fragOffset := binary.BigEndian.Uint16(quote[6:8]) & 0x1FFF; fragOffset != 0 {
		q.MissingReason = "non-first fragment: transport header not present"
		return nil
	}
	q.parseTransportQuote(q.Protocol, quote[ihl:])
	return nil
}

func (q *ICMPQuote) parseIPv6Quote(quote []byte) error {
	q.IPVersion = 6
	if len(quote) < 1 {
		q.MissingReason = "quote is empty"
		return nil
	}
	if version := quote[0] >> 4; version != 6 {
		return fmt.Errorf("%w: quoted packet has IP version %d, want 6", ErrICMPQuoteInvalid, version)
	}
	if len(quote) < 40 {
		q.MissingReason = "quote ends inside IPv6 header"
		return nil
	}
	q.SrcIP = net.IP(append([]byte(nil), quote[8:24]...))
	q.DstIP = net.IP(append([]byte(nil), quote[24:40]...))
	q.AddressesStatus = ICMPQuoteFieldKnown

	// Walk the extension header chain, but only across headers that are
	// fully present in the quote. If the quote ends halfway through an
	// extension header, stop and report what was already confirmed.
	next := IPProtocol(quote[6])
	offset := 40
	for {
		switch next {
		case IPProtocolIPv6HopByHop, IPProtocolIPv6Routing, IPProtocolIPv6Destination:
			hdrLen, ok := q.icmpQuoteIPv6ExtLen(quote, offset, 8, 1)
			if !ok {
				return nil
			}
			next = IPProtocol(quote[offset])
			offset += hdrLen
		case IPProtocolAH:
			// AH (RFC 4302) measures its length in 32-bit words minus 2.
			hdrLen, ok := q.icmpQuoteIPv6ExtLen(quote, offset, 4, 2)
			if !ok {
				return nil
			}
			next = IPProtocol(quote[offset])
			offset += hdrLen
		case IPProtocolIPv6Fragment:
			if len(quote)-offset < 8 {
				q.MissingReason = "quote ends inside IPv6 fragment header"
				return nil
			}
			fragOffset := binary.BigEndian.Uint16(quote[offset+2:offset+4]) >> 3
			next = IPProtocol(quote[offset])
			offset += 8
			if fragOffset != 0 {
				q.Protocol = next
				q.ProtocolStatus = ICMPQuoteFieldKnown
				q.MissingReason = "non-first fragment: transport header not present"
				return nil
			}
		case IPProtocolESP:
			// The upper layer is encrypted and therefore invisible.
			q.Protocol = IPProtocolESP
			q.ProtocolStatus = ICMPQuoteFieldKnown
			q.MissingReason = "ESP payload is encrypted: upper layer not visible"
			return nil
		case IPProtocolNoNextHeader:
			q.Protocol = IPProtocolNoNextHeader
			q.ProtocolStatus = ICMPQuoteFieldKnown
			q.MissingReason = "no next header"
			return nil
		default:
			q.Protocol = next
			q.ProtocolStatus = ICMPQuoteFieldKnown
			q.parseTransportQuote(next, quote[offset:])
			return nil
		}
	}
}

// icmpQuoteIPv6ExtLen returns the total length of a length-prefixed IPv6
// extension header at offset, computed as (quote[offset+1]+add)*unit. It
// reports false when the header is not fully contained in the quote, setting
// the missing reason on the way out.
func (q *ICMPQuote) icmpQuoteIPv6ExtLen(quote []byte, offset, unit, add int) (int, bool) {
	if len(quote)-offset < 2 {
		q.MissingReason = "quote ends inside IPv6 extension header"
		return 0, false
	}
	hdrLen := (int(quote[offset+1]) + add) * unit
	if len(quote)-offset < hdrLen {
		q.MissingReason = "quote ends inside IPv6 extension header"
		return 0, false
	}
	return hdrLen, true
}

// parseTransportQuote recovers ports and the TCP sequence number from the
// quoted transport header. Quoted ICMP messages are deliberately not parsed
// recursively.
func (q *ICMPQuote) parseTransportQuote(proto IPProtocol, data []byte) {
	switch proto {
	case IPProtocolTCP:
		if len(data) < 4 {
			q.MissingReason = "quote ends inside TCP header: ports unavailable"
			return
		}
		q.SrcPort = binary.BigEndian.Uint16(data[0:2])
		q.DstPort = binary.BigEndian.Uint16(data[2:4])
		q.PortsStatus = ICMPQuoteFieldKnown
		if len(data) < 8 {
			q.MissingReason = "quote ends inside TCP header: sequence number unavailable"
			return
		}
		q.TCPSeq = binary.BigEndian.Uint32(data[4:8])
		q.TCPSeqStatus = ICMPQuoteFieldKnown
	case IPProtocolUDP:
		if len(data) < 4 {
			q.MissingReason = "quote ends inside UDP header: ports unavailable"
			return
		}
		q.SrcPort = binary.BigEndian.Uint16(data[0:2])
		q.DstPort = binary.BigEndian.Uint16(data[2:4])
		q.PortsStatus = ICMPQuoteFieldKnown
	case IPProtocolICMPv4, IPProtocolICMPv6:
		q.MissingReason = "quoted ICMP message is not parsed recursively"
	default:
		q.MissingReason = fmt.Sprintf("protocol %s does not carry ports", proto)
	}
}
