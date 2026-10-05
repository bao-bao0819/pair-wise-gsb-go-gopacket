// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// ErrNgIndexGzip gets returned by NewNgIndex if the input starts with the gzip
// magic. Random access is only supported on uncompressed pcapng files.
var ErrNgIndexGzip = errors.New("pcapgo: NgIndex does not support gzip compressed input; decompress the file before indexing")

// ErrNgPacketNumber gets returned by the packet lookup methods of NgIndex if the
// requested packet number does not exist.
var ErrNgPacketNumber = errors.New("pcapgo: packet number out of range")

// NgCorruptBlockError is returned while building an NgIndex if a block cannot
// be parsed. Offset is the file offset of the beginning of the offending block
// (or, if the file ends in the middle of a block, the offset at which the
// truncated block starts).
type NgCorruptBlockError struct {
	Offset int64
	Err    error
}

func (e *NgCorruptBlockError) Error() string {
	return fmt.Sprintf("pcapgo: corrupt pcapng block at offset %d: %v", e.Offset, e.Err)
}

// Unwrap returns the underlying parse error.
func (e *NgCorruptBlockError) Unwrap() error {
	return e.Err
}

// NgIndexOptions holds options for building an NgIndex. The semantics mirror
// NgReaderOptions, except that only options relevant to packet lookup are
// exposed.
type NgIndexOptions struct {
	// WantMixedLinkType enables indexing a pcapng file containing multiple
	// interfaces with varying link types. If false all link types must match,
	// which is the libpcap behaviour.
	WantMixedLinkType bool
	// ErrorOnMismatchingLinkType enables returning an error if a packet with a
	// link type not matching the first interface is encountered and
	// WantMixedLinkType == false. If false those packets are just silently
	// skipped, which is the libpcap behaviour.
	ErrorOnMismatchingLinkType bool
	// SkipUnknownVersion enables automatically skipping sections with an
	// unknown version, which is recommended by the pcapng standard. Otherwise
	// ErrNgVersionMismatch is returned.
	SkipUnknownVersion bool
}

// ngIndexedInterface is an interface descriptor plus the timing
// precomputation state needed to interpret packet timestamps, as maintained by
// NgReader.
type ngIndexedInterface struct {
	iface      NgInterface
	secondMask uint64
	scaleUp    uint64
	scaleDown  uint64
}

// ngIndexedSection captures the context of one section needed to decode its
// packets. Interface ids are only unique within a section, so they must never
// be resolved across sections.
type ngIndexedSection struct {
	info      NgSectionInfo
	bigEndian bool
	skip      bool
	ifaces    []ngIndexedInterface
}

// ngPacketEntry is one indexed packet. Only the offset and the minimum context
// required to reconstruct data and gopacket.CaptureInfo are stored; packet
// payload is never cached.
type ngPacketEntry struct {
	offset     int64
	blockType  ngBlockType
	section    int
	ifaceID    int
	timestamp  time.Time
	hasTS      bool
	capLen     int
	origLen    int
	dataOffset int64
	dataLen    int
	optsOffset int64
	optsLen    int
	mixedLink  layers.LinkType
}

// NgIndex is a read-only, stateless random access index over an uncompressed
// pcapng file. All lookups operate on the io.ReaderAt passed to NewNgIndex and
// do not share a mutable file cursor: queries may be interleaved freely, even
// concurrently.
type NgIndex struct {
	r            io.ReaderAt
	size         int64
	options      NgIndexOptions
	sections     []ngIndexedSection
	linkType     layers.LinkType
	firstLinkSet bool
	packets      []ngPacketEntry
}

// DefaultNgIndexOptions provides sane defaults for building an NgIndex.
var DefaultNgIndexOptions = NgIndexOptions{}

// NewNgIndex builds a read-only index of the uncompressed pcapng data readable
// from r. size is the length of the file in bytes, which is required to bound
// block parsing. The whole file is scanned once while building the index, but
// packet payload is not retained.
//
// Gzip compressed input is rejected with ErrNgIndexGzip. Parse errors are
// returned wrapped in *NgCorruptBlockError, carrying the file offset of the
// offending block; a half-parsed block is never registered as a packet.
func NewNgIndex(r io.ReaderAt, size int64, options NgIndexOptions) (*NgIndex, error) {
	if size < 0 {
		return nil, errors.New("pcapgo: negative size passed to NewNgIndex")
	}
	idx := &NgIndex{
		r:       r,
		size:    size,
		options: options,
	}

	magic := make([]byte, 2)
	n, err := r.ReadAt(magic, 0)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	if n >= 2 && magic[0] == magicGzip1 && magic[1] == magicGzip2 {
		return nil, ErrNgIndexGzip
	}
	if size == 0 {
		return nil, io.EOF
	}

	if err := idx.build(); err != nil {
		return nil, err
	}
	return idx, nil
}

// readFullAt reads exactly len(buf) bytes at offset. A short read is reported as
// io.ErrUnexpectedEOF.
func (idx *NgIndex) readFullAt(buf []byte, offset int64) error {
	n, err := idx.r.ReadAt(buf, offset)
	if err == io.EOF && n == len(buf) {
		return nil
	}
	if err != nil {
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if n != len(buf) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (idx *NgIndex) corrupt(offset int64, format string, args ...interface{}) error {
	return &NgCorruptBlockError{
		Offset: offset,
		Err:    fmt.Errorf(format, args...),
	}
}

// ngConvertTime mirrors NgReader.convertTime: it adds the interface timestamp
// offset and scales the timestamp to nanosecond precision.
func ngConvertTime(iface ngIndexedInterface, ts uint64) (int64, int64) {
	return int64(ts/iface.secondMask + iface.iface.TimestampOffset),
		int64(ts % iface.secondMask * iface.scaleUp / iface.scaleDown)
}

// build scans the whole file section by section and registers every packet
// that NgReader would return.
func (idx *NgIndex) build() error {
	var offset int64
	var section *ngIndexedSection
	var order binary.ByteOrder = binary.LittleEndian

	for offset < idx.size {
		blockOffset := offset
		if idx.size-offset < 8 {
			return idx.corrupt(blockOffset, "truncated block header: only %d bytes left", idx.size-offset)
		}

		header := make([]byte, 12)
		if err := idx.readFullAt(header[:8], blockOffset); err != nil {
			return idx.corrupt(blockOffset, "could not read block header: %v", err)
		}

		typ := ngBlockType(order.Uint32(header[0:4]))

		if typ == ngBlockTypeSectionHeader {
			// Determine the byte order from the byte order magic, which sits
			// right after the block type and block length fields.
			if err := idx.readFullAt(header[8:12], blockOffset+8); err != nil {
				return idx.corrupt(blockOffset, "could not read section byte order magic: %v", err)
			}
			switch {
			case binary.BigEndian.Uint32(header[8:12]) == ngByteOrderMagic:
				order = binary.BigEndian
			case binary.LittleEndian.Uint32(header[8:12]) == ngByteOrderMagic:
				order = binary.LittleEndian
			default:
				return idx.corrupt(blockOffset, "wrong byte order value in Section Header")
			}
		} else if section == nil {
			return idx.corrupt(blockOffset, "pcapng file must start with a Section Header Block")
		}

		totalLen := order.Uint32(header[4:8])
		if totalLen < 12 || totalLen%4 != 0 {
			return idx.corrupt(blockOffset, "invalid block length %d", totalLen)
		}
		if int64(totalLen) > idx.size-blockOffset {
			return idx.corrupt(blockOffset, "block length %d exceeds file size", totalLen)
		}

		body := make([]byte, totalLen)
		if err := idx.readFullAt(body, blockOffset); err != nil {
			return idx.corrupt(blockOffset, "could not read block body: %v", err)
		}

		if typ == ngBlockTypeSectionHeader {
			newSection := ngIndexedSection{bigEndian: order == binary.BigEndian}
			skip, err := idx.parseSectionHeader(body, blockOffset, &newSection)
			if err != nil {
				return err
			}
			newSection.skip = skip
			idx.sections = append(idx.sections, newSection)
			section = &idx.sections[len(idx.sections)-1]
		} else if !section.skip {
			if err := idx.parseBlock(body, blockOffset, len(idx.sections)-1, section, order); err != nil {
				return err
			}
		}

		// Every block repeats its total length at the end.
		if trailer := order.Uint32(body[totalLen-4 : totalLen]); trailer != totalLen {
			return idx.corrupt(blockOffset, "trailing block length %d does not match leading length %d", trailer, totalLen)
		}

		offset = blockOffset + int64(totalLen)
	}

	return nil
}

// scanOptions iterates over the TLV options inside a block body. body spans the
// whole block (indexed from the start of the block), start is the offset of the
// first option, and remaining is the number of bytes from start up to (but not
// including) the trailing total block length. The callback receives the option
// code and its unpadded value.
//
// It mirrors the tolerance of NgReader.readOption: if no end-of-options option
// terminates the area exactly at its end, termination is assumed.
func scanOptions(body []byte, start int, remaining int, order binary.ByteOrder, blockOffset int64, cb func(code ngOptionCode, value []byte) error) error {
	off := start
	for remaining > 0 {
		if remaining == 4 {
			return nil
		}
		if remaining < 4 {
			return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("truncated option header")}
		}
		code := ngOptionCode(order.Uint16(body[off : off+2]))
		length := int(order.Uint16(body[off+2 : off+4]))
		valueStart := off + 4
		padded := (length + 3) &^ 3
		if 4+padded > remaining {
			return &NgCorruptBlockError{Offset: blockOffset, Err: fmt.Errorf("option code %d value length %d exceeds block", code, length)}
		}
		if code == ngOptionCodeEndOfOptions {
			if length != 0 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("end of options must be zero length")}
			}
			return nil
		}
		if cb != nil {
			if err := cb(code, body[valueStart:valueStart+length]); err != nil {
				return err
			}
		}
		off += 4 + padded
		remaining -= 4 + padded
	}
	return nil
}

// parseSectionHeader parses a Section Header Block. It returns skip=true if the
// section uses an unsupported version and skipping was requested.
func (idx *NgIndex) parseSectionHeader(body []byte, blockOffset int64, section *ngIndexedSection) (bool, error) {
	const fixedPart = 28 // type(4) length(4) magic(4) version(4) section length(8) + trailer(4)
	if len(body) < fixedPart {
		return false, idx.corrupt(blockOffset, "Section Header Block too short: %d bytes", len(body))
	}
	var order binary.ByteOrder = binary.BigEndian
	if !section.bigEndian {
		order = binary.LittleEndian
	}

	major := order.Uint16(body[12:14])
	minor := order.Uint16(body[14:16])
	if major != ngVersionMajor || minor != ngVersionMinor {
		if !idx.options.SkipUnknownVersion {
			return false, &NgCorruptBlockError{Offset: blockOffset, Err: ErrNgVersionMismatch}
		}
		return true, nil
	}

	var info NgSectionInfo
	err := scanOptions(body, 24, len(body)-4-24, order, blockOffset, func(code ngOptionCode, value []byte) error {
		switch code {
		case ngOptionCodeComment:
			info.Comment = string(value)
		case ngOptionCodeHardware:
			info.Hardware = string(value)
		case ngOptionCodeOS:
			info.OS = string(value)
		case ngOptionCodeUserApplication:
			info.Application = string(value)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	section.info = info
	return false, nil
}

// parseBlock dispatches one non-section block of an active section.
func (idx *NgIndex) parseBlock(body []byte, blockOffset int64, sectionNum int, section *ngIndexedSection, order binary.ByteOrder) error {
	typ := ngBlockType(order.Uint32(body[0:4]))
	switch typ {
	case ngBlockTypeInterfaceDescriptor:
		return idx.parseInterfaceDescriptor(body, blockOffset, section, order)
	case ngBlockTypeEnhancedPacket:
		return idx.parseEnhancedPacket(body, blockOffset, sectionNum, section, order)
	case ngBlockTypePacket:
		return idx.parsePacketBlock(body, blockOffset, sectionNum, section, order)
	case ngBlockTypeSimplePacket:
		return idx.parseSimplePacket(body, blockOffset, sectionNum, section, order)
	case ngBlockTypeInterfaceStatistics:
		// Statistics do not produce packets, but an unknown interface id is
		// structural corruption, exactly as for NgReader.
		if len(body) < 24 {
			return idx.corrupt(blockOffset, "Interface Statistics Block too short: %d bytes", len(body))
		}
		ifaceID := int(order.Uint32(body[8:12]))
		if ifaceID >= len(section.ifaces) {
			return idx.corrupt(blockOffset, "interface id %d not present in section (have only %d interfaces)", ifaceID, len(section.ifaces))
		}
		return scanOptions(body, 20, len(body)-4-20, order, blockOffset, nil)
	default:
		// Name Resolution, Decryption Secrets and unknown blocks carry no
		// packets; the trailing length is validated by the caller.
		return nil
	}
}

// parseInterfaceDescriptor parses an Interface Description Block and appends
// the interface (with precomputed timing factors) to the current section.
func (idx *NgIndex) parseInterfaceDescriptor(body []byte, blockOffset int64, section *ngIndexedSection, order binary.ByteOrder) error {
	const fixedPart = 20 // header(8) linktype(2) reserved(2) snaplen(4) + trailer(4)
	if len(body) < fixedPart {
		return idx.corrupt(blockOffset, "Interface Description Block too short: %d bytes", len(body))
	}

	var intf ngIndexedInterface
	intf.iface.LinkType = layers.LinkType(order.Uint16(body[8:10]))
	intf.iface.SnapLength = order.Uint32(body[12:16])

	err := scanOptions(body, 16, len(body)-4-16, order, blockOffset, func(code ngOptionCode, value []byte) error {
		switch code {
		case ngOptionCodeInterfaceName:
			intf.iface.Name = string(value)
		case ngOptionCodeComment:
			intf.iface.Comment = string(value)
		case ngOptionCodeInterfaceDescription:
			intf.iface.Description = string(value)
		case ngOptionCodeInterfaceFilter:
			// ignore filter type (first byte) since it is not specified
			if len(value) < 1 {
				return idx.corrupt(blockOffset, "interface filter option is empty")
			}
			intf.iface.Filter = string(value[1:])
		case ngOptionCodeInterfaceOS:
			intf.iface.OS = string(value)
		case ngOptionCodeInterfaceTimestampOffset:
			if len(value) < 8 {
				return idx.corrupt(blockOffset, "timestamp offset option must be 8 bytes, got %d", len(value))
			}
			intf.iface.TimestampOffset = order.Uint64(value[:8])
		case ngOptionCodeInterfaceTimestampResolution:
			if len(value) < 1 {
				return idx.corrupt(blockOffset, "timestamp resolution option is empty")
			}
			intf.iface.TimestampResolution = NgResolution(value[0])
		}
		return nil
	})
	if err != nil {
		return err
	}

	if intf.iface.TimestampResolution == 0 {
		intf.iface.TimestampResolution = 6
	}

	res := intf.iface.TimestampResolution
	if res.Binary() {
		intf.secondMask = 1 << int(res.Exponent())
	} else {
		intf.secondMask = 1
		for j := uint8(0); j < res.Exponent(); j++ {
			intf.secondMask *= 10
		}
	}
	intf.scaleUp = 1
	intf.scaleDown = 1
	if intf.secondMask < 1e9 {
		intf.scaleUp = 1e9 / intf.secondMask
	} else {
		intf.scaleDown = intf.secondMask / 1e9
	}

	section.ifaces = append(section.ifaces, intf)
	if !idx.firstLinkSet {
		idx.linkType = intf.iface.LinkType
		idx.firstLinkSet = true
	}
	return nil
}

// registerPacket validates a packet against its interface and the configured
// link type policy, and appends it to the index. It is only called once the
// whole block has been verified structurally, so a corrupt block never leaves a
// half-parsed entry behind.
func (idx *NgIndex) registerPacket(entry ngPacketEntry, section *ngIndexedSection) error {
	iface := section.ifaces[entry.ifaceID]

	if !idx.options.WantMixedLinkType {
		if iface.iface.LinkType != idx.linkType {
			if idx.options.ErrorOnMismatchingLinkType {
				return &NgCorruptBlockError{Offset: entry.offset, Err: ErrNgLinkTypeMismatch}
			}
			return nil
		}
	} else {
		entry.mixedLink = iface.iface.LinkType
	}

	idx.packets = append(idx.packets, entry)
	return nil
}

// parseEnhancedPacket parses an Enhanced Packet Block (type 6).
func (idx *NgIndex) parseEnhancedPacket(body []byte, blockOffset int64, sectionNum int, section *ngIndexedSection, order binary.ByteOrder) error {
	const (
		fixedHeader = 28 // block header (8) + EPB fields (20)
		trailer     = 4
	)
	if len(body) < fixedHeader+trailer {
		return idx.corrupt(blockOffset, "Enhanced Packet Block too short: %d bytes", len(body))
	}

	ifaceID := int(order.Uint32(body[8:12]))
	if ifaceID >= len(section.ifaces) {
		return idx.corrupt(blockOffset, "interface id %d not present in section (have only %d interfaces)", ifaceID, len(section.ifaces))
	}
	iface := section.ifaces[ifaceID]

	tsHigh := order.Uint32(body[12:16])
	tsLow := order.Uint32(body[16:20])
	capLen := int(order.Uint32(body[20:24]))
	origLen := int(order.Uint32(body[24:28]))

	paddedCap := (capLen + 3) &^ 3
	dataEnd := fixedHeader + paddedCap
	// Options occupy everything between the padded packet data and the trailer.
	if dataEnd > len(body)-trailer {
		return idx.corrupt(blockOffset, "captured packet length %d does not fit block of %d bytes", capLen, len(body))
	}
	// Validate the options area structurally; options are decoded lazily when
	// the packet is actually read.
	if err := scanOptions(body, dataEnd, len(body)-trailer-dataEnd, order, blockOffset, nil); err != nil {
		return err
	}

	tsRaw := uint64(tsHigh)<<32 | uint64(tsLow)
	secs, nanos := ngConvertTime(iface, tsRaw)

	entry := ngPacketEntry{
		offset:     blockOffset,
		blockType:  ngBlockTypeEnhancedPacket,
		section:    sectionNum,
		ifaceID:    ifaceID,
		timestamp:  time.Unix(secs, nanos).UTC(),
		hasTS:      true,
		capLen:     capLen,
		origLen:    origLen,
		dataOffset: blockOffset + fixedHeader,
		dataLen:    capLen,
		optsOffset: blockOffset + int64(dataEnd),
		optsLen:    len(body) - trailer - dataEnd,
	}
	return idx.registerPacket(entry, section)
}

// parsePacketBlock parses the deprecated Packet Block (type 2).
func (idx *NgIndex) parsePacketBlock(body []byte, blockOffset int64, sectionNum int, section *ngIndexedSection, order binary.ByteOrder) error {
	const (
		fixedHeader = 28 // block header (8) + packet fields (20)
		trailer     = 4
	)
	if len(body) < fixedHeader+trailer {
		return idx.corrupt(blockOffset, "Packet Block too short: %d bytes", len(body))
	}

	// Field offsets mirror NgReader.readPacketHeader exactly: after the 8 byte
	// block header it consumes 20 bytes and reads interface id at [0:2],
	// timestamp at [4:12], captured length at [12:16] and original length at
	// [16:20]. Two bytes (drop count) are part of the block but ignored, and
	// packet data therefore starts at block offset 28.
	ifaceID := int(order.Uint16(body[8:10]))
	if ifaceID >= len(section.ifaces) {
		return idx.corrupt(blockOffset, "interface id %d not present in section (have only %d interfaces)", ifaceID, len(section.ifaces))
	}
	iface := section.ifaces[ifaceID]

	tsHigh := order.Uint32(body[12:16])
	tsLow := order.Uint32(body[16:20])
	capLen := int(order.Uint32(body[20:24]))
	origLen := int(order.Uint32(body[24:28]))

	paddedCap := (capLen + 3) &^ 3
	dataEnd := fixedHeader + paddedCap
	if dataEnd > len(body)-trailer {
		return idx.corrupt(blockOffset, "captured packet length %d does not fit block of %d bytes", capLen, len(body))
	}
	// NgReader discards the remainder of a legacy Packet Block without parsing
	// its options, so the index does not validate them either.

	tsRaw := uint64(tsHigh)<<32 | uint64(tsLow)
	secs, nanos := ngConvertTime(iface, tsRaw)

	entry := ngPacketEntry{
		offset:     blockOffset,
		blockType:  ngBlockTypePacket,
		section:    sectionNum,
		ifaceID:    ifaceID,
		timestamp:  time.Unix(secs, nanos).UTC(),
		hasTS:      true,
		capLen:     capLen,
		origLen:    origLen,
		dataOffset: blockOffset + fixedHeader,
		dataLen:    capLen,
	}
	return idx.registerPacket(entry, section)
}

// parseSimplePacket parses a Simple Packet Block (type 3). Simple packets carry
// no timestamp, so they only participate in packet-number lookups.
func (idx *NgIndex) parseSimplePacket(body []byte, blockOffset int64, sectionNum int, section *ngIndexedSection, order binary.ByteOrder) error {
	const (
		fixedPart = 16 // block header (8) + original length (4) + trailer (4)
		dataStart = 12
		trailer   = 4
	)
	if len(body) < fixedPart {
		return idx.corrupt(blockOffset, "Simple Packet Block too short: %d bytes", len(body))
	}
	if len(section.ifaces) == 0 {
		return idx.corrupt(blockOffset, "at least one interface is needed for a Simple Packet Block")
	}

	origLen := int(order.Uint32(body[8:12]))
	capLen := origLen
	if snap := section.ifaces[0].iface.SnapLength; snap != 0 && uint32(capLen) > snap {
		capLen = int(snap)
	}
	paddedCap := (capLen + 3) &^ 3
	dataEnd := dataStart + paddedCap
	if dataEnd > len(body)-trailer {
		return idx.corrupt(blockOffset, "simple packet length %d does not fit block of %d bytes", capLen, len(body))
	}

	entry := ngPacketEntry{
		offset:     blockOffset,
		blockType:  ngBlockTypeSimplePacket,
		section:    sectionNum,
		ifaceID:    0,
		timestamp:  time.Time{},
		hasTS:      false,
		capLen:     capLen,
		origLen:    origLen,
		dataOffset: blockOffset + dataStart,
		dataLen:    capLen,
	}
	return idx.registerPacket(entry, section)
}

// Len returns the number of indexed packets, in file order. Packets skipped due
// to the link type policy are not counted.
func (idx *NgIndex) Len() int {
	return len(idx.packets)
}

// NumSections returns the number of sections in the file, including sections
// skipped because of an unsupported version.
func (idx *NgIndex) NumSections() int {
	return len(idx.sections)
}

// LinkType returns the link type of the first interface of the first section,
// as layers.LinkType. This is only valid if NgIndexOptions.WantMixedLinkType is
// false, mirroring NgReader.LinkType.
func (idx *NgIndex) LinkType() layers.LinkType {
	return idx.linkType
}

// SectionInfo returns information about the section with the given number.
func (idx *NgIndex) SectionInfo(section int) (NgSectionInfo, error) {
	if section < 0 || section >= len(idx.sections) {
		return NgSectionInfo{}, fmt.Errorf("section %d invalid; there are only %d sections", section, len(idx.sections))
	}
	return idx.sections[section].info, nil
}

// NInterfaces returns the number of interfaces of the section with the given
// number.
func (idx *NgIndex) NInterfaces(section int) int {
	if section < 0 || section >= len(idx.sections) {
		return 0
	}
	return len(idx.sections[section].ifaces)
}

// Interface returns the interface with the given id inside the given section.
// Interface ids are scoped to a section and must not be treated as file-wide
// unique identifiers.
func (idx *NgIndex) Interface(section, id int) (NgInterface, error) {
	if section < 0 || section >= len(idx.sections) {
		return NgInterface{}, fmt.Errorf("section %d invalid; there are only %d sections", section, len(idx.sections))
	}
	ifaces := idx.sections[section].ifaces
	if id < 0 || id >= len(ifaces) {
		return NgInterface{}, fmt.Errorf("interface %d invalid in section %d; there are only %d interfaces", id, section, len(ifaces))
	}
	return ifaces[id].iface, nil
}

// PacketNumbersBetween returns the numbers (file-order positions, starting at
// 0) of packets whose timestamp lies in the half-open interval [start, end).
// Timestamps are compared in file order and must not be monotonic; the result
// is always returned in file order.
//
// The zero value for start or end denotes no lower respectively upper bound.
// Simple Packet Blocks have no timestamp and are never returned. An interval
// that does not match anything returns an empty (non-nil) slice.
func (idx *NgIndex) PacketNumbersBetween(start, end time.Time) []int {
	numbers := make([]int, 0)
	for i := range idx.packets {
		pkt := &idx.packets[i]
		if !pkt.hasTS {
			continue
		}
		if !start.IsZero() && pkt.timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && !pkt.timestamp.Before(end) {
			continue
		}
		numbers = append(numbers, i)
	}
	return numbers
}

// NgPacketRef locates one packet in the indexed file and carries the section
// context needed to interpret it.
type NgPacketRef struct {
	number  int
	offset  int64
	section int
	ifaceID int
}

// Number returns the file-order packet number, starting at 0.
func (ref NgPacketRef) Number() int { return ref.number }

// Offset returns the file offset of the start of the packet block.
func (ref NgPacketRef) Offset() int64 { return ref.offset }

// Section returns the number of the section the packet belongs to.
func (ref NgPacketRef) Section() int { return ref.section }

// InterfaceID returns the interface id of the packet, scoped to its section.
func (ref NgPacketRef) InterfaceID() int { return ref.ifaceID }

// Ref returns the reference for packet number n. Packet numbers are the
// file-order positions reported by Len and PacketNumbersBetween.
func (idx *NgIndex) Ref(n int) (NgPacketRef, error) {
	if n < 0 || n >= len(idx.packets) {
		return NgPacketRef{}, ErrNgPacketNumber
	}
	pkt := &idx.packets[n]
	return NgPacketRef{number: n, offset: pkt.offset, section: pkt.section, ifaceID: pkt.ifaceID}, nil
}

// captureInfo builds the gopacket.CaptureInfo of a packet, matching the values
// produced by NgReader.ReadPacketData.
func (idx *NgIndex) captureInfo(pkt *ngPacketEntry) gopacket.CaptureInfo {
	ci := gopacket.CaptureInfo{
		Timestamp:      pkt.timestamp,
		CaptureLength:  pkt.capLen,
		Length:         pkt.origLen,
		InterfaceIndex: pkt.ifaceID,
	}
	if idx.options.WantMixedLinkType {
		ci.AncillaryData = []interface{}{pkt.mixedLink}
	}
	return ci
}

// readPacketByNumber reads the payload of packet number n and returns it
// together with its CaptureInfo. It touches only the bytes of that packet's
// block and keeps no state between calls.
func (idx *NgIndex) readPacketByNumber(n int) (data []byte, ci gopacket.CaptureInfo, opts NgPacketOptions, err error) {
	if n < 0 || n >= len(idx.packets) {
		return nil, gopacket.CaptureInfo{}, NgPacketOptions{}, ErrNgPacketNumber
	}
	pkt := &idx.packets[n]

	data = make([]byte, pkt.dataLen)
	if rerr := idx.readFullAt(data, pkt.dataOffset); rerr != nil {
		return nil, gopacket.CaptureInfo{}, NgPacketOptions{}, idx.corrupt(pkt.offset, "could not read packet data: %v", rerr)
	}

	if pkt.blockType == ngBlockTypeEnhancedPacket {
		rawOpts := make([]byte, pkt.optsLen)
		if rerr := idx.readFullAt(rawOpts, pkt.optsOffset); rerr != nil {
			return nil, gopacket.CaptureInfo{}, NgPacketOptions{}, idx.corrupt(pkt.offset, "could not read packet options: %v", rerr)
		}
		section := &idx.sections[pkt.section]
		var order binary.ByteOrder = binary.LittleEndian
		if section.bigEndian {
			order = binary.BigEndian
		}
		opts, err = parseNgPacketOptions(rawOpts, order, pkt.offset)
		if err != nil {
			return nil, gopacket.CaptureInfo{}, NgPacketOptions{}, err
		}
	}

	return data, idx.captureInfo(pkt), opts, nil
}

// ReadPacketData returns the payload and CaptureInfo of packet number n, using
// the same semantics as NgReader.ReadPacketData.
func (idx *NgIndex) ReadPacketData(n int) (data []byte, ci gopacket.CaptureInfo, err error) {
	data, ci, _, err = idx.readPacketByNumber(n)
	return
}

// ReadPacketDataWithOptions is ReadPacketData and additionally returns the
// Enhanced Packet Block options, mirroring
// NgReader.ReadPacketDataWithOptions.
func (idx *NgIndex) ReadPacketDataWithOptions(n int) (data []byte, ci gopacket.CaptureInfo, opts NgPacketOptions, err error) {
	return idx.readPacketByNumber(n)
}

// ReadPacketDataAt is a convenience wrapper around ReadPacketData for a
// reference returned by Ref or PacketNumbersBetween.
func (idx *NgIndex) ReadPacketDataAt(ref NgPacketRef) (data []byte, ci gopacket.CaptureInfo, err error) {
	return idx.ReadPacketData(ref.number)
}

// parseNgPacketOptions decodes the options area of an Enhanced Packet Block.
// The flags word is, as in NgReader, always interpreted as little endian.
func parseNgPacketOptions(raw []byte, order binary.ByteOrder, blockOffset int64) (NgPacketOptions, error) {
	ret := NgPacketOptions{}
	err := scanOptions(raw, 0, len(raw), order, blockOffset, func(code ngOptionCode, value []byte) error {
		switch code {
		case ngOptionCodeComment:
			ret.Comments = append(ret.Comments, string(value))
		case ngOptionCodeEpbFlags:
			if len(value) < 4 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB flags option must be 4 bytes")}
			}
			flags := NgEpbFlags{}
			flags.FromUint32(binary.LittleEndian.Uint32(value))
			ret.Flags = &flags
		case ngOptionCodeEpbHash:
			if len(value) < 1 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB hash option is empty")}
			}
			hash := make([]byte, len(value)-1)
			copy(hash, value[1:])
			ret.Hashes = append(ret.Hashes, NgEpbHash{
				Algorithm: NgEpbHashAlgorithm(value[0]),
				Hash:      hash,
			})
		case ngOptionCodeEpbDropCount:
			if len(value) < 8 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB drop count option must be 8 bytes")}
			}
			v := binary.LittleEndian.Uint64(value)
			ret.DropCount = &v
		case ngOptionCodeEpbPacketID:
			if len(value) < 8 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB packet id option must be 8 bytes")}
			}
			v := binary.LittleEndian.Uint64(value)
			ret.PacketID = &v
		case ngOptionCodeEpbQueue:
			if len(value) < 4 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB queue option must be 4 bytes")}
			}
			v := binary.LittleEndian.Uint32(value)
			ret.Queue = &v
		case ngOptionCodeEpbVerdict:
			if len(value) < 1 {
				return &NgCorruptBlockError{Offset: blockOffset, Err: errors.New("EPB verdict option is empty")}
			}
			verdictData := make([]byte, len(value)-1)
			copy(verdictData, value[1:])
			ret.Verdicts = append(ret.Verdicts, NgEpbVerdict{
				Type: NgEpbVerdictType(value[0]),
				Data: verdictData,
			})
		}
		return nil
	})
	if err != nil {
		return NgPacketOptions{}, err
	}
	return ret, nil
}
