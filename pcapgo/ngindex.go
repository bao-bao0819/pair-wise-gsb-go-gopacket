package pcapgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	// ErrNgIndexCompressed is returned by NewNgIndex when the input starts with gzip magic bytes.
	ErrNgIndexCompressed = errors.New("pcapgo: compressed pcapng is not supported by NgIndex")
	errNgIndexLocation   = errors.New("pcapgo: packet location does not belong to this index")
)

// NgIndexError identifies an invalid pcapng block and the file offset where it starts.
type NgIndexError struct {
	Offset int64
	Err    error
}

func (e *NgIndexError) Error() string {
	return fmt.Sprintf("pcapgo: invalid pcapng block at offset %d: %v", e.Offset, e.Err)
}

func (e *NgIndexError) Unwrap() error {
	return e.Err
}

// NgIndex is a read-only index of packet blocks in an uncompressed pcapng file.
//
// The index stores block offsets and the section/interface context required to
// decode each packet. It never stores packet payloads.
type NgIndex struct {
	r        io.ReaderAt
	size     int64
	options  NgReaderOptions
	sections []*ngIndexSection
	packets  []NgPacketLocation
}

type ngIndexSection struct {
	bigEndian bool
	ifaces    []NgInterface
}

// NgPacketLocation identifies one packet and the section-local context in effect for it.
type NgPacketLocation struct {
	// Number is the zero-based packet number in file order.
	Number int
	// Section is the zero-based section number in file order.
	Section int
	// Interface is the interface ID local to Section.
	Interface int
	// Offset is the absolute offset of the packet block.
	Offset int64
	// DataOffset is the absolute offset where captured packet data starts.
	DataOffset int64
	// CaptureInfo contains the same metadata that NgReader returns for this packet.
	CaptureInfo gopacket.CaptureInfo
	// HasTimestamp is false for Simple Packet Blocks.
	HasTimestamp bool

	section *ngIndexSection
}

// BigEndian reports whether the section containing this packet uses big-endian block fields.
func (p NgPacketLocation) BigEndian() bool {
	return p.section != nil && p.section.bigEndian
}

// Timestamp reports whether the packet has a capture timestamp. Simple Packet Blocks do not.
func (p NgPacketLocation) Timestamp() (time.Time, bool) {
	return p.CaptureInfo.Timestamp, p.HasTimestamp
}

// NewNgIndex builds an index with default reader options.
func NewNgIndex(r io.ReaderAt, size int64) (*NgIndex, error) {
	return NewNgIndexOptions(r, size, DefaultNgReaderOptions)
}

// NewNgIndexOptions builds an index using the supplied reader options.
func NewNgIndexOptions(r io.ReaderAt, size int64, options NgReaderOptions) (*NgIndex, error) {
	if r == nil {
		return nil, errors.New("pcapgo: nil ReaderAt")
	}
	if size < 0 {
		return nil, fmt.Errorf("pcapgo: negative pcapng size %d", size)
	}

	var magic [2]byte
	if err := ngReadFullAt(r, magic[:], 0, size); err != nil {
		return nil, err
	}
	if magic[0] == magicGzip1 && magic[1] == magicGzip2 {
		return nil, ErrNgIndexCompressed
	}

	idx := &NgIndex{r: r, size: size, options: options}
	if err := idx.build(); err != nil {
		return nil, err
	}
	return idx, nil
}

func ngReadFullAt(r io.ReaderAt, buf []byte, off, size int64) error {
	if off < 0 || off > size {
		return &NgIndexError{Offset: off, Err: errors.New("offset outside file")}
	}
	if int64(len(buf)) > size-off {
		return &NgIndexError{Offset: off, Err: io.ErrUnexpectedEOF}
	}
	for len(buf) > 0 {
		n, err := r.ReadAt(buf, off)
		if n > 0 {
			buf = buf[n:]
			off += int64(n)
		}
		if err != nil {
			if err == io.EOF && len(buf) == 0 {
				return nil
			}
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return &NgIndexError{Offset: off, Err: err}
		}
		if n == 0 {
			return &NgIndexError{Offset: off, Err: io.ErrNoProgress}
		}
	}
	return nil
}

func (x *NgIndex) build() error {
	var order binary.ByteOrder = binary.LittleEndian
	var section *ngIndexSection
	var firstLinkType layers.LinkType
	foundCompatibleInterface := false
	sectionBigEndian := false
	skippingUnknownSection := false
	sectionNumber := -1

	for off := int64(0); off < x.size; {
		var header [16]byte
		if err := ngReadFullAt(x.r, header[:], off, x.size); err != nil {
			return err
		}

		typ := ngBlockType(order.Uint32(header[0:4]))
		if typ != ngBlockTypeSectionHeader && ngBlockType(binary.LittleEndian.Uint32(header[0:4])) == ngBlockTypeSectionHeader {
			typ = ngBlockTypeSectionHeader
		}
		if typ == ngBlockTypeSectionHeader {
			switch header[8] {
			case 0x1a:
				order = binary.BigEndian
				sectionBigEndian = true
			case 0x4d:
				order = binary.LittleEndian
				sectionBigEndian = false
			default:
				return &NgIndexError{Offset: off, Err: errors.New("wrong byte order value in Section Header")}
			}
		}

		blockLen := int64(order.Uint32(header[4:8]))
		if blockLen < 12 {
			return &NgIndexError{Offset: off, Err: fmt.Errorf("invalid block length %d", blockLen)}
		}
		if blockLen%4 != 0 {
			return &NgIndexError{Offset: off, Err: fmt.Errorf("block length %d is not 32-bit aligned", blockLen)}
		}
		if blockLen > math.MaxInt64-off {
			return &NgIndexError{Offset: off, Err: fmt.Errorf("block length %d overflows file offset", blockLen)}
		}
		end := off + blockLen
		if end > x.size {
			return &NgIndexError{Offset: off, Err: fmt.Errorf("block length %d extends beyond file", blockLen)}
		}

		var trailer [4]byte
		if err := ngReadFullAt(x.r, trailer[:], end-4, x.size); err != nil {
			return err
		}
		if order.Uint32(trailer[:]) != uint32(blockLen) {
			return &NgIndexError{Offset: off, Err: errors.New("block trailer length does not match header")}
		}
		if skippingUnknownSection && typ != ngBlockTypeSectionHeader {
			off = end
			continue
		}

		switch typ {
		case ngBlockTypeSectionHeader:
			if blockLen < 28 {
				return &NgIndexError{Offset: off, Err: fmt.Errorf("section header block is too short: %d bytes", blockLen)}
			}
			major := order.Uint16(header[12:14])
			minor := order.Uint16(header[14:16])
			if major != ngVersionMajor || minor != ngVersionMinor {
				if !x.options.SkipUnknownVersion {
					return &NgIndexError{Offset: off, Err: ErrNgVersionMismatch}
				}
				section = nil
				sectionNumber = -1
				foundCompatibleInterface = false
				skippingUnknownSection = true
				off = end
				continue
			}
			section = &ngIndexSection{bigEndian: sectionBigEndian}
			x.sections = append(x.sections, section)
			sectionNumber = len(x.sections) - 1
			foundCompatibleInterface = x.options.WantMixedLinkType
			skippingUnknownSection = false

		case ngBlockTypeInterfaceDescriptor:
			if section == nil {
				return &NgIndexError{Offset: off, Err: errors.New("interface descriptor outside a pcapng section")}
			}
			if blockLen < 20 {
				return &NgIndexError{Offset: off, Err: fmt.Errorf("interface descriptor block is too short: %d bytes", blockLen)}
			}
			intf, err := x.readInterfaceDescriptor(off, blockLen, order)
			if err != nil {
				return err
			}
			if !x.options.WantMixedLinkType {
				if len(x.sections) == 1 && len(section.ifaces) == 0 {
					firstLinkType = intf.LinkType
					foundCompatibleInterface = true
				} else if !foundCompatibleInterface && intf.LinkType == firstLinkType {
					foundCompatibleInterface = true
				}
			}
			section.ifaces = append(section.ifaces, intf)

		case ngBlockTypeEnhancedPacket, ngBlockTypePacket:
			if section == nil {
				return &NgIndexError{Offset: off, Err: errors.New("packet outside a pcapng section")}
			}
			if !foundCompatibleInterface {
				return &NgIndexError{Offset: off, Err: errors.New("a section must have an interface before a packet block")}
			}
			if err := x.indexPacketBlock(off, blockLen, order, section, sectionNumber, firstLinkType, typ); err != nil {
				return err
			}

		case ngBlockTypeSimplePacket:
			if section == nil {
				return &NgIndexError{Offset: off, Err: errors.New("simple packet outside a pcapng section")}
			}
			if !foundCompatibleInterface || len(section.ifaces) == 0 {
				return &NgIndexError{Offset: off, Err: errors.New("at least one interface is needed for a simple packet block")}
			}
			if err := x.indexSimplePacket(off, blockLen, order, section, sectionNumber, firstLinkType); err != nil {
				return err
			}

		case ngBlockTypeInterfaceStatistics:
			if section == nil {
				return &NgIndexError{Offset: off, Err: errors.New("interface statistics outside a pcapng section")}
			}
			if !foundCompatibleInterface {
				return &NgIndexError{Offset: off, Err: errors.New("a section must have an interface before an interface statistics block")}
			}
		}

		off = end
	}
	return nil
}

type ngIndexOptionFunc func(code ngOptionCode, value []byte) error

func (x *NgIndex) readStructuralOptions(blockOff int64, order binary.ByteOrder, bodyOff, end int64, fn ngIndexOptionFunc) error {
	for bodyOff < end {
		if end-bodyOff < 4 {
			return &NgIndexError{Offset: blockOff, Err: errors.New("truncated block options")}
		}
		var head [4]byte
		if err := ngReadFullAt(x.r, head[:], bodyOff, x.size); err != nil {
			return err
		}
		bodyOff += 4
		code := ngOptionCode(order.Uint16(head[0:2]))
		optLen := int64(order.Uint16(head[2:4]))
		if code == ngOptionCodeEndOfOptions {
			if optLen != 0 {
				return &NgIndexError{Offset: blockOff, Err: errors.New("end of options must be zero length")}
			}
			return nil
		}
		padded := (optLen + 3) &^ 3
		if padded < 0 || padded > end-bodyOff {
			return &NgIndexError{Offset: blockOff, Err: errors.New("option extends beyond block")}
		}
		if fn != nil && optLen > 0 {
			value := make([]byte, optLen)
			if err := ngReadFullAt(x.r, value, bodyOff, x.size); err != nil {
				return err
			}
			if err := fn(code, value); err != nil {
				return &NgIndexError{Offset: blockOff, Err: err}
			}
		}
		bodyOff += padded
	}
	return nil
}

func (x *NgIndex) readInterfaceDescriptor(off, blockLen int64, order binary.ByteOrder) (NgInterface, error) {
	var fixed [8]byte
	if err := ngReadFullAt(x.r, fixed[:], off+8, x.size); err != nil {
		return NgInterface{}, err
	}

	intf := NgInterface{
		LinkType:   layers.LinkType(order.Uint16(fixed[0:2])),
		SnapLength: order.Uint32(fixed[4:8]),
	}

	err := x.readStructuralOptions(off, order, off+16, off+blockLen-4, func(code ngOptionCode, value []byte) error {
		switch code {
		case ngOptionCodeInterfaceName:
			intf.Name = string(value)
		case ngOptionCodeComment:
			intf.Comment = string(value)
		case ngOptionCodeInterfaceDescription:
			intf.Description = string(value)
		case ngOptionCodeInterfaceFilter:
			if len(value) < 1 {
				return errors.New("interface filter option is empty")
			}
			intf.Filter = string(value[1:])
		case ngOptionCodeInterfaceOS:
			intf.OS = string(value)
		case ngOptionCodeInterfaceTimestampOffset:
			if len(value) != 8 {
				return fmt.Errorf("interface timestamp offset option has length %d", len(value))
			}
			intf.TimestampOffset = order.Uint64(value)
		case ngOptionCodeInterfaceTimestampResolution:
			if len(value) < 1 {
				return errors.New("interface timestamp resolution option is empty")
			}
			intf.TimestampResolution = NgResolution(value[0])
		}
		return nil
	})
	if err != nil {
		return NgInterface{}, err
	}

	if intf.TimestampResolution == 0 {
		intf.TimestampResolution = 6
	}
	if err := ngPrepareInterface(&intf); err != nil {
		return NgInterface{}, err
	}
	return intf, nil
}

func ngPrepareInterface(intf *NgInterface) error {
	resolution := intf.TimestampResolution
	if resolution.Binary() {
		exponent := int(resolution.Exponent())
		if exponent >= 64 {
			return fmt.Errorf("unsupported binary timestamp resolution exponent %d", exponent)
		}
		intf.secondMask = uint64(1) << uint(exponent)
	} else {
		exponent := int(resolution.Exponent())
		if exponent > 18 {
			return fmt.Errorf("unsupported decimal timestamp resolution exponent %d", exponent)
		}
		intf.secondMask = 1
		for i := 0; i < exponent; i++ {
			intf.secondMask *= 10
		}
	}
	intf.scaleDown = 1
	intf.scaleUp = 1
	if intf.secondMask < uint64(time.Second) {
		intf.scaleUp = uint64(time.Second) / intf.secondMask
	} else {
		intf.scaleDown = intf.secondMask / uint64(time.Second)
	}
	return nil
}

func ngConvertTime(iface NgInterface, timestamp uint64) time.Time {
	seconds := int64(timestamp/iface.secondMask + iface.TimestampOffset)
	nanoseconds := int64(timestamp % iface.secondMask * iface.scaleUp / iface.scaleDown)
	return time.Unix(seconds, nanoseconds).UTC()
}

func (x *NgIndex) appendPacket(loc NgPacketLocation) {
	loc.Number = len(x.packets)
	x.packets = append(x.packets, loc)
}

func (x *NgIndex) indexPacketBlock(off, blockLen int64, order binary.ByteOrder, section *ngIndexSection, sectionNumber int, firstLinkType layers.LinkType, typ ngBlockType) error {
	minimumBlockLength := int64(32)
	headerLength := int64(28)
	if blockLen < minimumBlockLength {
		return &NgIndexError{Offset: off, Err: fmt.Errorf("packet block is too short: %d bytes", blockLen)}
	}

	var fixed [20]byte
	if err := ngReadFullAt(x.r, fixed[:], off+8, x.size); err != nil {
		return err
	}

	ifaceID := int(order.Uint32(fixed[0:4]))
	if typ == ngBlockTypePacket {
		ifaceID = int(order.Uint16(fixed[0:2]))
	}
	if ifaceID < 0 || ifaceID >= len(section.ifaces) {
		return &NgIndexError{Offset: off, Err: fmt.Errorf("interface id %d not present in section (have only %d interfaces)", ifaceID, len(section.ifaces))}
	}
	iface := section.ifaces[ifaceID]

	captureLength := int64(order.Uint32(fixed[12:16]))
	originalLength := int64(order.Uint32(fixed[16:20]))
	if captureLength > originalLength {
		return &NgIndexError{Offset: off, Err: fmt.Errorf("capture length %d is greater than original length %d", captureLength, originalLength)}
	}
	if captureLength > math.MaxInt || originalLength > math.MaxInt {
		return &NgIndexError{Offset: off, Err: errors.New("packet length is too large")}
	}

	paddedLength := (captureLength + 3) &^ 3
	if paddedLength > blockLen-headerLength-4 {
		return &NgIndexError{Offset: off, Err: errors.New("packet data extends beyond block")}
	}
	dataEnd := off + headerLength + paddedLength
	if err := x.readStructuralOptions(off, order, dataEnd, off+blockLen-4, nil); err != nil {
		return err
	}

	if !x.options.WantMixedLinkType && iface.LinkType != firstLinkType {
		return nil
	}

	timestamp := uint64(order.Uint32(fixed[4:8]))<<32 | uint64(order.Uint32(fixed[8:12]))
	ci := gopacket.CaptureInfo{
		Timestamp:      ngConvertTime(iface, timestamp),
		CaptureLength:  int(captureLength),
		Length:         int(originalLength),
		InterfaceIndex: ifaceID,
	}
	x.appendPacket(NgPacketLocation{
		Section:      sectionNumber,
		Interface:    ifaceID,
		Offset:       off,
		DataOffset:   off + headerLength,
		CaptureInfo:  ci,
		HasTimestamp: true,
		section:      section,
	})
	return nil
}

func (x *NgIndex) indexSimplePacket(off, blockLen int64, order binary.ByteOrder, section *ngIndexSection, sectionNumber int, firstLinkType layers.LinkType) error {
	if blockLen < 16 {
		return &NgIndexError{Offset: off, Err: fmt.Errorf("simple packet block is too short: %d bytes", blockLen)}
	}

	var fixed [4]byte
	if err := ngReadFullAt(x.r, fixed[:], off+8, x.size); err != nil {
		return err
	}
	originalLength := int64(order.Uint32(fixed[:]))
	if originalLength > math.MaxInt {
		return &NgIndexError{Offset: off, Err: errors.New("packet length is too large")}
	}

	paddedLength := (originalLength + 3) &^ 3
	if paddedLength > blockLen-16 {
		return &NgIndexError{Offset: off, Err: errors.New("simple packet data extends beyond block")}
	}

	iface := section.ifaces[0]
	if !x.options.WantMixedLinkType && iface.LinkType != firstLinkType {
		return nil
	}

	captureLength := int(originalLength)
	if iface.SnapLength != 0 && uint32(captureLength) > iface.SnapLength {
		captureLength = int(iface.SnapLength)
	}
	ci := gopacket.CaptureInfo{
		CaptureLength:  captureLength,
		Length:         int(originalLength),
		InterfaceIndex: 0,
	}
	x.appendPacket(NgPacketLocation{
		Section:     sectionNumber,
		Interface:   0,
		Offset:      off,
		DataOffset:  off + 12,
		CaptureInfo: ci,
		section:     section,
	})
	return nil
}

// Len returns the number of indexed packet blocks visible under the reader options.
func (x *NgIndex) Len() int {
	return len(x.packets)
}

// NSections returns the number of valid sections encountered while building the index.
func (x *NgIndex) NSections() int {
	return len(x.sections)
}

// NInterfaces returns the number of interfaces in the requested section.
func (x *NgIndex) NInterfaces(section int) (int, error) {
	if section < 0 || section >= len(x.sections) {
		return 0, fmt.Errorf("pcapgo: section %d invalid; there are %d sections", section, len(x.sections))
	}
	return len(x.sections[section].ifaces), nil
}

// SectionInterface returns the interface description associated with a section-local interface ID.
func (x *NgIndex) SectionInterface(section, iface int) (NgInterface, error) {
	if section < 0 || section >= len(x.sections) {
		return NgInterface{}, fmt.Errorf("pcapgo: section %d invalid; there are %d sections", section, len(x.sections))
	}
	if iface < 0 || iface >= len(x.sections[section].ifaces) {
		return NgInterface{}, fmt.Errorf("pcapgo: interface %d invalid; section %d has %d interfaces", iface, section, len(x.sections[section].ifaces))
	}
	return x.sections[section].ifaces[iface], nil
}

// Location returns the location of packet number n. Packet numbers are zero-based in file order.
func (x *NgIndex) Location(n int) (NgPacketLocation, error) {
	if n < 0 || n >= len(x.packets) {
		return NgPacketLocation{}, fmt.Errorf("pcapgo: packet number %d invalid; index contains %d packets", n, len(x.packets))
	}
	return x.packets[n], nil
}

// LocationsBetween returns locations with timestamps in [start, end), preserving file order.
// Simple Packet Blocks have no timestamp and are therefore not returned.
func (x *NgIndex) LocationsBetween(start, end time.Time) []NgPacketLocation {
	var locations []NgPacketLocation
	for _, location := range x.packets {
		timestamp := location.CaptureInfo.Timestamp
		if !location.HasTimestamp || timestamp.Before(start) || !timestamp.Before(end) {
			continue
		}
		locations = append(locations, location)
	}
	return locations
}

// ReadPacketDataBetween returns packet data with timestamps in [start, end), preserving file order.
// Simple Packet Blocks have no timestamp and are therefore not returned.
func (x *NgIndex) ReadPacketDataBetween(start, end time.Time) ([][]byte, []gopacket.CaptureInfo, error) {
	locations := x.LocationsBetween(start, end)
	data := make([][]byte, len(locations))
	captureInfo := make([]gopacket.CaptureInfo, len(locations))
	var err error
	for i, location := range locations {
		data[i], captureInfo[i], err = x.ReadPacketDataAtLocation(location)
		if err != nil {
			return nil, nil, err
		}
	}
	return data, captureInfo, nil
}

// ReadPacketDataAt reads packet number n directly from its indexed file offset.
func (x *NgIndex) ReadPacketDataAt(n int) ([]byte, gopacket.CaptureInfo, error) {
	location, err := x.Location(n)
	if err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return x.ReadPacketDataAtLocation(location)
}

// ReadPacketDataAtLocation reads the packet described by location directly from its indexed file offset.
func (x *NgIndex) ReadPacketDataAtLocation(location NgPacketLocation) ([]byte, gopacket.CaptureInfo, error) {
	if location.section == nil || location.Section < 0 || location.Section >= len(x.sections) ||
		x.sections[location.Section] != location.section {
		return nil, gopacket.CaptureInfo{}, errNgIndexLocation
	}

	data := make([]byte, location.CaptureInfo.CaptureLength)
	if err := ngReadFullAt(x.r, data, location.DataOffset, x.size); err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}

	ci := location.CaptureInfo
	if x.options.WantMixedLinkType {
		ci.AncillaryData = []interface{}{location.section.ifaces[location.Interface].LinkType}
	}
	return data, ci, nil
}
