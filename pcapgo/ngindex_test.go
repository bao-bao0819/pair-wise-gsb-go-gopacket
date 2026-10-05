package pcapgo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

type ngIndexBuilder struct {
	buf   bytes.Buffer
	order binary.ByteOrder
}

func (b *ngIndexBuilder) u32(v uint32) {
	var data [4]byte
	b.order.PutUint32(data[:], v)
	b.buf.Write(data[:])
}

func (b *ngIndexBuilder) u16(v uint16) {
	var data [2]byte
	b.order.PutUint16(data[:], v)
	b.buf.Write(data[:])
}

func (b *ngIndexBuilder) u64(v uint64) {
	var data [8]byte
	b.order.PutUint64(data[:], v)
	b.buf.Write(data[:])
}

func (b *ngIndexBuilder) option(code ngOptionCode, value []byte) {
	b.u16(uint16(code))
	b.u16(uint16(len(value)))
	b.buf.Write(value)
	for i := int64(len(value)); i&3 != 0; i++ {
		b.buf.WriteByte(0)
	}
}

func (b *ngIndexBuilder) sectionHeader(order binary.ByteOrder) {
	b.order = order
	b.u32(uint32(ngBlockTypeSectionHeader))
	b.u32(28)
	var magic [4]byte
	order.PutUint32(magic[:], ngByteOrderMagic)
	b.buf.Write(magic[:])
	b.u16(ngVersionMajor)
	b.u16(ngVersionMinor)
	b.u64(math.MaxUint64)
	b.u32(28)
}

func (b *ngIndexBuilder) interfaceDescriptor(linkType layers.LinkType, snapLength uint32, resolution byte, offset uint64) {
	blockLength := uint32(16 + 8 + 4 + 4)
	if offset != 0 {
		blockLength += 12
	}
	b.u32(uint32(ngBlockTypeInterfaceDescriptor))
	b.u32(blockLength)
	b.u16(uint16(linkType))
	b.u16(0)
	b.u32(snapLength)
	b.option(ngOptionCodeInterfaceTimestampResolution, []byte{resolution})
	if offset != 0 {
		var value [8]byte
		b.order.PutUint64(value[:], offset)
		b.option(ngOptionCodeInterfaceTimestampOffset, value[:])
	}
	b.option(ngOptionCodeEndOfOptions, nil)
	b.u32(blockLength)
}

func (b *ngIndexBuilder) enhancedPacket(iface uint32, ticks uint64, data []byte) {
	paddedLength := (len(data) + 3) &^ 3
	blockLength := uint32(32 + paddedLength)
	b.u32(uint32(ngBlockTypeEnhancedPacket))
	b.u32(blockLength)
	b.u32(iface)
	b.u32(uint32(ticks >> 32))
	b.u32(uint32(ticks))
	b.u32(uint32(len(data)))
	b.u32(uint32(len(data)))
	b.buf.Write(data)
	for i := len(data); i < paddedLength; i++ {
		b.buf.WriteByte(0)
	}
	b.u32(blockLength)
}

func (b *ngIndexBuilder) packetBlock(iface uint16, ticks uint64, data []byte) {
	paddedLength := (len(data) + 3) &^ 3
	blockLength := uint32(32 + paddedLength)
	b.u32(uint32(ngBlockTypePacket))
	b.u32(blockLength)
	b.u32(uint32(iface))
	b.u32(uint32(ticks >> 32))
	b.u32(uint32(ticks))
	b.u32(uint32(len(data)))
	b.u32(uint32(len(data)))
	b.buf.Write(data)
	for i := len(data); i < paddedLength; i++ {
		b.buf.WriteByte(0)
	}
	b.u32(blockLength)
}

func (b *ngIndexBuilder) simplePacket(data []byte) {
	paddedLength := (len(data) + 3) &^ 3
	blockLength := uint32(16 + paddedLength)
	b.u32(uint32(ngBlockTypeSimplePacket))
	b.u32(blockLength)
	b.u32(uint32(len(data)))
	b.buf.Write(data)
	for i := len(data); i < paddedLength; i++ {
		b.buf.WriteByte(0)
	}
	b.u32(blockLength)
}

func buildIndexedSample(t *testing.T) []byte {
	t.Helper()

	var b ngIndexBuilder
	b.sectionHeader(binary.LittleEndian)
	b.interfaceDescriptor(layers.LinkTypeEthernet, 0, 6, 1000)
	b.interfaceDescriptor(layers.LinkTypeNull, 0, 9, 1000)
	b.enhancedPacket(0, 2_000_000, []byte{1, 2, 3, 4, 5})
	b.enhancedPacket(1, 10_000_000_000, []byte{6, 7})
	b.packetBlock(0, 3_000_000, []byte{12, 13, 14, 15})
	b.simplePacket([]byte{8, 9, 10, 11})

	b.sectionHeader(binary.BigEndian)
	b.interfaceDescriptor(layers.LinkTypeLinuxSLL, 0, 0x83, 100)
	b.enhancedPacket(0, 16, bytes.Repeat([]byte{0x42}, 4096))

	return b.buf.Bytes()
}

type countingReaderAt struct {
	r         io.ReaderAt
	calls     int
	bytesRead int64
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	r.bytesRead += int64(len(p))
	return r.r.ReadAt(p, off)
}

func (r *countingReaderAt) reset() {
	r.calls = 0
	r.bytesRead = 0
}

func TestNgIndexMatchesSequentialNgReaderAndSupportsInterleavedReads(t *testing.T) {
	file := buildIndexedSample(t)
	counter := &countingReaderAt{r: bytes.NewReader(file)}

	options := DefaultNgReaderOptions
	options.WantMixedLinkType = true
	idx, err := NewNgIndexOptions(counter, int64(len(file)), options)
	if err != nil {
		t.Fatal(err)
	}

	if idx.Len() != 5 {
		t.Fatalf("indexed packet count = %d, want 5", idx.Len())
	}
	if idx.NSections() != 2 {
		t.Fatalf("section count = %d, want 2", idx.NSections())
	}

	first, err := idx.Location(0)
	if err != nil {
		t.Fatal(err)
	}
	last, err := idx.Location(4)
	if err != nil {
		t.Fatal(err)
	}
	if first.Section != 0 || first.Interface != 0 || first.BigEndian() {
		t.Fatalf("unexpected first packet context: section=%d interface=%d bigEndian=%t", first.Section, first.Interface, first.BigEndian())
	}
	second, err := idx.Location(1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Section != 0 || second.Interface != 1 {
		t.Fatalf("unexpected second packet context: section=%d interface=%d", second.Section, second.Interface)
	}
	if last.Section != 1 || last.Interface != 0 || !last.BigEndian() {
		t.Fatalf("unexpected last packet context: section=%d interface=%d bigEndian=%t", last.Section, last.Interface, last.BigEndian())
	}
	if !first.CaptureInfo.Timestamp.Equal(time.Unix(1002, 0).UTC()) {
		t.Fatalf("first timestamp = %v, want 1002s", first.CaptureInfo.Timestamp)
	}
	if got := last.CaptureInfo.Timestamp; !got.Equal(time.Unix(102, 0).UTC()) {
		t.Fatalf("last timestamp = %v, want 102s", got)
	}

	third, err := idx.Location(2)
	if err != nil {
		t.Fatal(err)
	}
	if third.Section != 0 || third.Interface != 0 || !third.HasTimestamp {
		t.Fatalf("unexpected packet block context: section=%d interface=%d timestamp=%t", third.Section, third.Interface, third.HasTimestamp)
	}

	simple, err := idx.Location(3)
	if err != nil {
		t.Fatal(err)
	}
	if ts, ok := simple.Timestamp(); ok || !ts.IsZero() {
		t.Fatalf("simple packet timestamp = %v, ok=%t, want zero/false", ts, ok)
	}

	rangeLocations := idx.LocationsBetween(time.Unix(100, 0).UTC(), time.Unix(1003, 0).UTC())
	if got := []int{rangeLocations[0].Number, rangeLocations[1].Number}; !reflect.DeepEqual(got, []int{0, 4}) {
		t.Fatalf("time range packet numbers = %v, want [0 4] in file order", got)
	}
	if locations := idx.LocationsBetween(time.Unix(1002, 0).UTC(), time.Unix(1003, 0).UTC()); len(locations) != 1 || locations[0].Number != 0 {
		t.Fatalf("[1002,1003) = %+v, want only packet 0", locations)
	}
	if locations := idx.LocationsBetween(time.Unix(1010, 0).UTC(), time.Unix(1011, 0).UTC()); len(locations) != 1 || locations[0].Number != 1 {
		t.Fatalf("[1010,1011) = %+v, want only packet 1", locations)
	}
	if locations := idx.LocationsBetween(time.Unix(1003, 0).UTC(), time.Unix(1004, 0).UTC()); len(locations) != 1 || locations[0].Number != 2 {
		t.Fatalf("[1003,1004) = %+v, want only packet 2", locations)
	}
	rangeData, rangeCI, err := idx.ReadPacketDataBetween(time.Unix(100, 0).UTC(), time.Unix(1003, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(rangeData) != 2 || len(rangeData[0]) != 5 || len(rangeData[1]) != 4096 {
		t.Fatalf("range data lengths = %v, want packet payloads 5 and 4096", []int{len(rangeData[0]), len(rangeData[1])})
	}
	if len(rangeCI) != 2 || rangeCI[0].InterfaceIndex != 0 || rangeCI[1].InterfaceIndex != 0 {
		t.Fatalf("range CaptureInfo = %#v, want two section-local interface 0 packets", rangeCI)
	}

	sequential, err := NewNgReader(bytes.NewReader(file), options)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < idx.Len(); i++ {
		wantData, wantCI, err := sequential.ReadPacketData()
		if err != nil {
			t.Fatalf("sequential packet %d: %v", i, err)
		}
		gotData, gotCI, err := idx.ReadPacketDataAt(i)
		if err != nil {
			t.Fatalf("indexed packet %d: %v", i, err)
		}
		if !bytes.Equal(gotData, wantData) {
			t.Fatalf("packet %d data mismatch", i)
		}
		if !reflect.DeepEqual(gotCI, wantCI) {
			t.Fatalf("packet %d CaptureInfo mismatch:\ngot:  %#v\nwant: %#v", i, gotCI, wantCI)
		}
	}

	counter.reset()
	data, ci, err := idx.ReadPacketDataAt(0)
	if err != nil {
		t.Fatal(err)
	}
	if counter.calls != 1 || counter.bytesRead != int64(len(data)) {
		t.Fatalf("single packet read used %d calls and %d bytes, want 1 call and %d bytes", counter.calls, counter.bytesRead, len(data))
	}
	if ci.CaptureLength != 5 || !bytes.Equal(data, []byte{1, 2, 3, 4, 5}) {
		t.Fatalf("unexpected single packet: data=%v ci=%#v", data, ci)
	}

	data3, _, err := idx.ReadPacketDataAtLocation(rangeLocations[1])
	if err != nil {
		t.Fatal(err)
	}
	data0, _, err := idx.ReadPacketDataAtLocation(rangeLocations[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(data3) != 4096 || len(data0) != 5 {
		t.Fatalf("interleaved read lengths = %d and %d, want 4096 and 5", len(data3), len(data0))
	}

	if iface0, err := idx.SectionInterface(0, 0); err != nil || iface0.LinkType != layers.LinkTypeEthernet {
		t.Fatalf("section 0 interface 0 = %+v, %v", iface0, err)
	} else if iface0.TimestampResolution != 6 || iface0.TimestampOffset != 1000 {
		t.Fatalf("section 0 interface 0 time context = resolution %d offset %d, want 6/1000", iface0.TimestampResolution, iface0.TimestampOffset)
	}
	if iface1, err := idx.SectionInterface(1, 0); err != nil || iface1.LinkType != layers.LinkTypeLinuxSLL {
		t.Fatalf("section 1 interface 0 = %+v, %v", iface1, err)
	} else if iface1.TimestampResolution != 0x83 || iface1.TimestampOffset != 100 {
		t.Fatalf("section 1 interface 0 time context = resolution %#x offset %d, want 0x83/100", iface1.TimestampResolution, iface1.TimestampOffset)
	}
}

func TestNgIndexBuildDoesNotReadPacketPayloads(t *testing.T) {
	file := buildIndexedSample(t)
	counter := &countingReaderAt{r: bytes.NewReader(file)}

	options := DefaultNgReaderOptions
	options.WantMixedLinkType = true
	if _, err := NewNgIndexOptions(counter, int64(len(file)), options); err != nil {
		t.Fatal(err)
	}
	if counter.bytesRead >= int64(len(file)) {
		t.Fatalf("index scanned %d of %d bytes; payload reads were expected", counter.bytesRead, len(file))
	}
	if counter.bytesRead > 512 {
		t.Fatalf("index read %d bytes of metadata, want fewer than 512", counter.bytesRead)
	}
}

func TestNgIndexRejectsCompressionAndCorruptBlocksWithOffset(t *testing.T) {
	counter := &countingReaderAt{r: bytes.NewReader([]byte{magicGzip1, magicGzip2, 8, 0})}
	_, err := NewNgIndex(counter, 4)
	if !errors.Is(err, ErrNgIndexCompressed) {
		t.Fatalf("gzip error = %v, want ErrNgIndexCompressed", err)
	}

	file := buildIndexedSample(t)
	truncated := append([]byte(nil), file[:len(file)-4]...)
	_, err = NewNgIndexOptions(bytes.NewReader(truncated), int64(len(truncated)), DefaultNgReaderOptions)
	var offsetErr *NgIndexError
	if !errors.As(err, &offsetErr) {
		t.Fatalf("truncated block error = %T %[1]v, want *NgIndexError", err)
	}
	wantCorruptOffset := int64(len(file) - 4128)
	if offsetErr.Offset != wantCorruptOffset {
		t.Fatalf("truncated block offset = %d, want %d", offsetErr.Offset, wantCorruptOffset)
	}

	badTrailer := append([]byte(nil), file...)
	badTrailer[len(badTrailer)-1] ^= 0xff
	_, err = NewNgIndexOptions(bytes.NewReader(badTrailer), int64(len(badTrailer)), DefaultNgReaderOptions)
	if !errors.As(err, &offsetErr) || offsetErr.Offset != wantCorruptOffset {
		t.Fatalf("bad trailer error = %v at %d, want offset %d", err, offsetErr.Offset, wantCorruptOffset)
	}
}
