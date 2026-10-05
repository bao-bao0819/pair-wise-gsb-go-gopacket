// Copyright 2026 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

// blockBuilder constructs raw pcapng blocks in memory with a selectable byte
// order, which the on-disk-only-little-endian NgWriter cannot do.
type blockBuilder struct {
	order binary.ByteOrder
}

func (b blockBuilder) putU16(dst []byte, v uint16) { b.order.PutUint16(dst, v) }
func (b blockBuilder) putU32(dst []byte, v uint32) { b.order.PutUint32(dst, v) }
func (b blockBuilder) putU64(dst []byte, v uint64) { b.order.PutUint64(dst, v) }

func pad4(n int) int { return (n + 3) &^ 3 }

func (b blockBuilder) option(code ngOptionCode, value []byte) []byte {
	padded := make([]byte, 4+pad4(len(value)))
	b.putU16(padded[0:2], uint16(code))
	b.putU16(padded[2:4], uint16(len(value)))
	copy(padded[4:], value)
	return padded
}

func (b blockBuilder) endOptions() []byte {
	return []byte{0, 0, 0, 0}
}

// shb builds a Section Header Block with an optional if_tsresol-style
// section; it carries no section length (-1).
func (b blockBuilder) shb() []byte {
	content := make([]byte, 16) // magic(4) version(4) section length(8)
	b.putU32(content[0:4], ngByteOrderMagic)
	b.putU16(content[4:6], ngVersionMajor)
	b.putU16(content[6:8], ngVersionMinor)
	for i := 8; i < 16; i++ {
		content[i] = 0xff
	}
	return b.block(ngBlockTypeSectionHeader, content, nil)
}

// idb builds an Interface Description Block. tsOffset is added only if nonZero.
func (b blockBuilder) idb(linkType layers.LinkType, snapLen uint32, resolution byte, tsOffset uint64) []byte {
	fixed := make([]byte, 8)
	b.putU16(fixed[0:2], uint16(linkType))
	fixed[2] = 0
	fixed[3] = 0
	b.putU32(fixed[4:8], snapLen)

	var opts []byte
	if resolution != 0 {
		opts = append(opts, b.option(ngOptionCodeInterfaceTimestampResolution, []byte{resolution})...)
	}
	if tsOffset != 0 {
		v := make([]byte, 8)
		b.putU64(v, tsOffset)
		opts = append(opts, b.option(ngOptionCodeInterfaceTimestampOffset, v)...)
	}
	opts = append(opts, b.endOptions()...)
	return b.block(ngBlockTypeInterfaceDescriptor, fixed, opts)
}

// epb builds an Enhanced Packet Block. ts is the raw interface-resolution
// timestamp; options are EPB options.
func (b blockBuilder) epb(ifaceID uint32, ts uint64, capLen, origLen uint32, data []byte, opts []byte) []byte {
	fixed := make([]byte, 20)
	b.putU32(fixed[0:4], ifaceID)
	b.putU32(fixed[4:8], uint32(ts>>32))
	b.putU32(fixed[8:12], uint32(ts))
	b.putU32(fixed[12:16], capLen)
	b.putU32(fixed[16:20], origLen)
	padded := make([]byte, pad4(len(data)))
	copy(padded, data)
	allOpts := opts
	allOpts = append(allOpts, b.endOptions()...)
	return b.block(ngBlockTypeEnhancedPacket, fixed, padded, allOpts)
}

// pb builds a deprecated Packet Block (type 2).
func (b blockBuilder) pb(ifaceID uint16, ts uint64, capLen, origLen uint32, data []byte) []byte {
	// The 20 bytes after the block header are laid out exactly as
	// NgReader.readPacketHeader interprets them: interface id (2), two ignored
	// bytes, timestamp high/low (8), captured/original length (8). This is a
	// compact, NgReader-specific interpretation of the legacy packet block.
	fixed := make([]byte, 20)
	b.putU16(fixed[0:2], ifaceID)
	b.putU32(fixed[4:8], uint32(ts>>32))
	b.putU32(fixed[8:12], uint32(ts))
	b.putU32(fixed[12:16], capLen)
	b.putU32(fixed[16:20], origLen)
	padded := make([]byte, pad4(len(data)))
	copy(padded, data)
	return b.block(ngBlockTypePacket, fixed, padded, b.endOptions())
}

// spb builds a Simple Packet Block (type 3).
func (b blockBuilder) spb(origLen uint32, data []byte) []byte {
	fixed := make([]byte, 4)
	b.putU32(fixed[0:4], origLen)
	padded := make([]byte, pad4(len(data)))
	copy(padded, data)
	return b.block(ngBlockTypeSimplePacket, fixed, padded)
}

// block assembles type + length + parts... + trailing length.
func (b blockBuilder) block(typ ngBlockType, parts ...[]byte) []byte {
	total := 12
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	head := make([]byte, 8)
	b.putU32(head[0:4], uint32(typ))
	b.putU32(head[4:8], uint32(total))
	out = append(out, head...)
	for _, p := range parts {
		out = append(out, p...)
	}
	tail := make([]byte, 4)
	b.putU32(tail[0:4], uint32(total))
	out = append(out, tail...)
	return out
}

// epbCommentOptions returns an EPB options fragment with one comment and one
// flags word. Flags values are always little endian per the reader semantics.
func epbCommentFlags(comment string, flags uint32) []byte {
	le := blockBuilder{order: binary.LittleEndian}
	out := le.option(ngOptionCodeComment, []byte(comment))
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, flags)
	out = append(out, le.option(ngOptionCodeEpbFlags, v)...)
	return out
}

// indexSample builds the cross-section sample used by the tests and returns the
// raw bytes together with the independently described expected packets.
type expectedPacket struct {
	section int
	iface   int
	ts      time.Time
	hasTS   bool
	capLen  int
	origLen int
	data    []byte
}

func buildIndexSample(t *testing.T) ([]byte, []expectedPacket) {
	t.Helper()
	le := blockBuilder{order: binary.LittleEndian}
	be := blockBuilder{order: binary.BigEndian}

	data1 := []byte("packet-0-little-endian!!")               // 24 bytes
	data2 := []byte("pkt1")                                   // 4
	data3 := []byte("packet-two-simple-packet-block-padding") // 41 bytes -> padded
	data4 := []byte("pkt3-be-interface-0-reuse")              // 27 bytes
	data5 := []byte("pkt4-be-iface1-after-idb")               // 26 bytes
	data6 := []byte("pkt5-be-oldest-ts")                      // 15 bytes
	data7 := []byte("deprecated-packet-block-data!!")         // 28 bytes

	var file []byte

	// Section 0: little endian, microsecond resolution, two interfaces.
	file = append(file, le.shb()...)
	file = append(file, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...) // iface 0: us
	file = append(file, le.idb(layers.LinkTypeEthernet, 0, 9, 0)...) // iface 1: ns

	// p0: iface 0, us, t = 1.000001 s
	p0opts := epbCommentFlags("p0-comment", uint32(NgEpbFlagDirectionInbound))
	file = append(file, le.epb(0, 1_000_001, uint32(len(data1)), uint32(len(data1)), data1, p0opts)...)
	// p1: iface 1, ns, t = 2.5 s (timestamp goes forward)
	file = append(file, le.epb(1, 2_500_000_000, uint32(len(data2)), uint32(len(data2)+10), data2, nil)...)
	// p2: simple packet, no timestamp (iface 0 snap length 0 -> cap = orig)
	file = append(file, le.spb(uint32(len(data3)), data3)...)

	// Section 1: big endian, microsecond resolution, timestamp offset +100s.
	// Interface id 0 is reused but is a distinct interface descriptor.
	file = append(file, be.shb()...)
	file = append(file, be.idb(layers.LinkTypeEthernet, 0, 6, 100)...) // iface 0: us, +100s

	// p3: t = 1.000002 s raw -> 101.000002 s. Earlier in wall-clock terms than
	// p1 only after adding the offset; still it appears later in file order.
	file = append(file, be.epb(0, 1_000_002, uint32(len(data4)), uint32(len(data4)), data4, nil)...)

	// Interface 1 appears *after* a packet, proving interface context is taken
	// from the section and ids are not global.
	file = append(file, be.idb(layers.LinkTypeEthernet, 0, 6, 100)...) // iface 1
	// p4: iface 1, raw t = 3.000003 -> 103.000003
	file = append(file, be.epb(1, 3_000_003, uint32(len(data5)), uint32(len(data5)), data5, nil)...)
	// p5: iface 0, raw t = 0.000000 -> 100.000000, time goes backwards in file
	file = append(file, be.epb(0, 0, uint32(len(data6)), uint32(len(data6)), data6, nil)...)
	// p6: deprecated packet block on iface 0 (section 1, +100s), raw t = 6 s
	file = append(file, be.pb(0, 6_000_000, uint32(len(data7)), uint32(len(data7)), data7)...)

	expected := []expectedPacket{
		{0, 0, time.Unix(1, 1_000).UTC(), true, len(data1), len(data1), data1},
		{0, 1, time.Unix(2, 500_000_000).UTC(), true, len(data2), len(data2) + 10, data2},
		{0, 0, time.Time{}, false, len(data3), len(data3), data3},
		{1, 0, time.Unix(101, 2_000).UTC(), true, len(data4), len(data4), data4},
		{1, 1, time.Unix(103, 3_000).UTC(), true, len(data5), len(data5), data5},
		{1, 0, time.Unix(100, 0).UTC(), true, len(data6), len(data6), data6},
		{1, 0, time.Unix(106, 0).UTC(), true, len(data7), len(data7), data7},
	}

	return file, expected
}

func newSampleIndex(t *testing.T, opts NgIndexOptions, raw []byte) *NgIndex {
	t.Helper()
	idx, err := NewNgIndex(bytes.NewReader(raw), int64(len(raw)), opts)
	if err != nil {
		t.Fatalf("NewNgIndex failed: %v", err)
	}
	return idx
}

// TestNgIndexMatchesNgReader builds the cross-section sample and verifies every
// packet read at random matches the values produced by a sequential NgReader,
// both for data and for gopacket.CaptureInfo.
func TestNgIndexMatchesNgReader(t *testing.T) {
	raw, expected := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	if got, want := idx.Len(), len(expected); got != want {
		t.Fatalf("Len = %d, want %d", got, want)
	}
	if got, want := idx.NumSections(), 2; got != want {
		t.Fatalf("NumSections = %d, want %d", got, want)
	}
	if idx.LinkType() != layers.LinkTypeEthernet {
		t.Fatalf("LinkType = %s, want Ethernet", idx.LinkType())
	}

	// Sequential reference reader.
	ngr, err := NewNgReader(bytes.NewReader(raw), DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("NewNgReader failed: %v", err)
	}

	for n, want := range expected {
		data, ci, err := idx.ReadPacketData(n)
		if err != nil {
			t.Fatalf("packet %d: index read failed: %v", n, err)
		}
		refData, refCI, refErr := ngr.ReadPacketData()
		if refErr != nil {
			t.Fatalf("packet %d: NgReader failed: %v", n, refErr)
		}

		if !bytes.Equal(data, want.data) {
			t.Fatalf("packet %d: data mismatch\ngot  %x\nwant %x", n, data, want.data)
		}
		if !bytes.Equal(data, refData) {
			t.Fatalf("packet %d: index data does not match NgReader", n)
		}

		if ci.CaptureLength != want.capLen || ci.Length != want.origLen {
			t.Fatalf("packet %d: cap/len = %d/%d, want %d/%d", n, ci.CaptureLength, ci.Length, want.capLen, want.origLen)
		}
		if ci.InterfaceIndex != want.iface {
			t.Fatalf("packet %d: interface = %d, want %d", n, ci.InterfaceIndex, want.iface)
		}
		if ci.Timestamp != want.ts {
			t.Fatalf("packet %d: timestamp = %v, want %v", n, ci.Timestamp, want.ts)
		}
		if !ci.Timestamp.Equal(refCI.Timestamp) ||
			ci.CaptureLength != refCI.CaptureLength ||
			ci.Length != refCI.Length ||
			ci.InterfaceIndex != refCI.InterfaceIndex {
			t.Fatalf("packet %d: CaptureInfo mismatch:\nindex %#v\nreader %#v", n, ci, refCI)
		}

		ref, err := idx.Ref(n)
		if err != nil {
			t.Fatalf("packet %d: Ref failed: %v", n, err)
		}
		if ref.Number() != n || ref.Section() != want.section || ref.InterfaceID() != want.iface {
			t.Fatalf("packet %d: Ref context %+v, want section %d iface %d", n, ref, want.section, want.iface)
		}
	}

	// The sequential reader must be exhausted.
	if _, _, err := ngr.ReadPacketData(); err != io.EOF {
		t.Fatalf("expected EOF from NgReader, got %v", err)
	}
}

// corruptAt sets the trailing block length of the block containing the given
// file offset to an invalid value and returns a copy.
func mutateByte(raw []byte, off int, value byte) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	out[off] = value
	return out
}

func expectCorruptAt(t *testing.T, raw []byte, opts NgIndexOptions, wantOffset int64) {
	t.Helper()
	_, err := NewNgIndex(bytes.NewReader(raw), int64(len(raw)), opts)
	var corrupt *NgCorruptBlockError
	if !errors.As(err, &corrupt) {
		t.Fatalf("expected *NgCorruptBlockError at offset %d, got %v", wantOffset, err)
	}
	if corrupt.Offset != wantOffset {
		t.Fatalf("corruption reported at offset %d, want %d", corrupt.Offset, wantOffset)
	}
}

// TestNgIndexCorruption verifies structural problems are reported with the file
// offset of the offending block and abort the build before any packet of that
// block is registered.
func TestNgIndexCorruption(t *testing.T) {
	raw, expected := buildIndexSample(t)

	good := newSampleIndex(t, DefaultNgIndexOptions, raw)
	lastRef, err := good.Ref(len(expected) - 1)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated block header at end of file: cutting two bytes off lands in the
	// last block, whose offset the error must report.
	truncated := raw[:len(raw)-2]
	expectCorruptAt(t, truncated, DefaultNgIndexOptions, lastRef.Offset())

	// Mismatched trailing block length of the first packet block. Its trailer is
	// the last 4 bytes immediately before the next block begins.
	firstPkt, err := good.Ref(0)
	if err != nil {
		t.Fatal(err)
	}
	secondPkt, _ := good.Ref(1)
	trailerOff := int(secondPkt.Offset()) - 1
	badTrailer := mutateByte(raw, trailerOff, 0xFF)
	expectCorruptAt(t, badTrailer, DefaultNgIndexOptions, firstPkt.Offset())

	// Unknown interface id in an EPB: craft a tiny section with a bad packet.
	le := blockBuilder{order: binary.LittleEndian}
	var bad []byte
	bad = append(bad, le.shb()...)
	bad = append(bad, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...)
	bad = append(bad, le.epb(7, 1, 4, 4, []byte("aaaa"), nil)...)
	// Corruption offset is right after SHB + IDB.
	wantOff := int64(len(le.shb()) + len(le.idb(layers.LinkTypeEthernet, 0, 6, 0)))
	expectCorruptAt(t, bad, DefaultNgIndexOptions, wantOff)
}

// TestNgIndexGzipRejected ensures gzip input is explicitly refused.
func TestNgIndexGzipRejected(t *testing.T) {
	raw, _ := buildIndexSample(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	_, err := NewNgIndex(bytes.NewReader(buf.Bytes()), int64(buf.Len()), DefaultNgIndexOptions)
	if !errors.Is(err, ErrNgIndexGzip) {
		t.Fatalf("expected ErrNgIndexGzip, got %v", err)
	}
}

// TestNgIndexEmptyAndTruncated covers the start-of-file edge cases.
func TestNgIndexEmptyAndTruncated(t *testing.T) {
	if _, err := NewNgIndex(bytes.NewReader(nil), 0, DefaultNgIndexOptions); err != io.EOF {
		t.Fatalf("empty file: expected io.EOF, got %v", err)
	}
	// One byte is enough to miss the gzip check but not a block header.
	if _, err := NewNgIndex(bytes.NewReader([]byte{0x0a}), 1, DefaultNgIndexOptions); err == nil {
		t.Fatal("one-byte file: expected error")
	}
}

// TestNgIndexSkipUnknownVersion checks that sections with an unsupported
// version are skipped when requested, and that packets after the skipped
// section are still indexed in file order.
func TestNgIndexSkipUnknownVersion(t *testing.T) {
	le := blockBuilder{order: binary.LittleEndian}

	// Build a bad-version SHB manually.
	badSHB := func() []byte {
		content := make([]byte, 16)
		le.putU32(content[0:4], ngByteOrderMagic)
		le.putU16(content[4:6], 9) // unsupported major
		le.putU16(content[6:8], 0)
		for i := 8; i < 16; i++ {
			content[i] = 0xff
		}
		return le.block(ngBlockTypeSectionHeader, content, le.endOptions())
	}

	var raw []byte
	raw = append(raw, le.shb()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...)
	raw = append(raw, le.epb(0, 1, 4, 4, []byte("aaaa"), nil)...)
	raw = append(raw, badSHB()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...) // ignored block in skipped section
	// A second, valid section.
	raw = append(raw, le.shb()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...)
	raw = append(raw, le.epb(0, 2, 4, 4, []byte("bbbb"), nil)...)

	// Without SkipUnknownVersion the build fails with a version error.
	_, err := NewNgIndex(bytes.NewReader(raw), int64(len(raw)), DefaultNgIndexOptions)
	if !errors.Is(err, ErrNgVersionMismatch) {
		t.Fatalf("expected ErrNgVersionMismatch, got %v", err)
	}

	idx := newSampleIndex(t, NgIndexOptions{SkipUnknownVersion: true}, raw)
	if idx.NumSections() != 3 {
		t.Fatalf("NumSections = %d, want 3", idx.NumSections())
	}
	if idx.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (packets of skipped section must not count)", idx.Len())
	}
	data0, _, err := idx.ReadPacketData(0)
	if err != nil || string(data0) != "aaaa" {
		t.Fatalf("first packet = %q, %v", data0, err)
	}
	data1, ci, err := idx.ReadPacketData(1)
	if err != nil || string(data1) != "bbbb" {
		t.Fatalf("second packet = %q, %v", data1, err)
	}
	if ref, _ := idx.Ref(1); ref.Section() != 2 {
		t.Fatalf("second packet should belong to section 2, got section %d (ci %#v)", ref.Section(), ci)
	}
}

// TestNgIndexMixedLinkType verifies the WantMixedLinkType policy and the
// ancillary link type in CaptureInfo, plus the default-skip and
// ErrorOnMismatchingLinkType behaviour.
func TestNgIndexMixedLinkType(t *testing.T) {
	le := blockBuilder{order: binary.LittleEndian}
	var raw []byte
	raw = append(raw, le.shb()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...)
	raw = append(raw, le.idb(layers.LinkTypeLinuxSLL, 0, 6, 0)...)
	raw = append(raw, le.epb(0, 10, 4, 4, []byte("eth0"), nil)...)
	raw = append(raw, le.epb(1, 20, 4, 4, []byte("sll1"), nil)...)

	// Default: the LinuxSLL packet is silently skipped.
	def := newSampleIndex(t, DefaultNgIndexOptions, raw)
	if def.Len() != 1 {
		t.Fatalf("default policy: Len = %d, want 1", def.Len())
	}

	// Error on mismatch.
	errOpts := NgIndexOptions{ErrorOnMismatchingLinkType: true}
	_, err := NewNgIndex(bytes.NewReader(raw), int64(len(raw)), errOpts)
	if !errors.Is(err, ErrNgLinkTypeMismatch) {
		t.Fatalf("expected ErrNgLinkTypeMismatch, got %v", err)
	}

	// Mixed: both packets are present with ancillary link types.
	mixOpts := NgIndexOptions{WantMixedLinkType: true}
	mix := newSampleIndex(t, mixOpts, raw)
	if mix.Len() != 2 {
		t.Fatalf("mixed policy: Len = %d, want 2", mix.Len())
	}
	data0, ci0, err := mix.ReadPacketData(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(data0) != "eth0" || len(ci0.AncillaryData) != 1 || ci0.AncillaryData[0] != layers.LinkTypeEthernet {
		t.Fatalf("packet 0 ancillary = %#v data = %q", ci0.AncillaryData, data0)
	}
	data1, ci1, err := mix.ReadPacketData(1)
	if err != nil {
		t.Fatal(err)
	}
	if string(data1) != "sll1" || ci1.AncillaryData[0] != layers.LinkTypeLinuxSLL {
		t.Fatalf("packet 1 ancillary = %#v", ci1.AncillaryData)
	}

	// Cross-check mixed results against NgReader.
	ngr, nerr := NewNgReader(bytes.NewReader(raw), NgReaderOptions{WantMixedLinkType: true})
	if nerr != nil {
		t.Fatal(nerr)
	}
	for n := 0; n < 2; n++ {
		rd, rci, rerr := ngr.ReadPacketData()
		if rerr != nil {
			t.Fatal(rerr)
		}
		_, ici, _ := mix.ReadPacketData(n)
		if rci.InterfaceIndex != ici.InterfaceIndex || rci.Timestamp != ici.Timestamp ||
			rci.AncillaryData[0] != ici.AncillaryData[0] || !bytes.Equal(rd, func() []byte {
			if n == 0 {
				return data0
			}
			return data1
		}()) {
			t.Fatalf("mixed packet %d mismatch vs NgReader: %#v vs %#v", n, rci, ici)
		}
	}
}

// TestNgIndexSimplePacket checks SPB padding, timestamp absence from time
// queries and equivalence to the sequential NgReader for an uncapped packet.
func TestNgIndexSimplePacket(t *testing.T) {
	le := blockBuilder{order: binary.LittleEndian}
	full := []byte("simple-packet-full-data") // 22 bytes
	var raw []byte
	raw = append(raw, le.shb()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 0, 6, 0)...) // unlimited
	raw = append(raw, le.spb(uint32(len(full)), full)...)

	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)
	if idx.Len() != 1 {
		t.Fatalf("Len = %d, want 1", idx.Len())
	}
	data, ci, err := idx.ReadPacketData(0)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Length != len(full) || ci.CaptureLength != len(full) || len(data) != len(full) {
		t.Fatalf("SPB cap = %d (len %d), data len %d, want %d", ci.CaptureLength, ci.Length, len(data), len(full))
	}
	if !bytes.Equal(data, full) {
		t.Fatalf("SPB data = %q, want %q", data, full)
	}
	if !ci.Timestamp.IsZero() {
		t.Fatalf("SPB timestamp should be zero, got %v", ci.Timestamp)
	}
	if nums := idx.PacketNumbersBetween(time.Time{}, time.Time{}); len(nums) != 0 {
		t.Fatalf("timestamp-less SPB must not appear in time query, got %v", nums)
	}

	// And it must match a sequential NgReader.
	ngr, err := NewNgReader(bytes.NewReader(raw), DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	rd, rci, err := ngr.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rd, data) || rci.CaptureLength != ci.CaptureLength || rci.Length != ci.Length {
		t.Fatalf("SPB mismatch vs NgReader: %d/%d vs %d/%d", len(rd), rci.CaptureLength, len(data), ci.CaptureLength)
	}
}

// TestNgIndexSimplePacketSnapLength checks the SPB snap-length cap behaviour
// for a snap-limited interface (index-only, since the block payload must not
// exceed snap length).
func TestNgIndexSimplePacketSnapLength(t *testing.T) {
	le := blockBuilder{order: binary.LittleEndian}
	full := []byte("simple-packet-full-data") // 22 bytes
	capped := full[:8]
	var raw []byte
	raw = append(raw, le.shb()...)
	raw = append(raw, le.idb(layers.LinkTypeEthernet, 8, 6, 0)...) // snaplen 8
	raw = append(raw, le.spb(uint32(len(full)), capped)...)

	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)
	data, ci, err := idx.ReadPacketData(0)
	if err != nil {
		t.Fatal(err)
	}
	if ci.Length != len(full) || ci.CaptureLength != 8 || len(data) != 8 {
		t.Fatalf("SPB cap = %d (len %d), data len %d, want cap 8 orig %d", ci.CaptureLength, ci.Length, len(data), len(full))
	}
	if !bytes.Equal(data, capped) {
		t.Fatalf("SPB data = %q, want %q", data, capped)
	}
}

// countingReaderAt records every ReadAt invocation. It proves that indexed
// random reads do not walk the file from the beginning (which a sequential
// cursor-based reader would have to do).
type countingReaderAt struct {
	r         io.ReaderAt
	calls     int
	bytesRead int64
	regions   []readRegion
}

type readRegion struct {
	off int64
	n   int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	c.bytesRead += int64(len(p))
	c.regions = append(c.regions, readRegion{off, len(p)})
	return c.r.ReadAt(p, off)
}

func (c *countingReaderAt) reset() {
	c.calls = 0
	c.bytesRead = 0
	c.regions = nil
}

// TestNgIndexRandomReadDoesNotRescan proves that, after the index is built,
// reading one packet touches only that packet's block and never rescans earlier
// payload.
func TestNgIndexRandomReadDoesNotRescan(t *testing.T) {
	raw, expected := buildIndexSample(t)
	counter := &countingReaderAt{r: bytes.NewReader(raw)}

	idx, err := NewNgIndex(counter, int64(len(raw)), DefaultNgIndexOptions)
	if err != nil {
		t.Fatalf("NewNgIndex failed: %v", err)
	}

	// Jump to the last packet (big endian section, deprecated packet block).
	target := idx.Len() - 1
	ref, err := idx.Ref(target)
	if err != nil {
		t.Fatal(err)
	}
	counter.reset()

	data, ci, err := idx.ReadPacketData(target)
	if err != nil {
		t.Fatalf("ReadPacketData failed: %v", err)
	}
	if !bytes.Equal(data, expected[target].data) {
		t.Fatal("last packet data mismatch")
	}
	if ci.InterfaceIndex != expected[target].iface {
		t.Fatal("last packet interface mismatch")
	}

	// No read may start before the target block, i.e. we never rescan earlier
	// bytes of the file.
	for _, region := range counter.regions {
		if region.off < ref.Offset() {
			t.Fatalf("random read touched offset %d before target block offset %d; full file was rescanned", region.off, ref.Offset())
		}
	}
	// Reading one packet must move vastly fewer bytes than a full-file rescan.
	if counter.bytesRead >= int64(len(raw)) {
		t.Fatalf("single packet read consumed %d bytes, but the whole file is %d bytes", counter.bytesRead, len(raw))
	}

	// A second, independent random read (an SPB without timestamp) is bounded
	// by its own block and does not depend on the previous cursor.
	spbRef, err := idx.Ref(2)
	if err != nil {
		t.Fatal(err)
	}
	counter.reset()
	if _, _, err := idx.ReadPacketData(2); err != nil {
		t.Fatal(err)
	}
	for _, region := range counter.regions {
		if region.off < spbRef.Offset() {
			t.Fatalf("SPB read touched offset %d before its block at %d", region.off, spbRef.Offset())
		}
	}
}

// TestNgIndexInterleavedQueries mixes time-range and packet-number queries.
// Because the index has no mutable file cursor, interleaving cannot corrupt the
// results.
func TestNgIndexInterleavedQueries(t *testing.T) {
	raw, expected := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	nums := idx.PacketNumbersBetween(time.Unix(100, 0).UTC(), time.Time{})
	if len(nums) != 4 {
		t.Fatalf("time range returned %d packets, want 4", len(nums))
	}

	for _, n := range []int{6, 0, nums[0], 2, nums[len(nums)-1], 4} {
		data, ci, err := idx.ReadPacketData(n)
		if err != nil {
			t.Fatalf("interleaved read of %d failed: %v", n, err)
		}
		if !bytes.Equal(data, expected[n].data) {
			t.Fatalf("interleaved read of %d returned wrong data", n)
		}
		if ci.Timestamp != expected[n].ts {
			t.Fatalf("interleaved read of %d timestamp mismatch", n)
		}
		// Re-running the time query in between must be unaffected.
		again := idx.PacketNumbersBetween(time.Unix(100, 0).UTC(), time.Time{})
		if len(again) != len(nums) {
			t.Fatalf("time query changed after packet read: %v vs %v", again, nums)
		}
	}
}

// TestNgIndexConcurrentReads uses the same index from several goroutines to
// demonstrate there is no shared mutable cursor.
func TestNgIndexConcurrentReads(t *testing.T) {
	raw, expected := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	var wg sync.WaitGroup
	errs := make(chan error, idx.Len()*4)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < idx.Len(); n++ {
				data, _, err := idx.ReadPacketData(n)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(data, expected[n].data) {
					errs <- fmt.Errorf("goroutine got wrong data for packet %d", n)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// TestNgIndexEpbOptions verifies EPB options are decoded lazily and match the
// NgReaderWithOptions semantics, including the always-little-endian flags word.
func TestNgIndexEpbOptions(t *testing.T) {
	raw, _ := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	data, ci, opts, err := idx.ReadPacketDataWithOptions(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != ci.CaptureLength {
		t.Fatal("data/capture length mismatch")
	}
	if len(opts.Comments) != 1 || opts.Comments[0] != "p0-comment" {
		t.Fatalf("comments = %#v, want [p0-comment]", opts.Comments)
	}
	if opts.Flags == nil {
		t.Fatal("flags missing")
	}
	if opts.Flags.Direction != NgEpbFlagDirectionInbound {
		t.Fatalf("direction = %d, want inbound", opts.Flags.Direction)
	}

	// Cross-check against NgReader.
	ngr, err := NewNgReader(bytes.NewReader(raw), DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	_, nci, nopts, err := ngr.ReadPacketDataWithOptions()
	if err != nil {
		t.Fatal(err)
	}
	if nci.Timestamp != ci.Timestamp || len(nopts.Comments) != len(opts.Comments) ||
		nopts.Flags == nil || nopts.Flags.ToUint32() != opts.Flags.ToUint32() {
		t.Fatalf("EPB options mismatch:\nindex %#v\nreader %#v", opts, nopts)
	}
}

// TestNgIndexInterfaceContext checks that interface id 0 resolves to distinct
// per-section descriptors and exposes timing metadata.
func TestNgIndexInterfaceContext(t *testing.T) {
	raw, _ := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	if got := idx.NInterfaces(0); got != 2 {
		t.Fatalf("section 0 interfaces = %d, want 2", got)
	}
	if got := idx.NInterfaces(1); got != 2 {
		t.Fatalf("section 1 interfaces = %d, want 2", got)
	}

	i0s0, err := idx.Interface(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	i0s1, err := idx.Interface(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if i0s0.TimestampOffset != 0 || i0s1.TimestampOffset != 100 {
		t.Fatalf("interface 0 reused but contexts not distinct: offsets %d/%d", i0s0.TimestampOffset, i0s1.TimestampOffset)
	}
	if exp := uint8(6); i0s0.TimestampResolution != NgResolution(exp) {
		t.Fatalf("section 0 iface 0 resolution = %d, want 6", i0s0.TimestampResolution)
	}

	// Interface id 1 in section 0 uses nanosecond resolution.
	i1s0, err := idx.Interface(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if i1s0.TimestampResolution != NgResolution(9) {
		t.Fatalf("section 0 iface 1 resolution = %d, want 9", i1s0.TimestampResolution)
	}

	if _, err := idx.Interface(2, 0); err == nil {
		t.Fatal("expected error for invalid section")
	}
	if _, err := idx.Interface(0, 9); err == nil {
		t.Fatal("expected error for invalid interface")
	}

	info, err := idx.SectionInfo(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = info
}

// TestNgIndexTimeRange exercises half-open [start, end) queries over a file
// whose timestamps are not monotonic, including timestamp-less SPBs.
func TestNgIndexTimeRange(t *testing.T) {
	raw, _ := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)

	check := func(name string, start, end time.Time, want []int) {
		t.Helper()
		got := idx.PacketNumbersBetween(start, end)
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: got %v, want %v", name, got, want)
			}
		}
	}

	// Timestamps (file order): 1.000001(0), 2.5(1), none(2), 101.000002(3),
	// 103.000003(4), 100.0(5), 106.0(6).
	check("narrow-bounded", time.Unix(100, 0).UTC(), time.Unix(102, 0).UTC(), []int{3, 5})
	check("left-closed", time.Unix(100, 0).UTC(), time.Unix(101, 0).UTC(), []int{5})
	check("right-open", time.Unix(99, 0).UTC(), time.Unix(101, 2000).UTC(), []int{5})
	check("start-only", time.Unix(102, 0).UTC(), time.Time{}, []int{4, 6})
	check("end-only", time.Time{}, time.Unix(2, 0).UTC(), []int{0})
	check("all", time.Time{}, time.Time{}, []int{0, 1, 3, 4, 5, 6})
	check("no-match", time.Unix(200, 0).UTC(), time.Unix(300, 0).UTC(), []int{})

	// Results stay in file order although 103.000003 (n=4) is followed by 100
	// (n=5) and 106 (n=6).
	got := idx.PacketNumbersBetween(time.Unix(100, 0).UTC(), time.Time{})
	want := []int{3, 4, 5, 6}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("file-order violation: got %v want %v", got, want)
		}
	}
}

// TestNgIndexOutOfRange verifies packet number bounds.
func TestNgIndexOutOfRange(t *testing.T) {
	raw, expected := buildIndexSample(t)
	idx := newSampleIndex(t, DefaultNgIndexOptions, raw)
	for _, n := range []int{-1, len(expected), 1 << 20} {
		if _, _, err := idx.ReadPacketData(n); !errors.Is(err, ErrNgPacketNumber) {
			t.Fatalf("ReadPacketData(%d) err = %v, want ErrNgPacketNumber", n, err)
		}
		if _, err := idx.Ref(n); !errors.Is(err, ErrNgPacketNumber) {
			t.Fatalf("Ref(%d) err = %v, want ErrNgPacketNumber", n, err)
		}
	}
}
