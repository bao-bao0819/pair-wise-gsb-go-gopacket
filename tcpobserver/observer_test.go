// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpobserver

import (
	"bytes"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func epOf(port uint16) gopacket.Endpoint {
	return TCPEndpoint(layers.TCPPort(port))
}

func newConn(t *testing.T) *Connection {
	t.Helper()
	c, err := NewConnection(epOf(1000), epOf(2000))
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	return c
}

func classVec(r *Report) []ByteClass {
	var out []ByteClass
	for _, s := range r.Spans {
		for range s.Data {
			out = append(out, s.Class)
		}
	}
	return out
}

func expectClasses(t *testing.T, r *Report, want []ByteClass) {
	t.Helper()
	got := classVec(r)
	if len(got) != len(want) {
		t.Fatalf("class len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("class[%d] = %v, want %v (got %v want %v)", i, got[i], want[i], got, want)
		}
	}
}

// ob observes a segment, failing the test on error and returning the report.
func ob(t *testing.T, c *Connection, s Segment) *Report {
	t.Helper()
	r, err := c.Observe(s)
	if err != nil {
		t.Fatalf("observe seq=%#x: %v", s.Seq, err)
	}
	return r
}

// TestWraparound keeps payloads tiny while crossing the 2^32 boundary.
func TestWraparound(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)

	// SYN at 0xFFFFFFFE; data starts at 0xFFFFFFFF.
	r := ob(t, c, Segment{Endpoint: a, Seq: 0xFFFFFFFE, SYN: true, Payload: []byte{0xAA, 0xBB}})
	expectClasses(t, r, []ByteClass{ClassNew, ClassNew})
	if r.Spans[0].Start != 0xFFFFFFFF {
		t.Fatalf("start = %#x want 0xFFFFFFFF", r.Spans[0].Start)
	}

	// Fill seq 1 (seq 0 wrapped to 0) and seq 2.
	r = ob(t, c, Segment{Endpoint: a, Seq: 1, Payload: []byte{0x22}})
	expectClasses(t, r, []ByteClass{ClassNew})

	// Replay [0xFFFFFFFF,3): same/same/same/new.
	r = ob(t, c, Segment{Endpoint: a, Seq: 0xFFFFFFFF, Payload: []byte{0xAA, 0xBB, 0x22, 0x33}})
	expectClasses(t, r, []ByteClass{ClassSame, ClassSame, ClassSame, ClassNew})
	if r.Spans[0].Start != 0xFFFFFFFF || r.Spans[1].Start != 2 {
		t.Fatalf("span boundaries wrong: %+v", r.Spans)
	}
}

// TestPartialOverlapAcrossTwoOld sends a new segment bridging two old blocks.
func TestPartialOverlapAcrossTwoOld(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte{0, 1}})
	ob(t, c, Segment{Endpoint: a, Seq: 4, Payload: []byte{4, 5}})

	r := ob(t, c, Segment{Endpoint: a, Seq: 1, Payload: []byte{1, 9, 9, 4, 5}})
	expectClasses(t, r, []ByteClass{
		ClassSame,
		ClassNew, ClassNew,
		ClassSame, ClassSame,
	})
}

// TestHoleThenFill sends data out of order and closes the gap.
func TestHoleThenFill(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	ob(t, c, Segment{Endpoint: a, Seq: 10, Payload: []byte("CD")})
	r := ob(t, c, Segment{Endpoint: a, Seq: 8, Payload: []byte("AB")})
	expectClasses(t, r, []ByteClass{ClassNew, ClassNew})

	r = ob(t, c, Segment{Endpoint: a, Seq: 8, Payload: []byte("ABCD")})
	expectClasses(t, r, []ByteClass{ClassSame, ClassSame, ClassSame, ClassSame})
	if !bytes.Equal(r.Same(), []byte("ABCD")) {
		t.Fatalf("same = %q", r.Same())
	}
}

// TestBothDirectionsSameSequence verifies independent sequence spaces.
func TestBothDirectionsSameSequence(t *testing.T) {
	c := newConn(t)
	a, b := epOf(1000), epOf(2000)
	ra := ob(t, c, Segment{Endpoint: a, Seq: 5, Payload: []byte("XY")})
	rb := ob(t, c, Segment{Endpoint: b, Seq: 5, Payload: []byte("XY")})
	expectClasses(t, ra, []ByteClass{ClassNew, ClassNew})
	expectClasses(t, rb, []ByteClass{ClassNew, ClassNew})

	ra = ob(t, c, Segment{Endpoint: a, Seq: 5, Payload: []byte("XY")})
	rb = ob(t, c, Segment{Endpoint: b, Seq: 5, Payload: []byte("XY")})
	expectClasses(t, ra, []ByteClass{ClassSame, ClassSame})
	expectClasses(t, rb, []ByteClass{ClassSame, ClassSame})
}

// TestSYNData confirms SYN consumes a sequence number but bytes are payload.
func TestSYNData(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	r := ob(t, c, Segment{Endpoint: a, Seq: 1000, SYN: true, Payload: []byte{7, 8}})
	expectClasses(t, r, []ByteClass{ClassNew, ClassNew})
	if r.Spans[0].Start != 1001 {
		t.Fatalf("data start = %d want 1001", r.Spans[0].Start)
	}
	r = ob(t, c, Segment{Endpoint: a, Seq: 1001, Payload: []byte{7, 8}})
	expectClasses(t, r, []ByteClass{ClassSame, ClassSame})
}

// TestConflictKeepsBaseline ensures the first observation is the reference.
func TestConflictKeepsBaseline(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte("ABCD")})
	r := ob(t, c, Segment{Endpoint: a, Seq: 1, Payload: []byte("xy")})
	expectClasses(t, r, []ByteClass{ClassConflict, ClassConflict})
	if len(r.Conflicts) != 1 {
		t.Fatalf("conflicts = %d want 1", len(r.Conflicts))
	}
	cf := r.Conflicts[0]
	if cf.Start != 1 || !bytes.Equal(cf.Observed, []byte("xy")) ||
		!bytes.Equal(cf.Baseline, []byte("BC")) {
		t.Fatalf("conflict = %+v baseline %q", cf, cf.Baseline)
	}
	// Original still wins when observed a third time.
	r = ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte("ABCD")})
	expectClasses(t, r, []ByteClass{ClassSame, ClassSame, ClassSame, ClassSame})
}

// TestReleaseWatermark frees old bytes and marks later arrivals indeterminate.
func TestReleaseWatermark(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte{0, 1, 2, 3, 4}})
	if err := c.Release(a, 3); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Segment [2,5): bytes 2 released => indeterminate; 3,4 same.
	r := ob(t, c, Segment{Endpoint: a, Seq: 2, Payload: []byte{2, 3, 4}})
	expectClasses(t, r, []ByteClass{ClassIndeterminate, ClassSame, ClassSame})
	if n := retainedBytes(&c.dir[0]); n != 2 {
		t.Fatalf("retained bytes = %d want 2", n)
	}
	// A fully released byte can never be reported as new.
	r = ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte{9, 9}})
	expectClasses(t, r, []ByteClass{ClassIndeterminate, ClassIndeterminate})
	// Releasing earlier target is a no-op.
	if err := c.Release(a, 1); err != nil {
		t.Fatalf("release earlier: %v", err)
	}
	if n := retainedBytes(&c.dir[0]); n != 2 {
		t.Fatalf("retained bytes after no-op = %d want 2", n)
	}
}

// TestAmbiguity exercises the exact half-space and over-window boundaries.
func TestAmbiguity(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte{1}})

	// A new segment exactly half the sequence space away is ambiguous.
	if _, err := c.Observe(Segment{Endpoint: a, Seq: halfSpace, Payload: []byte{2}}); err != ErrAmbiguous {
		t.Fatalf("half-space err = %v want ErrAmbiguous", err)
	}
	// Just inside is fine.
	ob(t, c, Segment{Endpoint: a, Seq: halfSpace - 1, Payload: []byte{2}})

	// A segment whose payload reaches the boundary is ambiguous.
	if _, err := c.Observe(Segment{Endpoint: a, Seq: halfSpace - 1, Payload: []byte{3, 4}}); err != ErrAmbiguous {
		t.Fatalf("over-window err = %v want ErrAmbiguous", err)
	}

	// Release target exactly half-space away is ambiguous.
	if err := c.Release(a, uint32(halfSpace)); err != ErrAmbiguous {
		t.Fatalf("release err = %v want ErrAmbiguous", err)
	}

	// Unknown endpoint is rejected.
	if _, err := c.Observe(Segment{Endpoint: epOf(9999), Seq: 0}); err != ErrUnknownEndpoint {
		t.Fatalf("unknown endpoint err = %v", err)
	}
}

func retainedBytes(d *direction) int {
	n := 0
	for _, ch := range d.chunks {
		n += len(ch.data)
	}
	return n
}

// TestAgingRecenter advances the watermark past half a window and keeps
// observing, ensuring the anchor recenters and comparisons stay correct.
func TestAgingRecenter(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)

	// Seed a few bytes near the start of the 32-bit space.
	ob(t, c, Segment{Endpoint: a, Seq: 0, Payload: []byte{0x10}})
	ob(t, c, Segment{Endpoint: a, Seq: 1, Payload: []byte{0x11}})

	// Advance the watermark by more than half the space; the byte at seq 0 is
	// dropped and later arrivals in that region are aged out.
	big := uint32(halfSpace - 4)
	if err := c.Release(a, big); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Fresh bytes well past the old anchor are new and not ambiguous.
	r := ob(t, c, Segment{Endpoint: a, Seq: big, Payload: []byte{0x20, 0x21}})
	expectClasses(t, r, []ByteClass{ClassNew, ClassNew})
	// Retransmission compares cleanly against the recentered window.
	r = ob(t, c, Segment{Endpoint: a, Seq: big, Payload: []byte{0x20, 0x21}})
	expectClasses(t, r, []ByteClass{ClassSame, ClassSame})
	// Bytes in the released region are indeterminate.
	r = ob(t, c, Segment{Endpoint: a, Seq: big - 2, Payload: []byte{0, 1}})
	expectClasses(t, r, []ByteClass{ClassIndeterminate, ClassIndeterminate})
}

// TestStability replays the same fixed input sequence and expects identical
// reports.
func TestStability(t *testing.T) {
	seq := []Segment{
		{Endpoint: epOf(1000), Seq: 4, Payload: []byte{4, 5}},
		{Endpoint: epOf(1000), Seq: 0, Payload: []byte{0, 1}},
		{Endpoint: epOf(2000), Seq: 0, Payload: []byte{9}},
		{Endpoint: epOf(1000), Seq: 2, Payload: []byte{2, 3}},
		{Endpoint: epOf(1000), Seq: 1, Payload: []byte{1, 2}},
	}
	first := runScenario(t, seq)
	for trial := 0; trial < 3; trial++ {
		got := runScenario(t, seq)
		if !bytes.Equal(got, first) {
			t.Fatalf("trial %d reports differ:\n%s\nvs\n%s", trial, got, first)
		}
	}
}

func runScenario(t *testing.T, seq []Segment) []byte {
	t.Helper()
	c := newConn(t)
	var buf bytes.Buffer
	for _, s := range seq {
		r, err := c.Observe(s)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		for _, sp := range r.Spans {
			buf.WriteByte(byte(sp.Class))
			buf.Write(sp.Data)
		}
		buf.WriteByte(0)
	}
	return buf.Bytes()
}
