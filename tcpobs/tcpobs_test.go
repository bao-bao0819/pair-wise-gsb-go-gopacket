package tcpobs

import (
	"errors"
	"math/rand"
	"net/netip"
	"reflect"
	"testing"
)

var (
	epA = Endpoint{Addr: netip.MustParseAddr("192.0.2.1"), Port: 49152}
	epB = Endpoint{Addr: netip.MustParseAddr("192.0.2.2"), Port: 80}
	epC = Endpoint{Addr: netip.MustParseAddr("192.0.2.3"), Port: 443}
)

func aseg(seq uint32, payload string) Segment {
	return Segment{From: epA, Seq: seq, Payload: []byte(payload)}
}

func iv(start uint32, s string) Interval {
	return Interval{Start: start, Bytes: []byte(s)}
}

func mustObserve(t *testing.T, o *Observer, s Segment) Report {
	t.Helper()
	r, err := o.Observe(s)
	if err != nil {
		t.Fatalf("Observe(%+v): %v", s, err)
	}
	return r
}

func checkReport(t *testing.T, r Report, new, retrans, conflict, unknown []Interval) {
	t.Helper()
	for _, c := range []struct {
		what string
		got  []Interval
		want []Interval
	}{
		{"New", r.New, new},
		{"Retrans", r.Retrans, retrans},
		{"Conflict", r.Conflict, conflict},
		{"Unknown", r.Unknown, unknown},
	} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.what, c.got, c.want)
		}
	}
}

func retainedBytes(d *dirState) int {
	n := 0
	for _, iv := range d.ivs {
		n += len(iv.data)
	}
	return n
}

func TestWraparound(t *testing.T) {
	o := NewObserver(epA, epB)
	r := mustObserve(t, o, aseg(0xFFFFFFFE, "abcd"))
	checkReport(t, r, []Interval{iv(0xFFFFFFFE, "abcd")}, nil, nil, nil)

	r = mustObserve(t, o, aseg(1, "dEF"))
	checkReport(t, r, []Interval{iv(2, "EF")}, []Interval{iv(1, "d")}, nil, nil)
}

func TestPartialOverlapAcrossTwoIntervals(t *testing.T) {
	o := NewObserver(epA, epB)
	mustObserve(t, o, aseg(10, "AAAAA"))
	mustObserve(t, o, aseg(20, "BBBBB"))
	// Straddles the tail of the first interval, the hole, and the head
	// of the second interval.
	r := mustObserve(t, o, aseg(12, "AAAcccccBB"))
	checkReport(t, r,
		[]Interval{iv(15, "ccccc")},
		[]Interval{iv(12, "AAA"), iv(20, "BB")},
		nil, nil)
}

func TestHoleThenFill(t *testing.T) {
	o := NewObserver(epA, epB)
	mustObserve(t, o, aseg(10, "AAAAA"))
	mustObserve(t, o, aseg(20, "BBBBB"))
	r := mustObserve(t, o, aseg(15, "ccccc"))
	checkReport(t, r, []Interval{iv(15, "ccccc")}, nil, nil, nil)

	d := &o.dirs[AtoB]
	if len(d.ivs) != 1 {
		t.Fatalf("expected intervals to merge into one, got %d", len(d.ivs))
	}
	if got := string(d.ivs[0].data); got != "AAAAAcccccBBBBB" {
		t.Fatalf("merged baseline = %q", got)
	}
	// The merged range is now fully known.
	r = mustObserve(t, o, aseg(10, "AAAAAcccccBBBBB"))
	checkReport(t, r, nil, []Interval{iv(10, "AAAAAcccccBBBBB")}, nil, nil)
}

func TestBothDirectionsSameSeq(t *testing.T) {
	o := NewObserver(epA, epB)
	r := mustObserve(t, o, aseg(100, "hello"))
	checkReport(t, r, []Interval{iv(100, "hello")}, nil, nil, nil)

	// The same sequence numbers on the reverse direction live in an
	// independent sequence space.
	r = mustObserve(t, o, Segment{From: epB, Seq: 100, Payload: []byte("world")})
	checkReport(t, r, []Interval{iv(100, "world")}, nil, nil, nil)

	r = mustObserve(t, o, Segment{From: epB, Seq: 100, Payload: []byte("world")})
	checkReport(t, r, nil, []Interval{iv(100, "world")}, nil, nil)
}

func TestSYNWithData(t *testing.T) {
	o := NewObserver(epA, epB)
	// SYN consumes the first sequence number; payload starts at Seq+1.
	r := mustObserve(t, o, Segment{From: epA, Seq: 100, SYN: true, Payload: []byte("abc")})
	checkReport(t, r, []Interval{iv(101, "abc")}, nil, nil, nil)

	// The SYN's own sequence number is not payload baseline.
	r = mustObserve(t, o, aseg(100, "X"))
	checkReport(t, r, []Interval{iv(100, "X")}, nil, nil, nil)

	r = mustObserve(t, o, aseg(101, "abc"))
	checkReport(t, r, nil, []Interval{iv(101, "abc")}, nil, nil)
}

func TestFINOccupiesSeqButIsNotPayload(t *testing.T) {
	o := NewObserver(epA, epB)
	r := mustObserve(t, o, Segment{From: epA, Seq: 200, FIN: true, Payload: []byte("ab")})
	checkReport(t, r, []Interval{iv(200, "ab")}, nil, nil, nil)

	// The FIN's sequence number (202) carries no baseline byte.
	r = mustObserve(t, o, aseg(202, "Z"))
	checkReport(t, r, []Interval{iv(202, "Z")}, nil, nil, nil)
}

func TestConflictDoesNotOverwriteBaseline(t *testing.T) {
	o := NewObserver(epA, epB)
	mustObserve(t, o, aseg(10, "abc"))

	r := mustObserve(t, o, aseg(10, "aBc"))
	checkReport(t, r, nil,
		[]Interval{iv(10, "a"), iv(12, "c")},
		[]Interval{iv(11, "B")}, nil)

	// The first observation is still the baseline.
	r = mustObserve(t, o, aseg(10, "abc"))
	checkReport(t, r, nil, []Interval{iv(10, "abc")}, nil, nil)
}

func TestWatermark(t *testing.T) {
	o := NewObserver(epA, epB)
	mustObserve(t, o, aseg(10, "abcdefghij"))
	if err := o.Release(epA, 15); err != nil {
		t.Fatalf("Release: %v", err)
	}
	d := &o.dirs[AtoB]
	if got := retainedBytes(d); got != 5 {
		t.Fatalf("retained bytes after release = %d, want 5", got)
	}

	// Bytes before the watermark can no longer be judged.
	r := mustObserve(t, o, aseg(10, "abcdefghij"))
	checkReport(t, r, nil, []Interval{iv(15, "fghij")}, nil,
		[]Interval{iv(10, "abcde")})

	// Data arriving before the watermark is not stored as new either.
	r = mustObserve(t, o, aseg(12, "XY"))
	checkReport(t, r, nil, nil, nil, []Interval{iv(12, "XY")})
	if got := retainedBytes(d); got != 5 {
		t.Fatalf("retained bytes = %d, want 5", got)
	}
	if len(d.ivs) != 1 || d.ivs[0].start != 5 {
		t.Fatalf("unexpected retained intervals: %+v", d.ivs)
	}

	// Releasing at or before the watermark is a no-op.
	if err := o.Release(epA, 12); err != nil {
		t.Fatalf("Release backwards: %v", err)
	}
	if got := retainedBytes(d); got != 5 {
		t.Fatalf("retained bytes = %d, want 5", got)
	}
}

func TestReleaseBeforeAnyData(t *testing.T) {
	o := NewObserver(epA, epB)
	if err := o.Release(epA, 100); err != nil {
		t.Fatalf("Release: %v", err)
	}
	r := mustObserve(t, o, aseg(90, "abc"))
	checkReport(t, r, nil, nil, nil, []Interval{iv(90, "abc")})

	r = mustObserve(t, o, aseg(100, "ab"))
	checkReport(t, r, []Interval{iv(100, "ab")}, nil, nil, nil)
}

func TestAmbiguousSequence(t *testing.T) {
	// Exactly half a sequence space away from a point window.
	o := NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, ""))
	if _, err := o.Observe(aseg(1000+(1<<31), "x")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}

	// Tie: equidistant from both edges of a non-empty window.
	o = NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, "0123456789"))
	if _, err := o.Observe(aseg(1000+5+(1<<31), "x")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}

	// One byte closer resolves fine.
	o = NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, "0123456789"))
	if _, err := o.Observe(aseg(1000+5+(1<<31)-1, "x")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A segment whose far end reaches beyond the supported window.
	o = NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, "0123456789"))
	if _, err := o.Observe(aseg(1000+(1<<31)-5, "01234567890123456789")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
	// A slightly shorter segment at the same spot is still inside.
	o = NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, "0123456789"))
	if _, err := o.Observe(aseg(1000+(1<<31)-5, "01234567890123")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Release is subject to the same check.
	o = NewObserver(epA, epB)
	mustObserve(t, o, aseg(1000, "0123456789"))
	if err := o.Release(epA, 1000+5+(1<<31)); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("expected ErrAmbiguous, got %v", err)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	o := NewObserver(epA, epB)
	if _, err := o.Observe(aseg(1, "x").from(epC)); !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("expected ErrUnknownEndpoint, got %v", err)
	}
	if err := o.Release(epC, 1); !errors.Is(err, ErrUnknownEndpoint) {
		t.Fatalf("expected ErrUnknownEndpoint, got %v", err)
	}
}

func (s Segment) from(e Endpoint) Segment { s.From = e; return s }

// The remainder of this file cross-checks the observer against a small
// byte-by-byte reference model on random out-of-order segment sequences.

const (
	clsNew = iota
	clsRetrans
	clsConflict
	clsUnknown
)

// refDir is the reference model: one map entry per retained payload byte.
type refDir struct {
	init   bool
	anchor uint32
	wm     int64
	hasWM  bool
	base   map[int64]byte
}

func (r *refDir) observe(s Segment) []int {
	if !r.init {
		r.init = true
		r.anchor = s.Seq
	}
	off := int64(int32(s.Seq - r.anchor))
	if s.SYN {
		off++
	}
	classes := make([]int, len(s.Payload))
	for i, b := range s.Payload {
		o := off + int64(i)
		switch {
		case r.hasWM && o < r.wm:
			classes[i] = clsUnknown
		default:
			if base, ok := r.base[o]; ok {
				if base == b {
					classes[i] = clsRetrans
				} else {
					classes[i] = clsConflict
				}
			} else {
				classes[i] = clsNew
				r.base[o] = b
			}
		}
	}
	return classes
}

func (r *refDir) release(seq uint32) {
	if !r.init {
		r.init = true
		r.anchor = seq
	}
	off := int64(int32(seq - r.anchor))
	if r.hasWM && off <= r.wm {
		return
	}
	r.wm, r.hasWM = off, true
	for o := range r.base {
		if o < off {
			delete(r.base, o)
		}
	}
}

type pastSeg struct {
	off     int64
	payload []byte
}

type genDir struct {
	init   bool
	anchor uint32
	hi     int64
	wm     int64
	past   []pastSeg
}

type op struct {
	seg     Segment
	release bool
	dir     int
}

// genScript builds a random script of segments and watermark releases.
// All offsets stay close to each direction's anchor so no operation is
// ambiguous.
func genScript(rng *rand.Rand, n int) []op {
	var ops []op
	var gs [2]genDir
	for len(ops) < n {
		dirIdx := rng.Intn(2)
		g := &gs[dirIdx]
		from := epA
		if dirIdx == 1 {
			from = epB
		}
		if !g.init {
			g.init = true
			switch rng.Intn(3) {
			case 0:
				g.anchor = uint32(rng.Intn(1 << 20))
			case 1:
				g.anchor = 0xFFFFF000 + uint32(rng.Intn(0x1000))
			default:
				g.anchor = rng.Uint32()
			}
		}
		if g.hi > 20 && rng.Intn(20) == 0 {
			g.wm += int64(rng.Intn(40))
			ops = append(ops, op{release: true, dir: dirIdx,
				seg: Segment{From: from, Seq: g.anchor + uint32(g.wm)}})
			continue
		}
		var off int64
		var payload []byte
		if len(g.past) > 0 && rng.Intn(10) < 4 {
			// Resend a mutated copy of an older segment.
			p := g.past[rng.Intn(len(g.past))]
			off = p.off + int64(rng.Intn(7)) - 3
			payload = append([]byte(nil), p.payload...)
			for i := range payload {
				if rng.Intn(4) == 0 {
					payload[i] = byte(rng.Intn(256))
				}
			}
		} else {
			off = g.hi - 8 + int64(rng.Intn(20))
			payload = make([]byte, rng.Intn(13))
			rng.Read(payload)
		}
		if off < -20 {
			off = -20
		}
		s := Segment{From: from, Seq: g.anchor + uint32(off), Payload: payload}
		if rng.Intn(20) == 0 {
			s.SYN = true
		}
		if rng.Intn(20) == 0 {
			s.FIN = true
		}
		ops = append(ops, op{seg: s, dir: dirIdx})
		poff := off
		total := int64(len(payload))
		if s.SYN {
			poff++
			total++
		}
		if s.FIN {
			total++
		}
		g.past = append(g.past, pastSeg{off: poff, payload: payload})
		if end := off + total; end > g.hi {
			g.hi = end
		}
	}
	return ops
}

// expandReport flattens a report into one class per payload byte and
// verifies the report covers the payload exactly once.
func expandReport(t *testing.T, s Segment, r Report) []int {
	t.Helper()
	classes := make([]int, len(s.Payload))
	for i := range classes {
		classes[i] = -1
	}
	startSeq := s.Seq
	if s.SYN {
		startSeq++
	}
	fill := func(ivs []Interval, cls int) {
		for _, iv := range ivs {
			base := int(int32(iv.Start - startSeq))
			for j, b := range iv.Bytes {
				idx := base + j
				if idx < 0 || idx >= len(classes) {
					t.Fatalf("report interval %+v outside payload", iv)
				}
				if classes[idx] != -1 {
					t.Fatalf("payload byte %d classified twice", idx)
				}
				if b != s.Payload[idx] {
					t.Fatalf("report byte %d = %#x, payload has %#x", idx, b, s.Payload[idx])
				}
				classes[idx] = cls
			}
		}
	}
	fill(r.New, clsNew)
	fill(r.Retrans, clsRetrans)
	fill(r.Conflict, clsConflict)
	fill(r.Unknown, clsUnknown)
	for i, c := range classes {
		if c == -1 {
			t.Fatalf("payload byte %d not classified", i)
		}
	}
	return classes
}

// checkRetained verifies the observer's retained baseline matches the
// reference model byte for byte, and that intervals stay merged.  The
// retained set must track the reference's live map, so memory follows
// retained intervals and payload, not the sequence space size.
func checkRetained(t *testing.T, d *dirState, r *refDir) {
	t.Helper()
	count := 0
	for i, iv := range d.ivs {
		if i > 0 && d.ivs[i-1].end() >= iv.start {
			t.Fatalf("intervals not disjoint and merged: %+v", d.ivs)
		}
		for j, b := range iv.data {
			o := iv.start + int64(j)
			rb, ok := r.base[o]
			if !ok {
				t.Fatalf("observer retains offset %d the reference dropped", o)
			}
			if rb != b {
				t.Fatalf("baseline at %d = %#x, reference has %#x", o, b, rb)
			}
			count++
		}
	}
	if count != len(r.base) {
		t.Fatalf("observer retains %d bytes, reference has %d", count, len(r.base))
	}
}

func runScript(t *testing.T, ops []op, checkRef bool) []Report {
	t.Helper()
	o := NewObserver(epA, epB)
	refs := [2]refDir{
		{base: map[int64]byte{}},
		{base: map[int64]byte{}},
	}
	var reports []Report
	for i, op := range ops {
		if op.release {
			if err := o.Release(op.seg.From, op.seg.Seq); err != nil {
				t.Fatalf("op %d: Release: %v", i, err)
			}
			refs[op.dir].release(op.seg.Seq)
			continue
		}
		rep, err := o.Observe(op.seg)
		if err != nil {
			t.Fatalf("op %d: Observe(%+v): %v", i, op.seg, err)
		}
		reports = append(reports, rep)
		if checkRef {
			want := refs[op.dir].observe(op.seg)
			if got := expandReport(t, op.seg, rep); !reflect.DeepEqual(got, want) {
				t.Fatalf("op %d: classes got %v, want %v (seg %+v)", i, got, want, op.seg)
			}
			checkRetained(t, &o.dirs[op.dir], &refs[op.dir])
		}
	}
	return reports
}

func TestRandomAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for trial := 0; trial < 60; trial++ {
		ops := genScript(rng, 150)
		first := runScript(t, ops, true)
		// A fixed input sequence must report identically every time.
		second := runScript(t, ops, false)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("trial %d: same script produced different reports", trial)
		}
	}
}
