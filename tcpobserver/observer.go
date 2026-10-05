// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpobserver

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Half of the 32-bit TCP sequence space.  Two sequence numbers exactly this
// far apart cannot be ordered unambiguously.
const halfSpace = 1 << 31

// Bytes reported by the observer fall into one of these classes.
type ByteClass uint8

const (
	// ClassNew covers payload bytes never seen before in this direction.
	ClassNew ByteClass = iota + 1
	// ClassSame covers overlapping bytes equal to the first observation.
	ClassSame
	// ClassConflict covers overlapping bytes that disagree with the first
	// observation.  The first observation is retained as the reference.
	ClassConflict
	// ClassIndeterminate covers bytes at or before a released watermark:
	// they cannot be compared and must never be reported as new.
	ClassIndeterminate
)

func (c ByteClass) String() string {
	switch c {
	case ClassNew:
		return "new"
	case ClassSame:
		return "same"
	case ClassConflict:
		return "conflict"
	case ClassIndeterminate:
		return "indeterminate"
	default:
		return "unknown"
	}
}

// ErrAmbiguous is returned when a segment (or release target) sits exactly
// half the sequence space from the reference position or reaches beyond the
// supported comparison window, so its ordering cannot be decided.
var ErrAmbiguous = errors.New("tcpobserver: sequence number is ambiguous (half sequence space or beyond window)")

// ErrUnknownEndpoint is returned when a segment originates from an endpoint
// that is neither side of the observed connection.
var ErrUnknownEndpoint = errors.New("tcpobserver: segment endpoint is not one of the connection endpoints")

// ErrEqualEndpoints is returned when NewConnection is given two identical
// endpoints.
var ErrEqualEndpoints = errors.New("tcpobserver: connection endpoints must differ")

// Span describes a contiguous run of bytes from one observed segment.
// Ranges are expressed in absolute, wrapping uint32 sequence numbers with
// the usual TCP half-open convention [Start, End): Start is the sequence
// number of Data[0] and End is the first sequence number after the run.
type Span struct {
	Class ByteClass
	Start uint32
	End   uint32
	Data  []byte
}

// Conflict pairs an observed byte with the first byte seen at that position.
type Conflict struct {
	Start    uint32
	Observed []byte
	Baseline []byte
}

// Report is the result of observing one segment in one direction.
type Report struct {
	// Spans partition the segment payload (excluding the SYN/FIN sequence
	// positions) in sequence order.  A pure control segment yields nil.
	Spans []Span
	// Conflicts holds, in sequence order, every conflicting run.
	Conflicts []Conflict
}

func collect(spans []Span, want ByteClass) []byte {
	var out []byte
	for _, s := range spans {
		if s.Class == want {
			out = append(out, s.Data...)
		}
	}
	return out
}

// New returns the payload bytes classified as ClassNew.
func (r Report) New() []byte { return collect(r.Spans, ClassNew) }

// Same returns the overlapping payload bytes equal to the reference.
func (r Report) Same() []byte { return collect(r.Spans, ClassSame) }

// Indeterminate returns the payload bytes at or before a released watermark.
func (r Report) Indeterminate() []byte { return collect(r.Spans, ClassIndeterminate) }

// Segment is a direction-neutral, already decoded TCP segment.  Endpoint
// identifies the sender; use TCPEndpoint to build TCP-port endpoints.
type Segment struct {
	Endpoint gopacket.Endpoint
	Seq      uint32
	SYN      bool
	FIN      bool
	Payload  []byte
}

// TCPEndpoint builds a gopacket.Endpoint for a TCP port, matching the
// endpoints produced by (*layers.TCP).TransportFlow.
func TCPEndpoint(port layers.TCPPort) gopacket.Endpoint {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(port))
	return gopacket.NewEndpoint(layers.EndpointTCPPort, b[:])
}

// Connection observes a single TCP connection between two fixed endpoints.
// A Connection is not safe for concurrent use.
type Connection struct {
	dir [2]direction
}

// NewConnection creates an observer for one connection.  The two endpoints
// must differ; pass them in either order.  Create a new Connection whenever
// the connection is reused.
func NewConnection(a, b gopacket.Endpoint) (*Connection, error) {
	if a == b {
		return nil, ErrEqualEndpoints
	}
	c := &Connection{}
	c.dir[0].ep = a
	c.dir[1].ep = b
	return c, nil
}

func (c *Connection) index(ep gopacket.Endpoint) (int, bool) {
	if ep == c.dir[0].ep {
		return 0, true
	}
	if ep == c.dir[1].ep {
		return 1, true
	}
	return 0, false
}

// Observe feeds one decoded segment and returns its classification report.
// The segment is rejected (and no state changes) if its endpoint is unknown
// or if its bytes fall in the ambiguous half of the sequence space.
func (c *Connection) Observe(seg Segment) (*Report, error) {
	i, ok := c.index(seg.Endpoint)
	if !ok {
		return nil, ErrUnknownEndpoint
	}
	payload := append([]byte(nil), seg.Payload...)
	return c.dir[i].observe(seg.Seq, seg.SYN, seg.FIN, payload)
}

// ObserveTCP is a convenience wrapper around Observe for a fully decoded
// layers.TCP segment.
func (c *Connection) ObserveTCP(t *layers.TCP) (*Report, error) {
	return c.Observe(Segment{
		Endpoint: TCPEndpoint(t.SrcPort),
		Seq:      t.Seq,
		SYN:      t.SYN,
		FIN:      t.FIN,
		Payload:  t.Payload,
	})
}

// Release advances the watermark for the direction sent by ep: bytes with
// sequence number strictly before target no longer need overlap comparison.
// Their storage is freed, and any later arrival at those positions is
// reported as ClassIndeterminate.  Releasing a monotonically earlier target
// is a no-op.  It returns ErrAmbiguous if the target cannot be ordered.
func (c *Connection) Release(ep gopacket.Endpoint, target uint32) error {
	i, ok := c.index(ep)
	if !ok {
		return ErrUnknownEndpoint
	}
	return c.dir[i].release(target)
}

// chunk is a retained, contiguous run of reference bytes in coordinates
// relative to dir.base, stored in ascending order and never adjacent.
type chunk struct {
	start int64
	data  []byte
}

func (ch chunk) end() int64 { return ch.start + int64(len(ch.data)) }

// direction holds the independent sequence space of one endpoint's sends.
// Relative coordinate x maps to absolute sequence (base + x) mod 2^32.
// base is the comparison anchor and never moves backward; watermark is the
// released cutoff expressed as an absolute sequence.  Retained reference
// bytes satisfy rel(seq) >= rel(watermark); coordinates below the watermark
// are reported as indeterminate, never as new.
type direction struct {
	ep        gopacket.Endpoint
	base      uint32
	watermark uint32
	hasBase   bool
	hasMark   bool
	chunks    []chunk
}

// rel maps an absolute sequence number onto a signed coordinate relative to
// the active base.  It returns ok=false exactly when the result lies on or
// beyond either end of the unambiguous window.
func (d *direction) rel(abs uint32) (int64, bool) {
	x := int64(int32(abs - d.base))
	if x <= -halfSpace || x >= halfSpace {
		return 0, false
	}
	return x, true
}

// fwd is the signed forward distance from ref to abs in sequence space,
// valid throughout (-2^31, 2^31).  ok=false at the exact half-space points.
func fwd(ref, abs uint32) (int64, bool) {
	x := int64(int32(abs - ref))
	if x <= -halfSpace || x >= halfSpace {
		return 0, false
	}
	return x, true
}

func (d *direction) observe(seq uint32, syn, fin bool, payload []byte) (*Report, error) {
	dataStart := seq
	if syn {
		dataStart = seq + 1 // SYN consumes one sequence number, no payload.
	}

	if !d.hasBase {
		d.base = dataStart
		d.hasBase = true
	}

	s, ok := d.rel(dataStart)
	e := s + int64(len(payload))
	if !ok || e > halfSpace {
		// Outside the anchor window.  When a watermark exists, data wholly at
		// or before it is aged out; anything that could lie forward is
		// genuinely ambiguous.
		if d.hasMark {
			ds, dsOK := fwd(d.watermark, dataStart)
			if dsOK && ds+int64(len(payload)) <= 0 {
				return d.allIndeterminate(payload, dataStart), nil
			}
		}
		return nil, ErrAmbiguous
	}
	if fin {
		// FIN occupies the single sequence number after the payload and must
		// itself sit inside the unambiguous window.
		if _, ok := d.rel(dataStart + uint32(len(payload))); !ok {
			return nil, ErrAmbiguous
		}
	}

	rep := &Report{}
	if len(payload) == 0 {
		return rep, nil
	}

	// Anything at or before the released watermark is indeterminate.
	mark := int64(-halfSpace) - 1
	if mw, ok := d.rel(d.watermark); d.hasMark && ok {
		mark = mw
	}

	// Build a class vector for each payload byte, comparing against retained
	// reference bytes.  Negative coordinates are below the watermark.
	classes := make([]ByteClass, len(payload))
	idx := 0
	for i := range payload {
		pos := s + int64(i)
		for idx < len(d.chunks) && d.chunks[idx].end() <= pos {
			idx++
		}
		switch {
		case pos < mark:
			classes[i] = ClassIndeterminate
		case idx < len(d.chunks) && pos >= d.chunks[idx].start:
			off := int(pos - d.chunks[idx].start)
			if payload[i] == d.chunks[idx].data[off] {
				classes[i] = ClassSame
			} else {
				classes[i] = ClassConflict
			}
		default:
			classes[i] = ClassNew
		}
	}

	// Turn the class vector into maximal spans and gather conflicts.
	type run struct {
		class ByteClass
		start int
		end   int
	}
	var runs []run
	for i := 0; i < len(payload); {
		j := i + 1
		for j < len(payload) && classes[j] == classes[i] {
			j++
		}
		runs = append(runs, run{classes[i], i, j})
		i = j
	}

	var newRuns []chunk
	for _, r := range runs {
		absStart := d.base + uint32(s+int64(r.start))
		absEnd := d.base + uint32(s+int64(r.end))
		data := append([]byte(nil), payload[r.start:r.end]...)
		rep.Spans = append(rep.Spans, Span{
			Class: r.class,
			Start: absStart,
			End:   absEnd,
			Data:  data,
		})
		if r.class == ClassNew {
			newRuns = append(newRuns, chunk{start: s + int64(r.start), data: data})
		}
		if r.class == ClassConflict {
			rep.Conflicts = append(rep.Conflicts, d.conflictFor(s+int64(r.start), data))
		}
	}

	if len(newRuns) > 0 {
		d.merge(newRuns)
	}
	return rep, nil
}

// conflictFor slices the retained baseline bytes overlapping an observed run
// starting at relative coordinate start.
func (d *direction) allIndeterminate(payload []byte, dataStart uint32) *Report {
	r := &Report{}
	if len(payload) > 0 {
		r.Spans = []Span{{
			Class: ClassIndeterminate,
			Start: dataStart,
			End:   dataStart + uint32(len(payload)),
			Data:  append([]byte(nil), payload...),
		}}
	}
	return r
}

func (d *direction) conflictFor(start int64, observed []byte) Conflict {
	baseline := make([]byte, len(observed))
	ci := 0
	for _, ch := range d.chunks {
		for ci < len(observed) && start+int64(ci) < ch.start {
			ci++
		}
		for ci < len(observed) {
			pos := start + int64(ci)
			if pos >= ch.end() {
				break
			}
			baseline[ci] = ch.data[pos-ch.start]
			ci++
		}
	}
	return Conflict{
		Start:    d.base + uint32(start),
		Observed: append([]byte(nil), observed...),
		Baseline: baseline,
	}
}

// merge inserts new (disjoint, positive-coordinate) chunks, coalescing with
// any neighbors they now adjoin.
func (d *direction) merge(ins []chunk) {
	merged := make([]chunk, 0, len(d.chunks)+len(ins))
	i, j := 0, 0
	for i < len(d.chunks) || j < len(ins) {
		var cur chunk
		if j >= len(ins) || (i < len(d.chunks) && d.chunks[i].start < ins[j].start) {
			cur = d.chunks[i]
			i++
		} else {
			cur = ins[j]
			j++
		}
		if n := len(merged); n > 0 && merged[n-1].end() >= cur.start {
			prev := &merged[n-1]
			if cur.end() > prev.end() {
				prev.data = append(prev.data, cur.data[prev.end()-cur.start:]...)
			}
		} else {
			merged = append(merged, cur)
		}
	}
	d.chunks = merged
}

func (d *direction) release(target uint32) error {
	if !d.hasBase {
		// Nothing observed yet: seed the anchor and watermark together so
		// future segments are compared against the released cutoff.
		d.base = target
		d.watermark = target
		d.hasBase = true
		d.hasMark = true
		return nil
	}
	t, ok := d.rel(target)
	if !ok {
		return ErrAmbiguous
	}
	if d.hasMark {
		if cur, _ := d.rel(d.watermark); t <= cur {
			return nil // Watermarks only move forward.
		}
	}
	d.watermark = target
	d.hasMark = true

	kept := d.chunks[:0]
	for i := range d.chunks {
		ch := d.chunks[i]
		if ch.end() <= t {
			continue // Fully released.
		}
		if ch.start < t {
			// Trim the released prefix; copy so backing storage is freed.
			drop := int(t - ch.start)
			ch.data = append([]byte(nil), ch.data[drop:]...)
			ch.start = t
		}
		kept = append(kept, ch)
	}
	d.chunks = kept
	return nil
}
