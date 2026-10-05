// Package tcpobs provides a bidirectional TCP byte observer for offline
// traffic analysis.
//
// An Observer is created explicitly for a single connection, identified
// by its two endpoints.  The caller feeds already-decoded TCP segments
// into the observer, one at a time, and each Observe call reports how the
// segment's payload bytes relate to everything observed before on that
// direction: which bytes are new, which are identical retransmissions,
// which conflict with previously observed bytes (and where), and which
// can no longer be judged because they precede the caller-supplied
// watermark.
//
// The observer does not establish real connections, does not pick a
// "winning" payload among conflicting bytes, and does not use a clock to
// guess connection lifetimes; connection reuse is handled by simply
// creating a new Observer.  The first byte observed at a sequence
// position is the comparison baseline and is never overwritten by later
// conflicting bytes, so a fixed input sequence of segments always
// produces the same reports (reordering the input may legitimately change
// the new/retransmission classification).
//
// Each direction maintains its own sequence space with uint32 wraparound.
// SYN and FIN consume sequence numbers but are not payload.  Memory grows
// with the retained intervals and their payload bytes, not with the size
// of the sequence space.
package tcpobs

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

const (
	// halfSpace is half of the uint32 TCP sequence space.  Two positions
	// exactly half a sequence space apart cannot be ordered reliably.
	halfSpace = int64(1) << 31
	// fullSpace is the size of the uint32 TCP sequence space.
	fullSpace = int64(1) << 32
)

// Endpoint identifies one side of the observed connection.
type Endpoint struct {
	Addr netip.Addr
	Port uint16
}

// Direction identifies which way a segment travels through the connection.
type Direction int

const (
	// AtoB is the direction from the first endpoint to the second.
	AtoB Direction = iota
	// BtoA is the direction from the second endpoint to the first.
	BtoA
)

func (d Direction) String() string {
	if d == AtoB {
		return "AtoB"
	}
	return "BtoA"
}

// Interval is a run of consecutive payload bytes of a reported segment.
// Bytes aliases the segment's payload and stays valid until the caller
// reuses that buffer.
type Interval struct {
	// Start is the sequence number of the first byte of the run.
	Start uint32
	// Bytes are the segment's payload bytes in the run.
	Bytes []byte
}

// Report describes how one segment's payload relates to bytes observed
// earlier on the same direction.  Each category holds runs in increasing
// sequence order; together the four categories cover the whole payload
// exactly once.
type Report struct {
	// Dir is the direction the segment travelled.
	Dir Direction
	// New holds bytes never observed before; they become the new
	// baseline.
	New []Interval
	// Retrans holds bytes identical to the baseline.
	Retrans []Interval
	// Conflict holds bytes differing from the baseline.  The baseline is
	// not updated; choosing between conflicting payloads is left to the
	// caller.
	Conflict []Interval
	// Unknown holds bytes before the released watermark, which can no
	// longer be compared against anything and are never treated as new.
	Unknown []Interval
}

// Segment is a single decoded TCP segment presented to an Observer.
type Segment struct {
	// From is the endpoint that sent the segment; it must match one of
	// the endpoints passed to NewObserver.
	From Endpoint
	// Seq is the segment's TCP sequence number.
	Seq uint32
	// SYN and FIN consume one sequence number each but are not payload.
	// When SYN is set the payload starts at Seq+1.
	SYN, FIN bool
	// Payload is the segment's TCP payload.
	Payload []byte
}

// ErrAmbiguous is returned when a sequence number sits exactly half a
// sequence space away from the observer's reference window, or beyond the
// supported window, so its position cannot be resolved reliably.
var ErrAmbiguous = errors.New("tcpobs: ambiguous sequence position")

// ErrUnknownEndpoint is returned when a segment's sender matches neither
// endpoint of the connection.
var ErrUnknownEndpoint = errors.New("tcpobs: endpoint is not part of this connection")

// Observer watches the payload bytes of both directions of a single TCP
// connection.  It is not safe for concurrent use.
type Observer struct {
	a, b Endpoint
	dirs [2]dirState
}

// NewObserver creates an Observer for the connection between endpoints a
// and b.  The endpoints are unordered: whichever of them sends a segment
// first simply starts its direction's sequence space.
func NewObserver(a, b Endpoint) *Observer {
	return &Observer{a: a, b: b}
}

func (o *Observer) dirOf(from Endpoint) (Direction, error) {
	switch from {
	case o.a:
		return AtoB, nil
	case o.b:
		return BtoA, nil
	}
	return AtoB, ErrUnknownEndpoint
}

// Observe feeds one decoded segment into the observer and reports how its
// payload compares to previously observed bytes on the same direction.
func (o *Observer) Observe(seg Segment) (Report, error) {
	dir, err := o.dirOf(seg.From)
	if err != nil {
		return Report{}, err
	}
	return o.dirs[dir].observe(seg, dir)
}

// Release tells the observer that payload before seq (in from's sending
// direction) no longer needs to be compared, and drops the retained
// baseline bytes before it.  Bytes arriving before the watermark
// afterwards are reported as Unknown rather than New.  The watermark only
// moves forward; releasing at or before the current watermark is a
// no-op.
func (o *Observer) Release(from Endpoint, seq uint32) error {
	dir, err := o.dirOf(from)
	if err != nil {
		return err
	}
	return o.dirs[dir].release(seq)
}

// interval is a retained run of baseline bytes; the run covers the
// offsets [start, start+len(data)).
type interval struct {
	start int64 // offset relative to the direction's anchor
	data  []byte
}

func (iv interval) end() int64 { return iv.start + int64(len(iv.data)) }

// dirState tracks one direction's sequence space.  Sequence numbers are
// translated to int64 offsets relative to anchor, the first sequence
// number ever seen on the direction, so wraparound only has to be dealt
// with once, when a segment is positioned.
type dirState struct {
	init   bool
	anchor uint32
	lo, hi int64 // half-open window of positions ever occupied
	wm     int64 // release watermark
	hasWM  bool
	ivs    []interval // retained baseline: sorted, disjoint, non-adjacent
}

func (d *dirState) observe(seg Segment, dir Direction) (Report, error) {
	rep := Report{Dir: dir}
	total := len(seg.Payload)
	if seg.SYN {
		total++
	}
	if seg.FIN {
		total++
	}
	start, err := d.position(seg.Seq, total)
	if err != nil {
		return rep, err
	}
	pstart := start
	if seg.SYN {
		pstart++
	}
	if len(seg.Payload) > 0 {
		d.classify(pstart, seg.Payload, &rep)
	}
	return rep, nil
}

// position resolves seq to an offset, rejecting positions that are
// ambiguous relative to the current window, and grows the window to cover
// the totalLen sequence numbers the segment occupies.
func (d *dirState) position(seq uint32, totalLen int) (int64, error) {
	if !d.init {
		d.init = true
		d.anchor = seq
		d.lo, d.hi = 0, int64(totalLen)
		return 0, nil
	}
	start, err := d.resolve(seq)
	if err != nil {
		return 0, err
	}
	if totalLen > 0 {
		end := start + int64(totalLen)
		if end-1-d.hi >= halfSpace {
			return 0, fmt.Errorf("%w: seq %d length %d vs window [%d,%d]",
				ErrAmbiguous, seq, totalLen, d.lo, d.hi)
		}
		if start < d.lo {
			d.lo = start
		}
		if end > d.hi {
			d.hi = end
		}
	}
	return start, nil
}

// resolve maps seq to the offset closest to the current window.  A
// position exactly half a sequence space away from the window, or
// further, is ambiguous: it could equally be interpreted as lying on the
// other side of the sequence space.
func (d *dirState) resolve(seq uint32) (int64, error) {
	base := int64(int32(seq - d.anchor))
	mid := (d.lo + d.hi) / 2
	k0 := floorDiv(mid-base+halfSpace, fullSpace)
	best, bestDist := int64(0), int64(1)<<62
	tie := false
	for k := k0 - 1; k <= k0+1; k++ {
		cand := base + k*fullSpace
		var dist int64
		switch {
		case cand < d.lo:
			dist = d.lo - cand
		case cand > d.hi:
			dist = cand - d.hi
		}
		if dist < bestDist {
			best, bestDist, tie = cand, dist, false
		} else if dist == bestDist {
			tie = true
		}
	}
	if tie || bestDist >= halfSpace {
		return 0, fmt.Errorf("%w: seq %d vs window [%d,%d]",
			ErrAmbiguous, seq, d.lo, d.hi)
	}
	return best, nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// seq converts an offset back to a sequence number.
func (d *dirState) seq(off int64) uint32 { return d.anchor + uint32(off) }

// classify splits the payload at [start, start+len(payload)) into runs of
// unknown, retransmitted, conflicting and new bytes, appends them to rep,
// and merges the new bytes into the retained baseline.
func (d *dirState) classify(start int64, payload []byte, rep *Report) {
	end := start + int64(len(payload))
	slice := func(from, upto int64) []byte { return payload[from-start : upto-start] }
	i := sort.Search(len(d.ivs), func(i int) bool { return d.ivs[i].end() > start })
	var fresh []interval
	for pos := start; pos < end; {
		switch {
		case d.hasWM && pos < d.wm:
			// Retained intervals never reach below the watermark,
			// so the whole run up to it is unjudgeable.
			upto := min(end, d.wm)
			rep.Unknown = append(rep.Unknown, Interval{Start: d.seq(pos), Bytes: slice(pos, upto)})
			pos = upto
		case i < len(d.ivs) && d.ivs[i].start <= pos:
			iv := d.ivs[i]
			upto := min(end, iv.end())
			d.compare(rep, pos, slice(pos, upto), iv.data[pos-iv.start:upto-iv.start])
			pos = upto
			i++
		default:
			upto := end
			if i < len(d.ivs) && d.ivs[i].start < upto {
				upto = d.ivs[i].start
			}
			rep.New = append(rep.New, Interval{Start: d.seq(pos), Bytes: slice(pos, upto)})
			fresh = append(fresh, interval{start: pos, data: slice(pos, upto)})
			pos = upto
		}
	}
	for _, iv := range fresh {
		d.insert(iv.start, iv.data)
	}
}

// compare splits got into maximal runs of equal and differing bytes
// relative to the baseline and appends them to rep.
func (d *dirState) compare(rep *Report, pos int64, got, base []byte) {
	for i := 0; i < len(got); {
		j := i + 1
		same := got[i] == base[i]
		for j < len(got) && (got[j] == base[j]) == same {
			j++
		}
		iv := Interval{Start: d.seq(pos + int64(i)), Bytes: got[i:j]}
		if same {
			rep.Retrans = append(rep.Retrans, iv)
		} else {
			rep.Conflict = append(rep.Conflict, iv)
		}
		i = j
	}
}

// insert merges the new baseline bytes at [start, start+len(data)) into
// the retained intervals, joining neighbours that become adjacent.  The
// bytes are copied.
func (d *dirState) insert(start int64, data []byte) {
	end := start + int64(len(data))
	i := sort.Search(len(d.ivs), func(i int) bool { return d.ivs[i].end() > start })
	var merged []byte
	mstart := start
	if i > 0 && d.ivs[i-1].end() == start {
		mstart = d.ivs[i-1].start
		merged = append(merged, d.ivs[i-1].data...)
		d.ivs = append(d.ivs[:i-1], d.ivs[i:]...)
		i--
	}
	merged = append(merged, data...)
	if i < len(d.ivs) && d.ivs[i].start == end {
		merged = append(merged, d.ivs[i].data...)
		d.ivs = append(d.ivs[:i], d.ivs[i+1:]...)
	}
	d.ivs = append(d.ivs, interval{})
	copy(d.ivs[i+1:], d.ivs[i:])
	d.ivs[i] = interval{start: mstart, data: merged}
}

func (d *dirState) release(seq uint32) error {
	if !d.init {
		d.init = true
		d.anchor = seq
		d.hasWM = true
		return nil
	}
	off, err := d.resolve(seq)
	if err != nil {
		return err
	}
	if d.hasWM && off <= d.wm {
		return nil
	}
	d.wm, d.hasWM = off, true
	kept := d.ivs[:0]
	for _, iv := range d.ivs {
		switch {
		case iv.end() <= off:
			// Fully released.
		case iv.start < off:
			kept = append(kept, interval{start: off,
				data: append([]byte(nil), iv.data[off-iv.start:]...)})
		default:
			kept = append(kept, iv)
		}
	}
	for i := len(kept); i < len(d.ivs); i++ {
		d.ivs[i] = interval{}
	}
	d.ivs = kept
	if d.lo < off {
		d.lo = off
	}
	if d.hi < off {
		d.hi = off
	}
	return nil
}
