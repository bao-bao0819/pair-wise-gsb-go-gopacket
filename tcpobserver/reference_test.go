// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpobserver

// refDirection is a deliberately tiny, byte-at-a-time model of one
// direction's sequence space.  It keeps one map entry per retained byte and
// is used only to cross-check the interval-based implementation.
type refDirection struct {
	base      uint32
	watermark uint32
	hasBase   bool
	hasMark   bool
	bytes     map[int64]byte
}

type refConnection struct {
	dir map[uint16]*refDirection
}

func newRef() *refConnection {
	return &refConnection{dir: map[uint16]*refDirection{}}
}

func (r *refConnection) d(port uint16) *refDirection {
	d := r.dir[port]
	if d == nil {
		d = &refDirection{bytes: map[int64]byte{}}
		r.dir[port] = d
	}
	return d
}

func rel(base, abs uint32) int64 { return int64(int32(abs - base)) }

func ambiguous(x int64) bool { return x <= -halfSpace || x >= halfSpace }

type refSpan struct {
	class ByteClass
	start uint32
	data  []byte
}

// observe mirrors direction.observe one byte at a time.
func (d *refDirection) observe(seq uint32, syn, fin bool, payload []byte) ([]refSpan, [][2][]byte, error) {
	dataStart := seq
	if syn {
		dataStart = seq + 1
	}
	if !d.hasBase {
		d.base = dataStart
		d.hasBase = true
	}
	s := rel(d.base, dataStart)
	if ambiguous(s) || s+int64(len(payload)) > halfSpace {
		return nil, nil, ErrAmbiguous
	}
	if fin && ambiguous(rel(d.base, dataStart+uint32(len(payload)))) {
		return nil, nil, ErrAmbiguous
	}
	if len(payload) == 0 {
		return nil, nil, nil
	}
	mark := int64(-halfSpace) - 1
	if d.hasMark {
		mark = rel(d.base, d.watermark)
	}

	var spans []refSpan
	for i, b := range payload {
		pos := s + int64(i)
		var class ByteClass
		switch {
		case pos < mark:
			class = ClassIndeterminate
		default:
			if old, ok := d.bytes[pos]; ok {
				if old == b {
					class = ClassSame
				} else {
					class = ClassConflict
				}
			} else {
				class = ClassNew
				d.bytes[pos] = b
			}
		}
		if n := len(spans); n > 0 && spans[n-1].class == class {
			spans[n-1].data = append(spans[n-1].data, b)
		} else {
			spans = append(spans, refSpan{class, d.base + uint32(pos), []byte{b}})
		}
	}

	// Build clean conflict list directly from spans (start lives on span).
	var cf [][2][]byte
	for _, sp := range spans {
		if sp.class == ClassConflict {
			baseLine := make([]byte, len(sp.data))
			for k := range sp.data {
				baseLine[k] = d.bytes[rel(d.base, sp.start)+int64(k)]
			}
			cf = append(cf, [2][]byte{sp.data, baseLine})
		}
	}
	return spans, cf, nil
}

func (d *refDirection) release(target uint32) error {
	if !d.hasBase {
		d.base = target
		d.watermark = target
		d.hasBase = true
		d.hasMark = true
		return nil
	}
	t := rel(d.base, target)
	if ambiguous(t) {
		return ErrAmbiguous
	}
	if d.hasMark && t <= rel(d.base, d.watermark) {
		return nil
	}
	d.hasMark = true
	d.watermark = target
	for pos := range d.bytes {
		if pos < t {
			delete(d.bytes, pos)
		}
	}
	return nil
}
