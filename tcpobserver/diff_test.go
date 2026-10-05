// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpobserver

import (
	"bytes"
	"math/rand"
	"testing"
)

// op is one step in a randomized scenario.
type op struct {
	port    uint16
	release bool
	seq     uint32
	syn     bool
	fin     bool
	payload []byte
}

func buildOps(rng *rand.Rand) []op {
	const ports = 2
	var ops []op
	// Keep each direction anchored to a small window near a moving origin so
	// wrap-around and overlap happen often without leaving the window.
	var origin [ports]uint32
	var high [ports]uint32 // highest forward coordinate reached
	n := 20 + rng.Intn(40)
	for k := 0; k < n; k++ {
		p := uint16(rng.Intn(ports)) // 0 -> port 1000, 1 -> port 2000
		port := []uint16{1000, 2000}[p]
		if rng.Intn(6) == 0 && high[p] > 4 {
			// Advance a watermark by a small forward amount.
			adv := 1 + rng.Intn(int(high[p]))
			ops = append(ops, op{port: port, release: true, seq: origin[p] + uint32(adv)})
			continue
		}
		l := 1 + rng.Intn(5)
		// Pick a start somewhere from slightly behind the high-water point up
		// to a little ahead, encouraging overlap and holes.
		back := int64(high[p]) - int64(rng.Intn(int(high[p])+3))
		if back < 0 {
			back = 0
		}
		rel := uint32(back)
		if rng.Intn(3) == 0 {
			rel = high[p] + uint32(rng.Intn(4)) // jump ahead (hole)
		}
		// Occasionally wrap the origin near the 2^32 edge.
		if k == 3 {
			origin[p] = 0xFFFFFFFF - 6
		}
		seq := origin[p] + rel
		payload := make([]byte, l)
		for i := range payload {
			// Mostly stable content per position, occasional mutation.
			posByte := byte(int(rel) + i)
			if rng.Intn(5) == 0 {
				payload[i] = byte(rng.Intn(256)) // possible conflict
			} else {
				payload[i] = posByte
			}
		}
		if high[p] < rel+uint32(l) {
			high[p] = rel + uint32(l)
		}
		ops = append(ops, op{port: port, seq: seq, payload: payload})
	}
	return ops
}

func TestRandomAgainstReference(t *testing.T) {
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		ops := buildOps(rng)

		c := newConn(t)
		ref := newRef()

		for _, o := range ops {
			ep := epOf(o.port)
			if o.release {
				gotErr := c.Release(ep, o.seq)
				wantErr := ref.d(o.port).release(o.seq)
				if (gotErr != nil) != (wantErr != nil) {
					t.Fatalf("seed=%d release %#x got err %v want %v", seed, o.seq, gotErr, wantErr)
				}
				continue
			}
			rep, err := c.Observe(Segment{Endpoint: ep, Seq: o.seq, SYN: o.syn, FIN: o.fin, Payload: o.payload})
			rspans, rcf, rerr := ref.d(o.port).observe(o.seq, o.syn, o.fin, append([]byte(nil), o.payload...))
			if (err != nil) != (rerr != nil) {
				t.Fatalf("seed=%d observe seq=%#x got err %v want %v", seed, o.seq, err, rerr)
			}
			if err != nil {
				continue
			}
			if len(rep.Spans) != len(rspans) {
				t.Fatalf("seed=%d seq=%#x span count %d != %d\n got %+v\nwant %+v",
					seed, o.seq, len(rep.Spans), len(rspans), rep.Spans, rspans)
			}
			for i, sp := range rep.Spans {
				rs := rspans[i]
				if sp.Class != rs.class || sp.Start != rs.start || !bytes.Equal(sp.Data, rs.data) {
					t.Fatalf("seed=%d seq=%#x span %d mismatch got (c=%d start=%#x data=%v) want (c=%d start=%#x data=%v)",
						seed, o.seq, i, sp.Class, sp.Start, sp.Data, rs.class, rs.start, rs.data)
				}
				if sp.End != sp.Start+uint32(len(sp.Data)) {
					t.Fatalf("seed=%d span end inconsistent: %+v", seed, sp)
				}
			}
			if len(rep.Conflicts) != len(rcf) {
				t.Fatalf("seed=%d seq=%#x conflict count %d != %d", seed, o.seq, len(rep.Conflicts), len(rcf))
			}
			for i, cf := range rep.Conflicts {
				if !bytes.Equal(cf.Observed, rcf[i][0]) || !bytes.Equal(cf.Baseline, rcf[i][1]) {
					t.Fatalf("seed=%d conflict %d mismatch got obs=%v base=%v want obs=%v base=%v",
						seed, i, cf.Observed, cf.Baseline, rcf[i][0], rcf[i][1])
				}
			}

			// Retained byte counts must match the reference map size.
			idx, _ := c.index(ep)
			if n := retainedBytes(&c.dir[idx]); n != len(ref.d(o.port).bytes) {
				t.Fatalf("seed=%d seq=%#x retained %d != ref %d", seed, o.seq, n, len(ref.d(o.port).bytes))
			}
		}
	}
}

// TestMemoryBoundedByPayload verifies retained storage tracks only retained
// intervals, never the full sequence space.
func TestMemoryBoundedByPayload(t *testing.T) {
	c := newConn(t)
	a := epOf(1000)
	// One byte far across the sequence space must not allocate a huge array.
	ob(t, c, Segment{Endpoint: a, Seq: halfSpace - 10, Payload: []byte{0x42}})
	if n := retainedBytes(&c.dir[0]); n != 1 {
		t.Fatalf("retained = %d want 1", n)
	}
	if len(c.dir[0].chunks) != 1 {
		t.Fatalf("chunks = %d want 1", len(c.dir[0].chunks))
	}
	// After release, storage shrinks back toward zero.
	if err := c.Release(a, halfSpace-9); err != nil {
		t.Fatalf("release: %v", err)
	}
	if n := retainedBytes(&c.dir[0]); n != 0 {
		t.Fatalf("retained after release = %d want 0", n)
	}
}
