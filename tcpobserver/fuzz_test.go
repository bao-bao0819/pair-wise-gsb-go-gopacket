// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpobserver

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzObserve drives both implementations from a compact binary script:
// each op is a byte (high bit=release, low bit=direction), followed by a
// uint32 sequence number and, for observations, a length byte and payload.
func FuzzObserve(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 2, 10, 20, 1, 0, 0, 0, 0, 2, 10, 20})
	f.Fuzz(func(t *testing.T, script []byte) {
		c, err := NewConnection(epOf(1000), epOf(2000))
		if err != nil {
			t.Fatal(err)
		}
		ref := newRef()

		p := 0
		rd := func() (uint32, bool) {
			if p+4 > len(script) {
				return 0, false
			}
			v := binary.BigEndian.Uint32(script[p:])
			p += 4
			return v, true
		}
		for p < len(script) {
			op := script[p]
			p++
			dirIdx := int(op & 1)
			port := []uint16{1000, 2000}[dirIdx]
			seq, ok := rd()
			if !ok {
				return
			}
			if op&0x80 != 0 {
				gErr := c.Release(epOf(port), seq)
				rErr := ref.d(port).release(seq)
				if (gErr != nil) != (rErr != nil) {
					t.Fatalf("release %#x: %v vs %v", seq, gErr, rErr)
				}
				continue
			}
			if p >= len(script) {
				return
			}
			n := int(script[p]%8) + 1 // keep payloads short
			p++
			if p+n > len(script) {
				return
			}
			payload := append([]byte(nil), script[p:p+n]...)
			p += n
			syn := op&0x40 != 0

			rep, gErr := c.Observe(Segment{Endpoint: epOf(port), Seq: seq, SYN: syn, Payload: payload})
			rsp, rc, rErr := ref.d(port).observe(seq, syn, false, append([]byte(nil), payload...))
			if (gErr != nil) != (rErr != nil) {
				t.Fatalf("observe seq=%#x: %v vs %v", seq, gErr, rErr)
			}
			if gErr != nil {
				continue
			}
			if len(rep.Spans) != len(rsp) {
				t.Fatalf("span count %d != %d", len(rep.Spans), len(rsp))
			}
			for i := range rsp {
				if rep.Spans[i].Class != rsp[i].class ||
					rep.Spans[i].Start != rsp[i].start ||
					!bytes.Equal(rep.Spans[i].Data, rsp[i].data) {
					t.Fatalf("span %d mismatch", i)
				}
			}
			if len(rep.Conflicts) != len(rc) {
				t.Fatalf("conflict count %d != %d", len(rep.Conflicts), len(rc))
			}
		}
	})
}
