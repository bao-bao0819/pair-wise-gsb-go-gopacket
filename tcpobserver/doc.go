// Copyright 2026 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package tcpobserver provides an offline, bidirectional observer for the
// payload bytes of a single TCP connection.
//
// The observer does not establish sockets, track timers, or decide which
// bytes an application should consume.  The caller explicitly creates one
// observer for one connection, names its two endpoints, and feeds already
// decoded TCP segments in capture order.  For every segment the observer
// reports which payload bytes are newly observed, which overlap bytes that
// were seen before with identical content, and which overlap bytes that
// disagree with the first observation of that sequence position.
//
// Each direction keeps an independent, 32-bit sequence space, so the same
// raw sequence number traveling in opposite directions is tracked twice.
// SYN and FIN consume a sequence number but never carry payload.  Sequence
// numbers are compared modulo 2^32, so wraparound is handled natively.
//
// The first byte observed at any sequence position is the permanent
// reference for that position: a later byte at the same position is either
// an identical retransmission or a conflict, but the reference is never
// overwritten.  Reordering the input can change whether a byte is reported
// as new or retransmitted, but any fixed input sequence always yields the
// same report.
//
// Because the observer keeps bytes forever by default, the caller can
// advance a per-direction watermark with Connection.Release once it no
// longer needs overlap comparisons for older data.  Bytes that arrive at
// or before a released watermark are reported as indeterminate, never as
// new.
//
// A segment whose sequence space cannot be disambiguated relative to the
// retained window (exactly half the sequence space away, or extending
// beyond the supported window) causes an ErrAmbiguous error and is not
// incorporated.  Connection reuse is modeled by creating a fresh observer;
// no real-world clocks are used to guess connection lifetime.
package tcpobserver
