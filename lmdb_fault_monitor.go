// Ported from cascadia-relay@12ad754
package main

// Fatal-signature monitoring and the index-divergence health invariant.
//
// The nostrlib eventstore reports an index entry whose raw record is missing
// or undecodable only by writing to the standard logger; it returns no error
// and yields nothing. During the 2026-09-21 incident 4,067 such lines were
// logged in 127 ms while /health kept answering ok:true. With the reader
// isolation fix in place, any such line is evidence of real index/raw
// divergence in the store, so the relay now:
//
//   - recognises those signatures on the standard logger (an io.Writer in
//     front of the previous output; every line is forwarded unchanged),
//   - counts them per signature (Prometheus lmdb_index_divergence_total),
//   - and reports /health as 503 status=degraded, stickily, until restart.
//
// It is a log-signature scrape by necessity, not by preference; the
// signatures are pinned to the vendored eventstore source by a test so a
// silent upstream wording change is caught.

import (
	"bytes"
	"io"
	"log"
	"sync"
	"time"
)

type lmdbFaultSignature struct {
	Name  string
	Match []byte
}

// Signatures from eventstore/lmdb/query.go (pinned by test).
var lmdbFaultSignatures = []lmdbFaultSignature{
	{Name: "index-raw-miss", Match: []byte("from raw event store")},
	{Name: "undecodable-raw", Match: []byte("lmdb: value read error")},
	{Name: "query-error", Match: []byte("lmdb: unexpected query error")},
	{Name: "query-error", Match: []byte("lmdb: unexpected id query error")},
}

type lmdbFaultSnapshot struct {
	Detected bool              `json:"detected"`
	Counts   map[string]uint64 `json:"counts"`
	First    *time.Time        `json:"first,omitempty"`
	Last     *time.Time        `json:"last,omitempty"`
	LastLine string            `json:"last_line,omitempty"`
}

type lmdbFaultMonitor struct {
	next    io.Writer
	onFault func(signature string)

	mu       sync.Mutex
	counts   map[string]uint64
	first    time.Time
	last     time.Time
	lastLine string
}

// installLMDBFaultMonitor wraps the standard logger's current output. It must
// be called before the eventstore opens so no signature can be missed.
func installLMDBFaultMonitor() *lmdbFaultMonitor {
	m := newLMDBFaultMonitor(log.Writer())
	log.SetOutput(m)
	return m
}

func newLMDBFaultMonitor(next io.Writer) *lmdbFaultMonitor {
	return &lmdbFaultMonitor{next: next, counts: map[string]uint64{}}
}

// Write forwards p unchanged and scans it for fault signatures. The standard
// logger emits one complete entry per Write, so line boundaries are reliable.
func (m *lmdbFaultMonitor) Write(p []byte) (int, error) {
	n, err := m.next.Write(p)
	for _, sig := range lmdbFaultSignatures {
		if bytes.Contains(p, sig.Match) {
			m.record(sig.Name, p)
			break
		}
	}
	return n, err
}

func (m *lmdbFaultMonitor) record(signature string, line []byte) {
	now := time.Now().UTC()
	m.mu.Lock()
	m.counts[signature]++
	if m.first.IsZero() {
		m.first = now
	}
	m.last = now
	m.lastLine = string(bytes.TrimSpace(line))
	hook := m.onFault
	m.mu.Unlock()
	if hook != nil {
		hook(signature)
	}
}

func (m *lmdbFaultMonitor) snapshot() lmdbFaultSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := lmdbFaultSnapshot{Counts: make(map[string]uint64, len(m.counts)), LastLine: m.lastLine}
	for k, v := range m.counts {
		s.Counts[k] = v
	}
	if !m.first.IsZero() {
		first, last := m.first, m.last
		s.First, s.Last = &first, &last
		s.Detected = true
	}
	return s
}
