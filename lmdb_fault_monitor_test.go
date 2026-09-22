// Ported from cascadia-relay@12ad754
package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLMDBFaultMonitorForwardsAndCounts(t *testing.T) {
	var sink bytes.Buffer
	m := newLMDBFaultMonitor(&sink)
	var hooked []string
	m.onFault = func(s string) { hooked = append(hooked, s) }

	lines := []string{
		"2026/09/21 16:13:33 lmdb reader monitor: active_reads=3\n",
		"2026/09/21 16:13:33 lmdb: failed to get 000a0594 from raw event store: mdb_get: MDB_NOTFOUND: No matching key/data pair found (query prefix=6bc8, index=indexTag)\n",
		"2026/09/21 16:13:33 lmdb: value read error (id abc) on query prefix 6b sp 00 dbi indexTag: bad\n",
		"2026/09/21 16:13:33 lmdb: unexpected query error: boom\n",
		"2026/09/21 16:13:33 nostr REQ from=<redacted> sub=x\n",
	}
	for _, l := range lines {
		if _, err := m.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	if sink.String() != strings.Join(lines, "") {
		t.Fatal("monitor altered or dropped log output")
	}
	s := m.snapshot()
	if !s.Detected || s.Counts["index-raw-miss"] != 1 || s.Counts["undecodable-raw"] != 1 || s.Counts["query-error"] != 1 {
		t.Fatalf("unexpected snapshot %+v", s)
	}
	if s.First == nil || s.Last == nil || !strings.Contains(s.LastLine, "unexpected query error") {
		t.Fatalf("timestamps/last line not recorded: %+v", s)
	}
	if len(hooked) != 3 {
		t.Fatalf("hook calls = %v", hooked)
	}
}

func TestHealthFlipsTo503OnIndexDivergence(t *testing.T) {
	var sink bytes.Buffer
	m := newLMDBFaultMonitor(&sink)
	h := newHealthHandler("wot-relay", newLMDBRuntime(t.TempDir(), 1<<20, 16, "sync"), &lmdbReadTracker{}, m)

	get := func() (int, map[string]any) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	code, body := get()
	if code != http.StatusOK || body["ok"] != true || body["status"] != "ok" {
		t.Fatalf("healthy relay: %d %v", code, body)
	}
	m.Write([]byte("lmdb: failed to get 0000 from raw event store: MDB_NOTFOUND\n"))
	code, body = get()
	if code != http.StatusServiceUnavailable || body["ok"] != false || body["status"] != "degraded" {
		t.Fatalf("after divergence: %d %v", code, body)
	}
	div, _ := body["lmdb_index_divergence"].(map[string]any)
	if div == nil || div["detected"] != true {
		t.Fatalf("divergence detail missing: %v", body)
	}
	// Sticky: a later clean period does not clear it.
	m.Write([]byte("lmdb reader monitor: active_reads=0\n"))
	if code, _ := get(); code != http.StatusServiceUnavailable {
		t.Fatal("divergence must be sticky until restart")
	}
}

// TestLMDBFaultSignaturesPinnedToEventstoreSource fails if the vendored
// eventstore stops emitting any signature the monitor relies on.
func TestLMDBFaultSignaturesPinnedToEventstoreSource(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "fiatjaf.com/nostr").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	src, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "eventstore", "lmdb", "query.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range lmdbFaultSignatures {
		if !bytes.Contains(src, sig.Match) {
			t.Fatalf("eventstore query.go no longer contains %q (signature %s); update lmdbFaultSignatures", sig.Match, sig.Name)
		}
	}
}

func TestInstallLMDBFaultMonitorWrapsStandardLogger(t *testing.T) {
	prev := log.Writer()
	t.Cleanup(func() { log.SetOutput(prev) })
	var sink bytes.Buffer
	log.SetOutput(&sink)
	m := installLMDBFaultMonitor()
	log.Printf("lmdb: failed to get 0000 from raw event store: MDB_NOTFOUND")
	if !strings.Contains(sink.String(), "from raw event store") {
		t.Fatal("log line was not forwarded to the previous writer")
	}
	if !m.snapshot().Detected {
		t.Fatal("monitor did not see the standard logger's output")
	}
}
