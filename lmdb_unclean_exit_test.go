// Ported from cascadia-relay@12ad754
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore/lmdb"
)

// isoTagValues forces two index iterators so a saved store spans more than one
// tag prefix, mirroring the reader-isolation fixture in cascadia-relay.
var isoTagValues = []string{"isolation-a", "isolation-b"}

// isoEvent builds a deterministic event from (generation, i). Ported from
// cascadia-relay's reader-isolation fixture so storeWithEvents can populate a
// real eventstore without depending on that (unported) test file.
func isoEvent(generation, i uint64) nostr.Event {
	var seed [16]byte
	binary.BigEndian.PutUint64(seed[0:8], generation)
	binary.BigEndian.PutUint64(seed[8:16], i)
	return nostr.Event{
		ID:        nostr.ID(sha256.Sum256(seed[:])),
		PubKey:    nostr.PubKey(sha256.Sum256([]byte("isolation-author"))),
		CreatedAt: nostr.Timestamp(1_700_000_000 + i),
		Kind:      1,
		Tags:      nostr.Tags{{"t", isoTagValues[i%2]}, {"g", fmt.Sprintf("%d", generation)}},
		Content:   strings.Repeat(fmt.Sprintf("generation-%d ", generation), 24),
	}
}

// storeWithEvents opens a real eventstore at path, saves n events, and closes
// it. It returns the saved IDs.
func storeWithEvents(t *testing.T, path string, n int) []nostr.ID {
	t.Helper()
	db := &lmdb.LMDBBackend{Path: path, MapSize: 1 << 28}
	if err := db.Init(); err != nil {
		t.Fatal(err)
	}
	ids := make([]nostr.ID, 0, n)
	for i := 0; i < n; i++ {
		evt := isoEvent(1, uint64(i))
		if err := db.SaveEvent(evt); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, evt.ID)
	}
	db.Close()
	return ids
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func fixedClock(s string) func() time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return ts }
}

func TestCleanShutdownLeavesNoSentinelAndNoIncident(t *testing.T) {
	store := t.TempDir()
	if err := writeRunSentinel(store, "test"); err != nil {
		t.Fatal(err)
	}
	if err := clearRunSentinel(store); err != nil {
		t.Fatal(err)
	}
	inc, err := detectUncleanExit(store, uncleanExitConfig{})
	if err != nil || inc != nil {
		t.Fatalf("clean shutdown must not produce an incident: inc=%v err=%v", inc, err)
	}
	if _, err := os.Stat(filepath.Join(store, quarantineMarker)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no quarantine marker expected after clean shutdown")
	}
}

// TestUncleanExitSnapshotIsVerifiableAndReadable simulates a crash (sentinel
// left behind) on a real store: the snapshot must hash-match the source, and
// must itself be an openable LMDB store containing the same events. The store
// is reached through a symlink, as production's lmdb-live is.
func TestUncleanExitSnapshotIsVerifiableAndReadable(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "lmdb.fresh-20260921")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(root, "lmdb-live")
	if err := os.Symlink(target, live); err != nil {
		t.Fatal(err)
	}
	ids := storeWithEvents(t, live, 50)

	// Crash: the sentinel is never cleared.
	if err := writeRunSentinel(live, "e3f0f51"); err != nil {
		t.Fatal(err)
	}
	srcHashes := map[string]string{}
	for _, name := range lmdbStoreFiles {
		srcHashes[name] = fileSHA256(t, filepath.Join(target, name))
	}

	cfg := uncleanExitConfig{Policy: uncleanExitPolicyResume, now: fixedClock("2026-09-21T16:13:35Z")}
	inc, err := detectUncleanExit(live, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if inc == nil || inc.Quarantined || inc.SnapshotError != "" {
		t.Fatalf("expected snapshot-and-resume incident, got %+v", inc)
	}
	if inc.PreviousRun.Source != "e3f0f51" || inc.PreviousRun.PID != os.Getpid() {
		t.Fatalf("incident did not carry the previous run's sentinel: %+v", inc.PreviousRun)
	}

	// Evidence directory: sibling of the resolved target, timestamped.
	resolvedRoot, err := filepath.EvalSymlinks(root) // macOS: /var -> /private/var
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(resolvedRoot, evidenceDirBasename, "20260921T161335Z-unclean-exit")
	if inc.EvidenceDir != wantDir {
		t.Fatalf("evidence dir %q, want %q", inc.EvidenceDir, wantDir)
	}

	// Manifest matches the source files byte-for-byte.
	manifest, err := os.ReadFile(filepath.Join(wantDir, evidenceManifest))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatalf("bad manifest line %q", line)
		}
		if parts[0] != srcHashes[parts[1]] || parts[0] != fileSHA256(t, filepath.Join(wantDir, parts[1])) {
			t.Fatalf("hash mismatch for %s", parts[1])
		}
		delete(srcHashes, parts[1])
	}
	if len(srcHashes) != 0 {
		t.Fatalf("files missing from manifest: %v", srcHashes)
	}
	var recorded uncleanExitIncident
	rec, err := os.ReadFile(filepath.Join(wantDir, uncleanExitRecord))
	if err != nil || json.Unmarshal(rec, &recorded) != nil || recorded.PreviousRun.Source != "e3f0f51" {
		t.Fatalf("incident record not written correctly: err=%v %+v", err, recorded)
	}

	// The sentinel is consumed; the live store is untouched and re-openable;
	// the snapshot is a complete, readable store.
	if _, err := os.Stat(filepath.Join(target, runSentinelName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sentinel must be consumed by the incident")
	}
	for _, path := range []string{live, wantDir} {
		db := &lmdb.LMDBBackend{Path: path, MapSize: 1 << 28}
		if err := db.Init(); err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		n := 0
		for range db.QueryEvents(nostr.Filter{IDs: ids}, len(ids)) {
			n++
		}
		db.Close()
		if n != len(ids) {
			t.Fatalf("%s: %d of %d events readable", path, n, len(ids))
		}
	}
}

func TestUncleanExitQuarantineHoldsUntilMarkerRemoved(t *testing.T) {
	store := t.TempDir()
	storeWithEvents(t, store, 5)
	if err := writeRunSentinel(store, "x"); err != nil {
		t.Fatal(err)
	}
	inc, err := detectUncleanExit(store, uncleanExitConfig{Policy: uncleanExitPolicyQuarantine, EvidenceDir: filepath.Join(store, "..", "evidence")})
	if err != nil {
		t.Fatal(err)
	}
	if inc == nil || !inc.Quarantined || inc.SnapshotError != "" {
		t.Fatalf("expected quarantined incident with snapshot, got %+v", inc)
	}
	marker := filepath.Join(store, quarantineMarker)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("quarantine marker missing: %v", err)
	}

	// A restart while quarantined re-enters quarantine without re-snapshotting.
	again, err := detectUncleanExit(store, uncleanExitConfig{Policy: uncleanExitPolicyResume})
	if err != nil || again == nil || !again.Quarantined || again.EvidenceDir != inc.EvidenceDir {
		t.Fatalf("restart during quarantine must re-enter it with the same evidence: %+v err=%v", again, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	released := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() { released <- holdQuarantine(ctx, addr, store, inc, 20*time.Millisecond) }()

	// While held: /health is 503 with the reason, and the store is closed
	// (no sentinel written).
	var resp *http.Response
	for i := 0; i < 100; i++ {
		resp, err = http.Get("http://" + addr + "/health")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("quarantine listener unreachable: %v", err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || body["ok"] != false || body["status"] != "quarantined" || body["evidence_dir"] != inc.EvidenceDir {
		t.Fatalf("unexpected quarantine health: %d %v", resp.StatusCode, body)
	}
	select {
	case err := <-released:
		t.Fatalf("quarantine released prematurely: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(store, runSentinelName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("store must not be marked open while quarantined")
	}

	// Operator releases; startup continues in-process.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-released:
		if err != nil {
			t.Fatalf("release returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quarantine did not release after marker removal")
	}
	if _, err := http.Get("http://" + addr + "/health"); err == nil {
		t.Fatal("quarantine listener should be closed after release")
	}
}

func TestUncleanExitSnapshotFailureForcesQuarantine(t *testing.T) {
	store := t.TempDir()
	storeWithEvents(t, store, 5)
	if err := writeRunSentinel(store, "x"); err != nil {
		t.Fatal(err)
	}
	cfg := uncleanExitConfig{
		Policy:    uncleanExitPolicyResume,
		freeBytes: func(string) (uint64, error) { return 1024, nil },
	}
	inc, err := detectUncleanExit(store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if inc == nil || !inc.Quarantined || !strings.Contains(inc.SnapshotError, "insufficient free space") {
		t.Fatalf("snapshot failure must quarantine even under %s: %+v", uncleanExitPolicyResume, inc)
	}
	if _, err := os.Stat(filepath.Join(store, quarantineMarker)); err != nil {
		t.Fatalf("quarantine marker expected: %v", err)
	}
	for _, name := range lmdbStoreFiles {
		if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(store), evidenceDirBasename, "*", name)); len(matches) != 0 {
			t.Fatalf("no partial evidence copy expected, found %v", matches)
		}
	}
}

func TestUncleanExitPolicyValidation(t *testing.T) {
	for _, p := range []string{uncleanExitPolicyQuarantine, uncleanExitPolicyResume} {
		if !validUncleanExitPolicy(p) {
			t.Fatalf("%s should be valid", p)
		}
	}
	for _, p := range []string{"", "resume", "QUARANTINE", "ignore"} {
		if validUncleanExitPolicy(p) {
			t.Fatalf("%q should be invalid", p)
		}
	}
	if got := (uncleanExitConfig{Policy: "bogus"}).normalized().Policy; got != uncleanExitPolicyQuarantine {
		t.Fatalf("normalized default policy = %q, want %s", got, uncleanExitPolicyQuarantine)
	}

	// wot-relay carries the policy on its Config (config.go); an unset value
	// must default to quarantine. The .env is the reloadable source of truth,
	// so an empty process-environment value falls through to the default.
	path := filepath.Join(t.TempDir(), ".env")
	writeTestDotEnv(t, path, testPubkey(1), 1, 2, 100, 20, 200, "wss://relay.example")
	cfg, err := loadConfig(path, []string{"LMDB_UNCLEAN_EXIT_POLICY="})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got := cfg.LMDBUncleanExitPolicy; got != uncleanExitPolicyQuarantine {
		t.Fatalf("config default policy = %q", got)
	}
}
