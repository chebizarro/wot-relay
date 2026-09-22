// Ported from cascadia-relay@12ad754
package main

// Runtime invariant: the relay process opens the live LMDB path exactly once,
// through the nostrlib eventstore. No health probe, monitor, or helper may open
// a second lmdb.Env on that path while the relay is running.
//
// Why: LMDB record locks never conflict within one process, so a second open
// always wins the exclusive lock and re-initialises the shared lock table
// (mdb_env_setup_locks resets mti_numreaders/mti_txnid). Readers already in
// flight become invisible to mdb_find_oldest, the writer recycles pages they
// still reference, and the reader sees MDB_NOTFOUND on live index entries or
// aborts in mdb_cursor_sibling. This is the mechanism behind the 2026-09-16 and
// 2026-09-21 production incidents (docs/LMDB_REOPEN_ROOT_CAUSE.md). It is also
// documented in lmdb.h ("Do not have open an LMDB database twice in the same
// process at the same time").
//
// Health and monitoring therefore read only in-process counters maintained by
// the store wrapper, never the lock table.

import (
	"errors"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	plmdb "github.com/PowerDNS/lmdb-go/lmdb"
)

// nostrlibLMDBMaxReaders is the reader-slot ceiling the nostrlib eventstore
// applies to the live environment (eventstore/lmdb/lib.go, initialize():
// env.SetMaxReaders(1000)). It is not configurable from this relay; the
// LMDB_MAX_READERS setting is reported as requested only. A test pins this
// constant to the vendored source so it cannot silently drift.
const nostrlibLMDBMaxReaders = 1000

// lmdbEffectiveSyncMode is the durability the nostrlib eventstore actually
// configures: it opens the environment with no NoSync/NoMetaSync/MapAsync
// flags, so every commit is fully synchronous regardless of LMDB_SYNC_MODE.
const lmdbEffectiveSyncMode = "sync"

// lmdbRuntime is the static description of the live environment as the relay
// configured it. Nothing here is read from LMDB at runtime.
type lmdbRuntime struct {
	Path                string
	MapSize             int64
	RequestedMaxReaders int
	EffectiveMaxReaders int
	RequestedSyncMode   string
	EffectiveSyncMode   string
}

func newLMDBRuntime(path string, mapSize int64, requestedMaxReaders int, requestedSyncMode string) lmdbRuntime {
	return lmdbRuntime{
		Path:                path,
		MapSize:             effectiveLMDBMapSize(mapSize),
		RequestedMaxReaders: requestedMaxReaders,
		EffectiveMaxReaders: nostrlibLMDBMaxReaders,
		RequestedSyncMode:   requestedSyncMode,
		EffectiveSyncMode:   lmdbEffectiveSyncMode,
	}
}

// logConfigurationDrift reports settings that operators may believe are in
// force but that the eventstore does not apply.
func (rt lmdbRuntime) logConfigurationDrift() {
	if rt.RequestedMaxReaders > 0 && rt.RequestedMaxReaders != rt.EffectiveMaxReaders {
		log.Printf("lmdb: LMDB_MAX_READERS=%d requested but the nostrlib eventstore fixes the live environment at %d readers; the requested value is not applied", rt.RequestedMaxReaders, rt.EffectiveMaxReaders)
	}
	if rt.RequestedSyncMode != "" && rt.RequestedSyncMode != rt.EffectiveSyncMode {
		log.Printf("lmdb: LMDB_SYNC_MODE=%s requested but the nostrlib eventstore does not apply sync flags; effective mode is %s", rt.RequestedSyncMode, rt.EffectiveSyncMode)
	}
}

// lmdbReadTracker counts read transactions opened through the store wrapper.
// A query's read transaction stays open for as long as its iterator is being
// consumed, which for khatru means until the last event has been written to
// the websocket, so activeReads is the number of LMDB reader slots the relay
// currently holds.
type lmdbReadTracker struct {
	active atomic.Int64
	peak   atomic.Int64
	total  atomic.Uint64
}

func (t *lmdbReadTracker) begin() {
	t.total.Add(1)
	n := t.active.Add(1)
	for {
		p := t.peak.Load()
		if n <= p || t.peak.CompareAndSwap(p, n) {
			return
		}
	}
}

func (t *lmdbReadTracker) end() { t.active.Add(-1) }

func (t *lmdbReadTracker) snapshot() (active, peak int64, total uint64) {
	return t.active.Load(), t.peak.Load(), t.total.Load()
}

// trackQuery wraps a query iterator so the read is counted for exactly the
// span during which the eventstore's read transaction can be open.
func (t *lmdbReadTracker) trackQuery(seq iter.Seq[nostr.Event]) iter.Seq[nostr.Event] {
	return func(yield func(nostr.Event) bool) {
		t.begin()
		defer t.end()
		seq(yield)
	}
}

// lmdbHealthFields is the health/monitor view of the live environment. It is
// built from configuration and in-process counters only.
func lmdbHealthFields(rt lmdbRuntime, tracker *lmdbReadTracker) map[string]any {
	active, peak, total := tracker.snapshot()
	return map[string]any{
		"lmdb_map_size":                rt.MapSize,
		"lmdb_max_readers":             rt.EffectiveMaxReaders,
		"lmdb_requested_max_readers":   rt.RequestedMaxReaders,
		"lmdb_active_reads":            active,
		"lmdb_peak_active_reads":       peak,
		"lmdb_reads_total":             total,
		"lmdb_sync_mode":               rt.EffectiveSyncMode,
		"lmdb_requested_sync_mode":     rt.RequestedSyncMode,
		"lmdb_second_environment_open": false,
	}
}

// monitorLMDBReads periodically logs the in-process read counters. It holds
// no LMDB handle and opens nothing.
func monitorLMDBReads(rt lmdbRuntime, tracker *lmdbReadTracker, interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			logLMDBReadSample(rt, tracker)
		}
	}
}

func logLMDBReadSample(rt lmdbRuntime, tracker *lmdbReadTracker) {
	active, peak, total := tracker.snapshot()
	if rt.EffectiveMaxReaders > 0 && active >= int64(rt.EffectiveMaxReaders*8/10) {
		log.Printf("lmdb readers high-water mark: active_reads=%d peak_active_reads=%d max_readers=%d", active, peak, rt.EffectiveMaxReaders)
		return
	}
	log.Printf("lmdb reader monitor: active_reads=%d peak_active_reads=%d reads_total=%d max_readers=%d", active, peak, total, rt.EffectiveMaxReaders)
}

// lmdbEngineVersion reports the LMDB C library version compiled into lmdb-go.
// It lives here because this is the only production file permitted to import
// lmdb-go (see TestNoIndependentLMDBEnvInRelayPackage).
func lmdbEngineVersion() string {
	return plmdb.VersionString()
}

// --- live-path guard ---------------------------------------------------------

var errLMDBLivePathOpen = errors.New("lmdb: refusing to open a second environment on the live database path")

var liveLMDB struct {
	mu   sync.Mutex
	path string // canonical; empty until the eventstore path is registered
}

// registerLiveLMDBPath records the path the eventstore owns. Call it before the
// eventstore opens; any later attempt to open that path through
// openAuxiliaryLMDBEnv fails. Registering a second, different path is an error
// because the relay serves exactly one environment.
func registerLiveLMDBPath(path string) error {
	canon, err := canonicalLMDBPath(path)
	if err != nil {
		return err
	}
	liveLMDB.mu.Lock()
	defer liveLMDB.mu.Unlock()
	if liveLMDB.path != "" && liveLMDB.path != canon {
		return fmt.Errorf("lmdb: live path already registered as %s; refusing %s", liveLMDB.path, canon)
	}
	liveLMDB.path = canon
	return nil
}

// resetLiveLMDBPath clears the registration. Test-only; production has one
// live environment for the life of the process.
func resetLiveLMDBPath() {
	liveLMDB.mu.Lock()
	defer liveLMDB.mu.Unlock()
	liveLMDB.path = ""
}

// openAuxiliaryLMDBEnv is the only sanctioned way for relay code to obtain an
// lmdb.Env outside the eventstore (for example offline tooling operating on a
// copy). It refuses the registered live path, including through symlinks or
// relative aliases. A source-scan test enforces that no other file in this
// package calls lmdb.NewEnv.
func openAuxiliaryLMDBEnv(path string, mapSize int64, maxReaders int, flags uint) (*plmdb.Env, error) {
	canon, err := canonicalLMDBPath(path)
	if err != nil {
		return nil, err
	}
	liveLMDB.mu.Lock()
	live := liveLMDB.path
	liveLMDB.mu.Unlock()
	if live != "" && live == canon {
		return nil, fmt.Errorf("%w: %s", errLMDBLivePathOpen, canon)
	}

	env, err := plmdb.NewEnv()
	if err != nil {
		return nil, err
	}
	if err := env.SetMaxDBs(12); err != nil {
		env.Close()
		return nil, err
	}
	if maxReaders > 0 {
		if err := env.SetMaxReaders(maxReaders); err != nil {
			env.Close()
			return nil, err
		}
	}
	if err := env.SetMapSize(effectiveLMDBMapSize(mapSize)); err != nil {
		env.Close()
		return nil, err
	}
	if err := env.Open(path, flags, 0o644); err != nil {
		env.Close()
		return nil, err
	}
	return env, nil
}

// canonicalLMDBPath resolves symlinks and relative segments so that two
// spellings of the same directory compare equal. A path that does not exist
// yet is canonicalised through its nearest existing ancestor.
func canonicalLMDBPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent, base := filepath.Split(filepath.Clean(abs))
	if parent == abs || parent == "" {
		return abs, nil
	}
	resolvedParent, err := canonicalLMDBPath(filepath.Clean(parent))
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, base), nil
}
