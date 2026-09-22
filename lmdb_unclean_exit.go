// Ported from cascadia-relay@12ad754
package main

// Unclean-exit handling for the live LMDB store.
//
// A fatal LMDB assertion ends the process with SIGABRT, after which the
// container runtime restarts it and the eventstore resumes writing into the
// same directory, destroying the crash-time state. Both 2026-09 incidents lost
// their on-disk evidence this way (docs/LMDB_REOPEN_ROOT_CAUSE.md).
//
// This file makes an unclean exit observable and preserves the store before
// any write can happen:
//
//   - A run sentinel is written in the store directory just before the
//     eventstore opens and removed just after it closes cleanly. A sentinel
//     found at startup means the previous run did not shut down cleanly.
//   - On unclean exit the store files are copied, with a SHA-256 manifest, to
//     a timestamped evidence directory. This is a plain file copy taken while
//     no process has the environment open; it never opens an LMDB environment
//     and so respects the single-environment invariant in lmdb_runtime.go.
//   - Policy "quarantine" (default) then holds the relay: a stub listener
//     answers /health with 503 and the reason, and startup continues only when
//     the operator removes the quarantine marker. No restart is needed.
//     Policy "snapshot-and-resume" continues immediately after the snapshot.
//     If the snapshot cannot be taken, the relay quarantines regardless of
//     policy: writes never resume over unpreserved evidence.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	runSentinelName     = "RELAY_RUNNING"
	quarantineMarker    = "QUARANTINE.json"
	uncleanExitRecord   = "UNCLEAN_EXIT.json"
	evidenceManifest    = "MANIFEST.sha256"
	evidenceDirBasename = "lmdb-evidence"

	uncleanExitPolicyQuarantine = "quarantine"
	uncleanExitPolicyResume     = "snapshot-and-resume"

	quarantinePollInterval = 2 * time.Second
)

var lmdbStoreFiles = []string{"data.mdb", "lock.mdb"}

// runSentinel records the process that holds the store open.
type runSentinel struct {
	PID       int       `json:"pid"`
	StartedAt time.Time `json:"started_at"`
	Hostname  string    `json:"hostname"`
	Source    string    `json:"source,omitempty"`
}

// uncleanExitIncident is persisted as UNCLEAN_EXIT.json in the evidence
// directory and, while quarantined, as QUARANTINE.json in the store directory.
type uncleanExitIncident struct {
	DetectedAt    time.Time   `json:"detected_at"`
	StorePath     string      `json:"store_path"`
	PreviousRun   runSentinel `json:"previous_run"`
	EvidenceDir   string      `json:"evidence_dir,omitempty"`
	SnapshotError string      `json:"snapshot_error,omitempty"`
	Policy        string      `json:"policy"`
	Quarantined   bool        `json:"quarantined"`
	Release       string      `json:"release_instruction,omitempty"`
}

type uncleanExitConfig struct {
	Policy      string
	EvidenceDir string // empty: <parent of resolved store>/lmdb-evidence
	Source      string // source revision label for the sentinel, if known
	// freeBytes reports free space at a path; overridable in tests.
	freeBytes func(path string) (uint64, error)
	// now is overridable in tests.
	now func() time.Time
}

func (c uncleanExitConfig) normalized() uncleanExitConfig {
	if !validUncleanExitPolicy(c.Policy) {
		c.Policy = uncleanExitPolicyQuarantine
	}
	if c.freeBytes == nil {
		c.freeBytes = statfsFree
	}
	if c.now == nil {
		c.now = func() time.Time { return time.Now().UTC() }
	}
	return c
}

func validUncleanExitPolicy(p string) bool {
	return p == uncleanExitPolicyQuarantine || p == uncleanExitPolicyResume
}

// writeRunSentinel marks the store as open by this process.
func writeRunSentinel(storePath, source string) error {
	host, _ := os.Hostname()
	s := runSentinel{PID: os.Getpid(), StartedAt: time.Now().UTC(), Hostname: host, Source: source}
	return writeJSONFileSync(filepath.Join(storePath, runSentinelName), s)
}

// clearRunSentinel marks a clean close. Call only after the eventstore has
// closed.
func clearRunSentinel(storePath string) error {
	err := os.Remove(filepath.Join(storePath, runSentinelName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// detectUncleanExit inspects the store directory before the eventstore opens.
// It returns nil when the previous run closed cleanly (or there was none).
func detectUncleanExit(storePath string, cfg uncleanExitConfig) (*uncleanExitIncident, error) {
	cfg = cfg.normalized()

	// An existing quarantine marker means a previous process already took the
	// snapshot and was waiting for release when it was restarted. Re-enter
	// quarantine with the recorded incident; do not snapshot again.
	if data, err := os.ReadFile(filepath.Join(storePath, quarantineMarker)); err == nil {
		var inc uncleanExitIncident
		if jsonErr := json.Unmarshal(data, &inc); jsonErr != nil {
			return nil, fmt.Errorf("unreadable %s: %w", quarantineMarker, jsonErr)
		}
		inc.Quarantined = true
		return &inc, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	data, err := os.ReadFile(filepath.Join(storePath, runSentinelName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	inc := &uncleanExitIncident{DetectedAt: cfg.now(), StorePath: storePath, Policy: cfg.Policy}
	_ = json.Unmarshal(data, &inc.PreviousRun) // a corrupt sentinel is still an unclean exit

	dir, snapErr := snapshotStoreForEvidence(storePath, cfg, inc)
	inc.EvidenceDir = dir
	if snapErr != nil {
		inc.SnapshotError = snapErr.Error()
		inc.Quarantined = true
	} else {
		inc.Quarantined = cfg.Policy == uncleanExitPolicyQuarantine
	}
	if inc.Quarantined {
		inc.Release = fmt.Sprintf("after preserving evidence, remove %s to resume; the relay continues without a restart", filepath.Join(storePath, quarantineMarker))
		if err := writeJSONFileSync(filepath.Join(storePath, quarantineMarker), inc); err != nil {
			return nil, fmt.Errorf("write quarantine marker: %w", err)
		}
	}
	// The sentinel is consumed into the incident record; a fresh one is
	// written when the store is actually opened.
	if err := clearRunSentinel(storePath); err != nil {
		return nil, err
	}
	return inc, nil
}

// snapshotStoreForEvidence copies the store files to a new timestamped
// evidence directory and writes a SHA-256 manifest. It refuses to proceed
// when free space is insufficient and fails if any copied byte count does not
// match the source.
func snapshotStoreForEvidence(storePath string, cfg uncleanExitConfig, inc *uncleanExitIncident) (string, error) {
	cfg = cfg.normalized()
	resolved, err := filepath.EvalSymlinks(storePath)
	if err != nil {
		return "", err
	}
	evidenceRoot := cfg.EvidenceDir
	if evidenceRoot == "" {
		evidenceRoot = filepath.Join(filepath.Dir(resolved), evidenceDirBasename)
	}
	dest := filepath.Join(evidenceRoot, cfg.now().Format("20060102T150405Z")+"-unclean-exit")

	var total uint64
	sizes := map[string]int64{}
	for _, name := range lmdbStoreFiles {
		st, err := os.Stat(filepath.Join(resolved, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		sizes[name] = st.Size()
		total += uint64(st.Size())
	}
	if len(sizes) == 0 {
		return "", fmt.Errorf("no LMDB files found in %s", resolved)
	}
	if err := os.MkdirAll(evidenceRoot, 0o755); err != nil {
		return "", err
	}
	free, err := cfg.freeBytes(evidenceRoot)
	if err != nil {
		return "", fmt.Errorf("free space check: %w", err)
	}
	need := total + total/20 + 1<<20
	if free < need {
		return "", fmt.Errorf("insufficient free space for evidence snapshot: need %d bytes, have %d", need, free)
	}
	if err := os.Mkdir(dest, 0o755); err != nil {
		return "", err
	}

	var manifest strings.Builder
	for _, name := range lmdbStoreFiles {
		size, ok := sizes[name]
		if !ok {
			continue
		}
		sum, n, err := copyFileWithHash(filepath.Join(resolved, name), filepath.Join(dest, name))
		if err != nil {
			return dest, fmt.Errorf("copy %s: %w", name, err)
		}
		if n != size {
			return dest, fmt.Errorf("copy %s: source changed during copy (%d bytes read, %d expected)", name, n, size)
		}
		fmt.Fprintf(&manifest, "%s  %s\n", sum, name)
	}
	if err := os.WriteFile(filepath.Join(dest, evidenceManifest), []byte(manifest.String()), 0o644); err != nil {
		return dest, err
	}
	if err := writeJSONFileSync(filepath.Join(dest, uncleanExitRecord), inc); err != nil {
		return dest, err
	}
	if d, err := os.Open(dest); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return dest, nil
}

func copyFileWithHash(src, dst string) (string, int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	buf := make([]byte, 4<<20)
	n, err := io.CopyBuffer(io.MultiWriter(out, h), in, buf)
	if err != nil {
		out.Close()
		return "", n, err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", n, err
	}
	if err := out.Close(); err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// quarantineHandler answers every request with 503 and the incident details.
func quarantineHandler(storePath string, inc *uncleanExitIncident) http.Handler {
	marker := filepath.Join(storePath, quarantineMarker)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                      false,
			"status":                  "quarantined",
			"reason":                  "previous run ended uncleanly; store held closed until evidence is preserved and the operator releases it",
			"store":                   storePath,
			"quarantine_marker":       marker,
			"evidence_dir":            inc.EvidenceDir,
			"evidence_snapshot_error": inc.SnapshotError,
			"previous_run":            inc.PreviousRun,
			"detected_at":             inc.DetectedAt,
			"release_instruction":     inc.Release,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "relay quarantined after unclean exit; see /health", http.StatusServiceUnavailable)
	})
	return mux
}

// holdQuarantine serves the quarantine listener on addr until the marker
// disappears (returns nil) or ctx is cancelled (returns ctx.Err()).
func holdQuarantine(ctx context.Context, addr, storePath string, inc *uncleanExitIncident, poll time.Duration) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: quarantineHandler(storePath, inc)}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("lmdb: QUARANTINED after unclean exit of pid %d (started %s); evidence=%q snapshot_error=%q; %s",
		inc.PreviousRun.PID, inc.PreviousRun.StartedAt.Format(time.RFC3339), inc.EvidenceDir, inc.SnapshotError, inc.Release)

	marker := filepath.Join(storePath, quarantineMarker)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
				log.Printf("lmdb: quarantine released; continuing startup")
				return nil
			}
		}
	}
}

func writeJSONFileSync(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func statfsFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
