package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/khatru"
)

func TestSIGHUPReloadObservesEditedDotEnv(t *testing.T) {
	unsetConfigEnvironment(t)
	tempDir := t.TempDir()
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tempDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	startupRoot := testPubkey(1)
	writeTestDotEnv(t, ".env", startupRoot, 1, 2, 100, 20, 200, "wss://old.example")
	startup, err := LoadConfig()
	if err != nil {
		t.Fatalf("initial LoadConfig: %v", err)
	}
	var store runtimeConfigStore
	store.Store(startup)

	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(reloadSignals) })
	updates := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var logs bytes.Buffer
	go func() {
		defer close(done)
		handleConfigReloads(ctx, reloadSignals, LoadConfig, startup, &store, updates, log.New(&logs, "", 0))
	}()

	writeTestDotEnv(t, ".env", testPubkey(2), 4, 7, 400, 50, 600, "wss://new.example")
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	select {
	case <-updates:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SIGHUP reload")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out stopping reload handler")
	}

	current := store.Load()
	if current.RefreshInterval != 4*time.Hour {
		t.Fatalf("refresh interval = %s, want 4h", current.RefreshInterval)
	}
	if current.MinimumFollowers != 7 {
		t.Fatalf("minimum followers = %d, want 7", current.MinimumFollowers)
	}
	if current.MaxTrustNetwork != 400 || current.MaxRelays != 50 || current.MaxOneHopNetwork != 600 {
		t.Fatalf("reloaded limits = %#v, want 400/50/600", current)
	}
	if len(current.SeedRelays) != 1 || current.SeedRelays[0] != "wss://new.example" {
		t.Fatalf("seed relays = %#v, want edited .env value", current.SeedRelays)
	}
	if !strings.Contains(logs.String(), "root pubkey changes require a restart; keeping startup root pubkey") {
		t.Fatalf("missing restart-only root warning in logs:\n%s", logs.String())
	}
}

func TestLoadConfigDotEnvOverridesProcessEnvironment(t *testing.T) {
	path := t.TempDir() + "/.env"
	writeTestDotEnv(t, path, testPubkey(1), 1, 2, 100, 20, 200, "wss://file.example")

	cfg, err := loadConfig(path, []string{
		"REFRESH_INTERVAL_HOURS=9",
		"SEED_RELAYS=wss://environment.example",
	})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.RefreshInterval != 1 || len(cfg.SeedRelays) != 1 || cfg.SeedRelays[0] != "wss://file.example" {
		t.Fatalf(".env did not override process environment: %#v", cfg)
	}
}

func TestLoadConfigRejectsInvalidCandidate(t *testing.T) {
	path := t.TempDir() + "/.env"
	writeTestDotEnv(t, path, testPubkey(1), 0, 2, 100, 20, 200, "wss://relay.example")

	if _, err := loadConfig(path, nil); err == nil || !strings.Contains(err.Error(), "REFRESH_INTERVAL_HOURS") {
		t.Fatalf("expected invalid refresh interval error, got %v", err)
	}
}

func TestReloadRetainsLastValidRuntimeConfig(t *testing.T) {
	initial := Config{
		RefreshInterval:  3,
		MinimumFollowers: 4,
		MaxTrustNetwork:  100,
		MaxRelays:        20,
		MaxOneHopNetwork: 200,
		SeedRelays:       []string{"wss://last-valid.example"},
	}
	var store runtimeConfigStore
	store.Store(initial)
	before := store.Load()
	updates := make(chan struct{}, 1)

	err := reloadRuntimeConfig(
		func() (Config, error) { return Config{}, errors.New("invalid candidate") },
		initial,
		&store,
		updates,
		log.New(&bytes.Buffer{}, "", 0),
	)
	if err == nil {
		t.Fatal("expected reload error")
	}
	if after := store.Load(); after != before {
		t.Fatalf("invalid candidate replaced snapshot: before=%#v after=%#v", before, after)
	}
	select {
	case <-updates:
		t.Fatal("invalid candidate requested an immediate refresh")
	default:
	}
}

func TestRuntimeConfigStoreConcurrentLoadAndStore(t *testing.T) {
	var store runtimeConfigStore
	store.Store(runtimeConfigForSequence(1))

	const iterations = 5000
	errors := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 2; i <= iterations; i++ {
			store.Store(runtimeConfigForSequence(i))
		}
	}()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				current := store.Load()
				wantSeed := strconv.Itoa(current.MinimumFollowers)
				if len(current.SeedRelays) != 1 || current.SeedRelays[0] != wantSeed ||
					current.RefreshInterval != time.Duration(current.MinimumFollowers)*time.Hour {
					select {
					case errors <- fmt.Errorf("torn runtime snapshot: %#v", current):
					default:
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
}

func TestRunRefreshScheduleResetsTickerAndRefreshesImmediately(t *testing.T) {
	runtimeConfig.Store(Config{RefreshInterval: 1})
	updates := make(chan struct{}, 1)
	created := make(chan time.Duration, 1)
	fake := &fakeRefreshTicker{
		ticks:   make(chan time.Time, 1),
		resets:  make(chan time.Duration, 1),
		stopped: make(chan struct{}),
	}
	refreshed := make(chan bool, 2)
	ctx, cancel := context.WithCancel(context.Background())
	go runRefreshSchedule(ctx, updates, func(reloaded bool, runtime *RuntimeConfig) {
		refreshed <- reloaded
	}, func(interval time.Duration) refreshTicker {
		created <- interval
		return fake
	})

	if interval := receiveDuration(t, created); interval != time.Hour {
		t.Fatalf("initial ticker interval = %s, want 1h", interval)
	}
	runtimeConfig.Store(Config{RefreshInterval: 6})
	updates <- struct{}{}
	if interval := receiveDuration(t, fake.resets); interval != 6*time.Hour {
		t.Fatalf("reset ticker interval = %s, want 6h", interval)
	}
	select {
	case reloaded := <-refreshed:
		if !reloaded {
			t.Fatal("config update ran ordinary scheduled refresh")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("config update did not trigger immediate refresh")
	}

	fake.ticks <- time.Now()
	select {
	case reloaded := <-refreshed:
		if reloaded {
			t.Fatal("ticker event ran reload refresh")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ticker did not trigger scheduled refresh")
	}

	cancel()
	select {
	case <-fake.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh ticker was not stopped")
	}
}

type fakeRefreshTicker struct {
	ticks   chan time.Time
	resets  chan time.Duration
	stopped chan struct{}
}

func (f *fakeRefreshTicker) Chan() <-chan time.Time {
	return f.ticks
}

func (f *fakeRefreshTicker) Reset(interval time.Duration) {
	f.resets <- interval
}

func (f *fakeRefreshTicker) Stop() {
	close(f.stopped)
}

func receiveDuration(t *testing.T, values <-chan time.Duration) time.Duration {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for duration")
		return 0
	}
}

func runtimeConfigForSequence(sequence int) Config {
	return Config{
		RefreshInterval:  sequence,
		MinimumFollowers: sequence,
		MaxTrustNetwork:  sequence,
		MaxRelays:        sequence,
		MaxOneHopNetwork: sequence,
		SeedRelays:       []string{strconv.Itoa(sequence)},
	}
}

func writeTestDotEnv(
	t *testing.T,
	path, relayPubkey string,
	refreshInterval, minimumFollowers, maxTrustNetwork, maxRelays, maxOneHopNetwork int,
	seedRelays string,
) {
	t.Helper()
	contents := fmt.Sprintf(`RELAY_NAME=test relay
RELAY_PUBKEY=%s
RELAY_DESCRIPTION=test relay
DB_PATH=db
RELAY_URL=wss://relay.example
INDEX_PATH=templates/index.html
STATIC_PATH=templates/static
REFRESH_INTERVAL_HOURS=%d
MINIMUM_FOLLOWERS=%d
MAX_TRUST_NETWORK=%d
MAX_RELAYS=%d
MAX_ONE_HOP_NETWORK=%d
SEED_RELAYS=%s
ARCHIVAL_SYNC=FALSE
ARCHIVE_REACTIONS=FALSE
`, relayPubkey, refreshInterval, minimumFollowers, maxTrustNetwork, maxRelays, maxOneHopNetwork, seedRelays)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testPubkey(value byte) string {
	var privateKey [32]byte
	privateKey[31] = value
	return nostr.GetPublicKey(privateKey).Hex()
}

func unsetConfigEnvironment(t *testing.T) {
	t.Helper()
	keys := []string{
		"RELAY_NAME", "RELAY_PUBKEY", "RELAY_DESCRIPTION", "RELAY_CONTACT", "RELAY_ICON",
		"DB_PATH", "RELAY_URL", "INDEX_PATH", "STATIC_PATH", "PORT",
		"REFRESH_INTERVAL_HOURS", "MINIMUM_FOLLOWERS", "ARCHIVAL_SYNC", "MAX_AGE_DAYS",
		"ARCHIVE_REACTIONS", "IGNORE_FOLLOWS_LIST", "MAX_TRUST_NETWORK", "MAX_RELAYS",
		"MAX_ONE_HOP_NETWORK", "SEED_RELAYS", "ARCHIVE_KINDS",
		"LMDB_UNCLEAN_EXIT_POLICY", "LMDB_EVIDENCE_DIR",
	}
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
		key, value, present := key, value, present
		t.Cleanup(func() {
			if present {
				if err := os.Setenv(key, value); err != nil {
					t.Errorf("restore %s: %v", key, err)
				}
			} else if err := os.Unsetenv(key); err != nil {
				t.Errorf("clear %s: %v", key, err)
			}
		})
	}
}

func TestLoadConfigRejectsDurationOverflow(t *testing.T) {
	path := t.TempDir() + "/.env"
	maximum := int(math.MaxInt64 / int64(time.Hour))
	writeTestDotEnv(t, path, testPubkey(1), maximum, 1, 100, 20, 200, "wss://relay.example")
	if _, err := loadConfig(path, nil); err != nil {
		t.Fatalf("maximum supported interval rejected: %v", err)
	}
	writeTestDotEnv(t, path, testPubkey(1), maximum+1, 1, 100, 20, 200, "wss://relay.example")
	if _, err := loadConfig(path, nil); err == nil || !strings.Contains(err.Error(), "REFRESH_INTERVAL_HOURS") {
		t.Fatalf("expected duration overflow rejection, got %v", err)
	}
}

func TestInvalidDotEnvRetainsSnapshotAndDoesNotNotify(t *testing.T) {
	path := t.TempDir() + "/.env"
	writeTestDotEnv(t, path, testPubkey(1), 1, 1, 100, 20, 200, "wss://relay.example")
	initial, err := loadConfig(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	var store runtimeConfigStore
	store.Store(initial)
	before := store.Load()
	updates := make(chan struct{}, 1)
	for _, invalid := range []string{
		"REFRESH_INTERVAL_HOURS=0", "REFRESH_INTERVAL_HOURS=2562048",
		"MINIMUM_FOLLOWERS=-1", "MAX_TRUST_NETWORK=0", "MAX_RELAYS=0",
		"MAX_ONE_HOP_NETWORK=0", "SEED_RELAYS=https://invalid.example",
		"SEED_RELAYS=wss://valid.example,", "PORT=invalid", "unclosed='",
	} {
		t.Run(invalid, func(t *testing.T) {
			writeTestDotEnv(t, path, testPubkey(1), 7, 8, 400, 40, 600, "wss://new.example")
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = fmt.Fprintln(file, invalid)
			closeErr := file.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			err = reloadRuntimeConfig(func() (Config, error) { return loadConfig(path, nil) }, initial, &store, updates, log.New(&bytes.Buffer{}, "", 0))
			if err == nil {
				t.Fatal("invalid file accepted")
			}
			if store.Load() != before {
				t.Fatal("invalid file replaced active snapshot")
			}
			select {
			case <-updates:
				t.Fatal("invalid file notified refresh loop")
			default:
			}
		})
	}
}

func TestRuntimeConfigCopiesSeedRelays(t *testing.T) {
	initial := runtimeConfigForSequence(1)
	var store runtimeConfigStore
	store.Store(initial)
	initial.SeedRelays[0] = "changed"
	if store.Load().SeedRelays[0] != "1" {
		t.Fatal("published snapshot aliases candidate slice")
	}
}

func TestRefreshCoalescesUpdatesDuringRunningRefresh(t *testing.T) {
	runtimeConfig.Store(runtimeConfigForSequence(1))
	updates := make(chan struct{}, 1)
	fake := &fakeRefreshTicker{ticks: make(chan time.Time, 1), resets: make(chan time.Duration, 2), stopped: make(chan struct{})}
	started := make(chan *RuntimeConfig, 2)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go runRefreshSchedule(ctx, updates, func(_ bool, snapshot *RuntimeConfig) {
		started <- snapshot
		select {
		case <-release:
		case <-ctx.Done():
		}
	}, func(time.Duration) refreshTicker { return fake })
	first := runtimeConfig.Load()
	updates <- struct{}{}
	select {
	case got := <-started:
		if got != first {
			t.Fatal("refresh did not capture first generation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start")
	}
	for i := 2; i <= 4; i++ {
		runtimeConfig.Store(runtimeConfigForSequence(i))
		select {
		case updates <- struct{}{}:
		default:
		}
	}
	close(release)
	select {
	case got := <-started:
		if got != runtimeConfig.Load() || got.MinimumFollowers != 4 {
			t.Fatalf("queued refresh lost latest snapshot: %#v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued update lost during refresh")
	}
	if first.MinimumFollowers != 1 || first.SeedRelays[0] != "1" {
		t.Fatal("running generation mutated")
	}
	if interval := receiveDuration(t, fake.resets); interval != time.Hour {
		t.Fatalf("first reset: %s", interval)
	}
	if interval := receiveDuration(t, fake.resets); interval != 4*time.Hour {
		t.Fatalf("latest reset: %s", interval)
	}
	cancel()
	select {
	case <-fake.stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not stop")
	}
}

func TestTrustFilterUsesCapturedSnapshotAndRejectsEmptyRebuild(t *testing.T) {
	oldCounts, oldNetwork, oldSet, oldMap, oldReady := pubkeyFollowerCount, trustNetwork, trustNetworkSet, trustNetworkMap, trustNetworkReady
	t.Cleanup(func() {
		pubkeyFollowerCount, trustNetwork, trustNetworkSet, trustNetworkMap, trustNetworkReady = oldCounts, oldNetwork, oldSet, oldMap, oldReady
	})
	pubkeyFollowerCount = map[string]int{testPubkey(2): 1, testPubkey(3): 1}
	runtimeConfig.Store(Config{MinimumFollowers: 1, MaxTrustNetwork: 1, MaxOneHopNetwork: 10})
	captured := runtimeConfig.Load()
	runtimeConfig.Store(Config{MinimumFollowers: 2, MaxTrustNetwork: 20, MaxOneHopNetwork: 10})
	updateTrustNetworkFilter(captured)
	if len(trustNetworkMap) != 1 || len(trustNetwork) != 1 {
		t.Fatalf("captured limit not applied: %#v", trustNetworkMap)
	}
	previous := append([]string(nil), trustNetwork...)
	updateTrustNetworkFilter(captured)
	if !reflect.DeepEqual(previous, trustNetwork) {
		t.Fatal("bounded membership changed without input change")
	}
	updateTrustNetworkFilter(runtimeConfig.Load())
	if len(trustNetworkMap) != 0 {
		t.Fatal("raised threshold did not empty trust graph")
	}
	pk, err := nostr.PubKeyFromHex(testPubkey(2))
	if err != nil {
		t.Fatal(err)
	}
	if rejected, _ := rejectUntrustedEvent(context.Background(), nostr.Event{PubKey: pk}); !rejected {
		t.Fatal("empty rebuilt graph failed open")
	}
}

// This subprocess runs the production entrypoint (real listener, LMDB, signal
// handler and refresh workers), and inherits race instrumentation from go test.
func TestRuntimeConfigProcessHelper(t *testing.T) {
	if os.Getenv("WOT_RELAY_CONFIG_TEST_HELPER") != "1" {
		return
	}
	main()
}

func TestRuntimeConfigProcessSIGHUP(t *testing.T) {
	unsetConfigEnvironment(t)
	root := testPubkey(1)
	a, b, c, d := testPubkey(2), testPubkey(3), testPubkey(4), testPubkey(5)
	seed1, stopSeed1 := runtimeSeedFixture(t, []nostr.Event{
		runtimeFollowEvent(t, 1, nostr.Tags{{"p", a}, {"p", b}}),
		runtimeFollowEvent(t, 2, nostr.Tags{{"p", c}, {"r", "wss://a.example"}, {"r", "wss://b.example"}}),
		runtimeFollowEvent(t, 3, nostr.Tags{{"p", d}, {"r", "wss://c.example"}}),
	})
	seed2, _ := runtimeSeedFixture(t, []nostr.Event{
		runtimeFollowEvent(t, 1, nostr.Tags{{"p", b}, {"p", a}}),
		runtimeFollowEvent(t, 3, nostr.Tags{{"p", d}, {"r", "wss://d.example"}, {"r", "wss://e.example"}}),
	})
	emptySeed, _ := runtimeSeedFixture(t, nil)
	partialSeed, _ := runtimeSeedFixture(t, []nostr.Event{
		runtimeFollowEvent(t, 1, nostr.Tags{{"p", a}}),
	}, func(relay *khatru.Relay) {
		relay.OnRequest = func(_ context.Context, filter nostr.Filter) (bool, string) {
			return len(filter.Authors) == 1 && filter.Authors[0].Hex() == a, "restricted: fixture one-hop discovery unavailable"
		}
	})
	unavailableAtStartup, stopStartupSeed := runtimeSeedFixture(t, nil)
	stopStartupSeed()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	workdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	writeCandidate := func(pubkey string, hours, threshold, trustLimit, relayLimit, hopLimit int, seeds, extra string) {
		t.Helper()
		staged := path + ".next"
		writeTestDotEnv(t, staged, pubkey, hours, threshold, trustLimit, relayLimit, hopLimit, seeds)
		file, err := os.OpenFile(staged, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintf(file, "PORT=%d\nDB_PATH=%s\nINDEX_PATH=%s\nSTATIC_PATH=%s\n%s\n", port, filepath.Join(dir, "db"), filepath.Join(workdir, "templates/index.html"), filepath.Join(workdir, "templates/static"), extra)
		closeErr := file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if err := os.Rename(staged, path); err != nil {
			t.Fatal(err)
		}
	}
	writeCandidate(root, 1, 1, 100, 20, 200, unavailableAtStartup, "")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	logs := &runtimeProcessLogs{lines: make(chan string, 4096)}
	cmd := exec.Command(executable, "-test.run=^TestRuntimeConfigProcessHelper$")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "WOT_RELAY_CONFIG_TEST_HELPER=1")
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		if strings.Contains(logs.String(), "WARNING: DATA RACE") {
			t.Errorf("child race diagnostic:\n%s", logs.String())
		}
		if t.Failed() {
			t.Logf("relay output:\n%s", logs.String())
		}
	})
	waitLog := func(fragment string) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case line := <-logs.lines:
				if strings.Contains(line, fragment) {
					return
				}
			case <-done:
				t.Fatalf("relay exited while waiting for %q:\n%s", fragment, logs.String())
			case <-timer.C:
				t.Fatalf("no log %q:\n%s", fragment, logs.String())
			}
		}
	}
	waitLog("initial trust network discovery failed; no graph available; rejecting untrusted publications")
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	get := func(path, accept string) []byte {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, baseURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		return body
	}
	checkHealth := func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("PID %d not live: %v", pid, err)
		}
		var health struct {
			OK bool   `json:"ok"`
			DB string `json:"db"`
		}
		if err := json.Unmarshal(get("/health", ""), &health); err != nil {
			t.Fatal(err)
		}
		if !health.OK || health.DB != filepath.Join(dir, "db") {
			t.Fatalf("health/storage changed: %+v", health)
		}
		var info struct {
			Pubkey string `json:"pubkey"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal(get("/", "application/nostr+json"), &info); err != nil {
			t.Fatal(err)
		}
		if info.Pubkey != root || info.Name != "test relay" {
			t.Fatalf("restart-only relay identity changed: %+v", info)
		}
	}
	checkHealth()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	public, err := nostr.RelayConnect(ctx, fmt.Sprintf("ws://127.0.0.1:%d", port), nostr.RelayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = public.Close() })
	sequence := 0
	publish := func(secret byte, accepted bool) {
		t.Helper()
		sequence++
		event := runtimeFollowEvent(t, secret, nil)
		event.Kind, event.Content = nostr.KindTextNote, fmt.Sprintf("runtime-test-%d", sequence)
		var key [32]byte
		key[31] = secret
		if err := event.Sign(key); err != nil {
			t.Fatal(err)
		}
		publishCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		err := public.Publish(publishCtx, event)
		if accepted && err != nil {
			t.Fatalf("expected accepted author %d: %v", secret, err)
		}
		if !accepted && (err == nil || !strings.Contains(err.Error(), "not in web of trust")) {
			t.Fatalf("expected WoT rejection for author %d: %v", secret, err)
		}
	}
	// Initial discovery failure must not leave the pre-build admission window
	// open forever. A subsequent complete rebuild can recover the same process.
	publish(4, false)
	writeCandidate(root, 1, 1, 100, 20, 200, seed1, "")
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitLog("trust network refresh completed")
	checkHealth()
	publish(4, true)

	// Probe the public health route throughout all live edits, not just at the
	// boundaries. Completion is driven by reload logs and protocol OK replies.
	probeCtx, stopProbes := context.WithCancel(context.Background())
	probeResult := make(chan error, 1)
	var probes atomic.Int64
	go func() {
		for {
			req, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, baseURL+"/health", nil)
			resp, err := client.Do(req)
			if err != nil {
				if probeCtx.Err() != nil {
					probeResult <- nil
				} else {
					probeResult <- err
				}
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || readErr != nil {
				probeResult <- fmt.Errorf("health probe status=%d read=%v", resp.StatusCode, readErr)
				return
			}
			probes.Add(1)
		}
	}()
	t.Cleanup(func() {
		stopProbes()
		if err := <-probeResult; err != nil {
			t.Errorf("public health interrupted: %v", err)
		}
	})
	signalReload := func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}

	writeCandidate(testPubkey(9), 2, 2, 100, 20, 200, seed1,
		fmt.Sprintf("RELAY_NAME=changed\nPORT=%d\nDB_PATH=%s", port%65535+1, filepath.Join(dir, "must-not-open")))
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	publish(4, false) // repeated refresh must not inflate follower counts
	if _, err := os.Stat(filepath.Join(dir, "must-not-open")); !os.IsNotExist(err) {
		t.Fatalf("restart-only storage path opened: %v", err)
	}
	if !strings.Contains(logs.String(), "root pubkey changes require a restart") || !strings.Contains(logs.String(), "DB_PATH") || !strings.Contains(logs.String(), "PORT") {
		t.Fatal("missing restart-only warnings")
	}

	writeCandidate(root, 3, 1, 100, 20, 200, seed2, "")
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	publish(4, false) // no longer present on the replacement seed
	publish(5, true)

	writeCandidate(root, 4, 1, 1, 1, 1, seed2, "")
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	stats := string(get("/debug/stats", ""))
	for _, want := range []string{"Relays: 1\n", "Trust Network: 1\n", "One Hop Network: 1\n"} {
		if !strings.Contains(stats, want) {
			t.Fatalf("reduced limit %q not effective:\n%s", want, stats)
		}
	}

	// Change valid fields alongside the invalid field: neither the timer,
	// effective admission nor the source relay may partially change.
	writeCandidate(root, 5, 0, 100, 20, 200, seed1, "REFRESH_INTERVAL_HOURS=2562048")
	signalReload()
	waitLog("config reload failed; keeping last-valid runtime configuration")
	checkHealth()
	if after := string(get("/debug/stats", "")); !strings.Contains(after, "Network Refreshes: 5\n") {
		t.Fatalf("invalid input triggered refresh:\n%s", after)
	}
	keys := []string{a, b, d}
	sort.Strings(keys)
	for secret := byte(2); secret <= 5; secret++ {
		publish(secret, testPubkey(secret) == keys[0])
	}

	// A later valid update still reconciles after rejection on the same PID and
	// persistent public websocket connection.
	writeCandidate(root, 1, 1, 100, 20, 200, seed1, "")
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	publish(4, true)
	// An unavailable previously used seed must not replace or re-filter the
	// working graph, even when the accepted candidate raises the threshold.
	stopSeed1()
	writeCandidate(root, 2, 99, 1, 1, 1, seed1, "")
	signalReload()
	waitLog("trust network discovery failed; keeping last-successful graph")
	checkHealth()
	publish(4, true)
	if after := string(get("/debug/stats", "")); !strings.Contains(after, "Trust Network: 4\n") || !strings.Contains(after, "One Hop Network: 2\n") || !strings.Contains(after, "Relays: 3\n") {
		t.Fatalf("failed owner discovery replaced working inventories:\n%s", after)
	}

	// Completing owner discovery is insufficient if any one-hop query fails.
	writeCandidate(root, 3, 99, 1, 1, 1, partialSeed, "")
	signalReload()
	waitLog("trust network discovery failed; keeping last-successful graph: one-hop discovery:")
	checkHealth()
	publish(4, true)
	if after := string(get("/debug/stats", "")); !strings.Contains(after, "Trust Network: 4\n") || !strings.Contains(after, "One Hop Network: 2\n") || !strings.Contains(after, "Relays: 3\n") {
		t.Fatalf("failed one-hop discovery replaced working inventories:\n%s", after)
	}

	// A real EOSE with no matching events is a completed empty result, not an
	// outage. It must replace the old graph and continue to reject everyone.
	writeCandidate(root, 4, 1, 100, 20, 200, emptySeed, "")
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	publish(4, false)
	publish(5, false)
	if after := string(get("/debug/stats", "")); !strings.Contains(after, "Trust Network: 0\n") || !strings.Contains(after, "One Hop Network: 0\n") || !strings.Contains(after, "Relays: 0\n") {
		t.Fatalf("completed empty discovery did not replace graph:\n%s", after)
	}
	// The empty result is not sticky: a subsequent complete graph recovers.
	writeCandidate(root, 1, 1, 100, 20, 200, seed2, "")
	signalReload()
	waitLog("trust network refresh completed")
	checkHealth()
	publish(5, true)
	if probes.Load() == 0 {
		t.Fatal("no concurrent public health probes completed")
	}
	t.Logf("local production-entrypoint acceptance: PID=%d unchanged; persistent websocket; valid threshold/seed/limit changes; invalid candidate retained live state; health probes=%d; LMDB/root/listener unchanged; initial discovery failure rejects; unavailable seed and failed one-hop retain graph; completed empty EOSE denies all; subsequent recovery", pid, probes.Load())
}

func runtimeFollowEvent(t *testing.T, secret byte, tags nostr.Tags) nostr.Event {
	t.Helper()
	var key [32]byte
	key[31] = secret
	event := nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.KindFollowList, Tags: tags}
	if err := event.Sign(key); err != nil {
		t.Fatal(err)
	}
	return event
}

func runtimeSeedFixture(t *testing.T, events []nostr.Event, hooks ...func(*khatru.Relay)) (string, func()) {
	t.Helper()
	relay := khatru.NewRelay()
	relay.QueryStored = func(ctx context.Context, filter nostr.Filter) iter.Seq[nostr.Event] {
		return func(yield func(nostr.Event) bool) {
			for _, event := range events {
				if filter.Matches(event) && !yield(event) {
					return
				}
			}
		}
	}
	for _, hook := range hooks {
		hook(relay)
	}
	// httptest.Server.Close does not close hijacked websocket connections.
	// Track the underlying connections so an outage closes both the listener
	// and existing seed sessions, deterministically and without sleeping.
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	server := httptest.NewUnstartedServer(relay)
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		mu.Lock()
		defer mu.Unlock()
		if state == http.StateNew {
			connections[conn] = true
		}
		if state == http.StateClosed {
			delete(connections, conn)
		}
	}
	server.Start()
	stop := func() {
		server.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			_ = conn.Close()
			delete(connections, conn)
		}
	}
	t.Cleanup(stop)
	return "ws" + strings.TrimPrefix(server.URL, "http"), stop
}

type runtimeProcessLogs struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	pending string
	lines   chan string
}

func (l *runtimeProcessLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buffer.Write(p)
	l.pending += string(p)
	for {
		line, rest, ok := strings.Cut(l.pending, "\n")
		if !ok {
			break
		}
		l.pending = rest
		l.lines <- line
	}
	return len(p), nil
}

func (l *runtimeProcessLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buffer.String()
}

func TestFetchDiscoveryRequiresCompleteEOSE(t *testing.T) {
	oldPool := pool
	ctx, cancel := context.WithCancel(context.Background())
	pool = nostr.NewPool()
	pool.Context = ctx
	t.Cleanup(func() { cancel(); pool.Close("discovery test finished"); pool = oldPool })
	empty, _ := runtimeSeedFixture(t, nil)
	unavailable, stop := runtimeSeedFixture(t, nil)
	stop()
	closed, _ := runtimeSeedFixture(t, nil, func(relay *khatru.Relay) {
		relay.OnRequest = func(context.Context, nostr.Filter) (bool, string) { return true, "restricted: fixture" }
	})
	for _, tc := range []struct {
		name      string
		seeds     []string
		wantError bool
	}{
		{"complete empty", []string{empty}, false},
		{"unavailable", []string{unavailable}, true},
		{"complete empty plus unavailable", []string{empty, unavailable}, true},
		{"CLOSED", []string{closed}, true},
		{"no seeds", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			visited := false
			err := fetchDiscovery(queryCtx, tc.seeds, nostr.Filter{Kinds: []nostr.Kind{nostr.KindFollowList}}, func(nostr.Event) { visited = true })
			if (err != nil) != tc.wantError {
				t.Fatalf("discovery error=%v wantError=%v", err, tc.wantError)
			}
			if visited {
				t.Fatal("empty fixture delivered an event")
			}
		})
	}

	t.Run("canceled before EOSE", func(t *testing.T) {
		requested := make(chan struct{}, 1)
		incomplete, _ := runtimeSeedFixture(t, nil, func(relay *khatru.Relay) {
			relay.OnRequest = func(context.Context, nostr.Filter) (bool, string) { requested <- struct{}{}; return false, "" }
			relay.QueryStored = func(ctx context.Context, _ nostr.Filter) iter.Seq[nostr.Event] {
				return func(func(nostr.Event) bool) { <-ctx.Done() }
			}
		})
		queryCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- fetchDiscovery(queryCtx, []string{incomplete}, nostr.Filter{Kinds: []nostr.Kind{nostr.KindFollowList}}, func(nostr.Event) {})
		}()
		select {
		case <-requested:
		case <-time.After(5 * time.Second):
			t.Fatal("query did not start")
		}
		cancel() // explicit application cancellation, never timeout-as-success
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("canceled discovery reported complete")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled discovery did not finish")
		}
	})
}
