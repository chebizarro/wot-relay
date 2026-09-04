package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"fiatjaf.com/nostr"
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
	go runRefreshSchedule(ctx, updates, func(reloaded bool) {
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
