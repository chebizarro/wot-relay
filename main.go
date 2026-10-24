package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"iter"
	"log"
	"math"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/eventstore"
	"fiatjaf.com/nostr/eventstore/lmdb"
	"fiatjaf.com/nostr/khatru"
	"fiatjaf.com/nostr/khatru/policies"
	"fiatjaf.com/nostr/nip11"
)

var (
	version = "0.2.1"
)

var pool *nostr.Pool
var db *lmdb.LMDBBackend
var relays []string
var config Config
var runtimeConfig runtimeConfigStore
var trustNetwork []string
var trustNetworkSet = make(map[string]bool) // O(1) lookup
var oneHopNetwork []string
var oneHopNetworkSet = make(map[string]bool) // O(1) lookup
var trustNetworkMap map[string]bool
var trustNetworkReady bool // guarded by trustNetworkMutex, including an intentionally empty graph
var pubkeyFollowerCount = make(map[string]int)
var trustedNotes uint64
var untrustedNotes uint64
var archiveEventSemaphore = make(chan struct{}, 20)

// Performance counters
var (
	totalEvents         uint64
	rejectedEvents      uint64
	archivedEvents      uint64
	profileRefreshCount uint64
	networkRefreshCount uint64
)

// Mutexes for thread safety
var (
	relayMutex        sync.RWMutex
	trustNetworkMutex sync.RWMutex
	oneHopMutex       sync.RWMutex
	followerMutex     sync.RWMutex
)

func main() {
	nostr.InfoLogger = log.New(io.Discard, "", 0)
	green := "\033[32m"
	reset := "\033[0m"

	art := `
888       888      88888888888      8888888b.          888
888   o   888          888          888   Y88b         888
888  d8b  888          888          888    888         888
888 d888b 888  .d88b.  888          888   d88P .d88b.  888  8888b.  888  888
888d88888b888 d88""88b 888          8888888P" d8P  Y8b 888     "88b 888  888
88888P Y88888 888  888 888          888 T88b  88888888 888 .d888888 888  888
8888P   Y8888 Y88..88P 888          888  T88b Y8b.     888 888  888 Y88b 888
888P     Y888  "Y88P"  888          888   T88b "Y8888  888 "Y888888  "Y88888
                                                                         888
                                                                    Y8b d88P
                                               powered by: khatru     "Y88P"
	`

	fmt.Println(green + art + reset)
	log.Println("🚀 booting up web of trust relay")
	build := buildInfo()
	log.Printf("wot-relay build: revision=%s source=%s built=%s go=%s lmdb_engine=%q modules=%v",
		build.Revision, choose(build.Source, "-"), choose(build.BuildTime, "-"), build.GoVersion, build.LMDBEngine, build.Modules)
	relay := khatru.NewRelay()
	ctx := context.Background()
	pool = nostr.NewPool()
	pool.Context = ctx
	var err error
	config, err = LoadConfig()
	if err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}
	runtimeConfig.Store(config)
	log.Printf("refresh interval set to %s", runtimeConfig.Load().RefreshInterval)
	log.Printf("using %d seed relays", len(runtimeConfig.Load().SeedRelays))

	relay.Info = &nip11.RelayInformationDocument{
		Name:        config.RelayName,
		Description: config.RelayDescription,
		Contact:     config.RelayContact,
		Icon:        config.RelayIcon,
		Software:    "https://github.com/barrydeen/wot-relay",
		Version:     version,
	}
	if pk, err := nostr.PubKeyFromHex(config.RelayPubkey); err == nil {
		relay.Info.PubKey = &pk
	}

	appendPubkey(config.RelayPubkey)

	// --- LMDB hardening (ported from cascadia-relay@12ad754) ---
	// The eventstore is the only LMDB handle in this process. Register the path
	// first so any monitor or helper that tries to open it independently fails
	// (lmdb_runtime.go).
	if err := registerLiveLMDBPath(config.DBPath); err != nil {
		log.Fatalf("lmdb live path registration failed: %v", err)
	}
	lmdbRT := newLMDBRuntime(config.DBPath, 0, 0, "")
	lmdbRT.logConfigurationDrift()
	readTracker := &lmdbReadTracker{}
	faultMonitor := installLMDBFaultMonitor() // before the eventstore opens

	// Unclean-exit handling runs before the eventstore opens so the crash-time
	// store is preserved before any write can happen (lmdb_unclean_exit.go).
	if !validUncleanExitPolicy(config.LMDBUncleanExitPolicy) {
		log.Fatalf("invalid LMDB_UNCLEAN_EXIT_POLICY=%q (want %s or %s)", config.LMDBUncleanExitPolicy, uncleanExitPolicyQuarantine, uncleanExitPolicyResume)
	}
	if err := os.MkdirAll(config.DBPath, 0o755); err != nil {
		log.Fatalf("lmdb path: %v", err)
	}
	uncleanCfg := uncleanExitConfig{Policy: config.LMDBUncleanExitPolicy, EvidenceDir: config.LMDBEvidenceDir}
	incident, err := detectUncleanExit(config.DBPath, uncleanCfg)
	if err != nil {
		log.Fatalf("lmdb unclean-exit check failed: %v", err)
	}
	if incident != nil {
		log.Printf("lmdb: previous run (pid %d, started %s) ended uncleanly; evidence=%q snapshot_error=%q policy=%s",
			incident.PreviousRun.PID, incident.PreviousRun.StartedAt.Format(time.RFC3339), incident.EvidenceDir, incident.SnapshotError, incident.Policy)
		if incident.Quarantined {
			qctx, qcancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
			err := holdQuarantine(qctx, fmt.Sprintf("0.0.0.0:%s", config.Port), config.DBPath, incident, quarantinePollInterval)
			qcancel()
			if err != nil {
				log.Printf("lmdb: quarantine ended without release (%v); exiting with store closed", err)
				return
			}
		}
	}

	db = &lmdb.LMDBBackend{Path: config.DBPath}
	// The run sentinel marks the store open by this process; it is cleared on a
	// clean shutdown. A sentinel found at the next startup means an unclean exit.
	if err := writeRunSentinel(config.DBPath, build.Revision); err != nil {
		log.Fatalf("lmdb run sentinel: %v", err)
	}
	if err := db.Init(); err != nil {
		_ = clearRunSentinel(config.DBPath)
		panic(err)
	}
	defer func() {
		log.Println("closing database...")
		db.Close()
		if err := clearRunSentinel(config.DBPath); err != nil {
			log.Printf("lmdb run sentinel not cleared: %v", err)
		}
		log.Println("database closed")
	}()
	store := &trackedStore{inner: db, reads: readTracker}
	relay.UseEventstore(store, 500)

	relay.OnEvent = policies.SeqEvent(
		policies.RejectEventsWithBase64Media,
		policies.EventIPRateLimiter(5, time.Minute*1, 30),
		rejectUntrustedEvent,
	)

	relay.OnRequest = policies.SeqRequest(
		policies.NoEmptyFilters,
		policies.NoComplexFilters,
		policies.FilterIPRateLimiter(5, time.Minute*1, 30),
	)

	relay.RejectConnection = policies.ConnectionRateLimiter(10, time.Minute*2, 30)

	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	defer signal.Stop(reloadSignals)
	runtimeConfigUpdates := make(chan struct{}, 1)
	go handleConfigReloads(ctx, reloadSignals, LoadConfig, config, &runtimeConfig, runtimeConfigUpdates, log.Default())

	go refreshTrustNetwork(ctx, relay, runtimeConfigUpdates)
	go monitorMemoryUsage()
	go monitorPerformance()

	mux := relay.Router()
	static := http.FileServer(http.Dir(config.StaticPath))

	mux.Handle("GET /static/", http.StripPrefix("/static/", static))
	mux.Handle("GET /favicon.ico", http.StripPrefix("/", static))

	mux.HandleFunc("GET /debug/stats", debugStatsHandler)
	mux.HandleFunc("GET /debug/goroutines", debugGoroutinesHandler)
	mux.HandleFunc("GET /health", newHealthHandler(config.RelayName, lmdbRT, readTracker, faultMonitor))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.ParseFiles(config.IndexPath))
		data := struct {
			RelayName        string
			RelayPubkey      string
			RelayDescription string
			RelayURL         string
		}{
			RelayName:        config.RelayName,
			RelayPubkey:      config.RelayPubkey,
			RelayDescription: config.RelayDescription,
			RelayURL:         config.RelayURL,
		}
		err := tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	port := config.Port
	log.Printf("🎉 relay running on port :%s", port)
	log.Println("🔍 debug endpoints available at:")
	log.Printf("   http://localhost:%s/debug/pprof/ (CPU/memory profiling)", port)
	log.Printf("   http://localhost:%s/debug/stats (application stats)", port)
	log.Printf("   http://localhost:%s/debug/goroutines (goroutine info)", port)
	err = http.ListenAndServe(":"+port, relay)
	if err != nil {
		log.Fatal(err)
	}
}

func rejectUntrustedEvent(ctx context.Context, event nostr.Event) (bool, string) {
	atomic.AddUint64(&totalEvents, 1)
	trustNetworkMutex.RLock()
	trusted := trustNetworkMap[event.PubKey.Hex()]
	ready := trustNetworkReady
	trustNetworkMutex.RUnlock()

	// Preserve startup admission until the first build, but never treat an
	// intentionally empty rebuilt graph as permission to accept everyone.
	if !ready {
		return false, ""
	}
	if !trusted {
		atomic.AddUint64(&rejectedEvents, 1)
		return true, "not in web of trust"
	}
	if event.Kind == nostr.KindEncryptedDirectMessage {
		atomic.AddUint64(&rejectedEvents, 1)
		return true, "only gift wrapped DMs are allowed"
	}
	return false, ""
}

func updateTrustNetworkFilter(runtime *RuntimeConfig) {
	// Build new trust network in temporary variables
	newTrustNetworkMap := make(map[string]bool)
	var newTrustNetwork []string
	newTrustNetworkSet := make(map[string]bool)

	log.Println("🌐 building new trust network map")

	followerMutex.RLock()
	// Stable ordering keeps bounded membership deterministic across rebuilds.
	keys := make([]string, 0, len(pubkeyFollowerCount))
	for pubkey := range pubkeyFollowerCount {
		keys = append(keys, pubkey)
	}
	sort.Strings(keys)
	for _, pubkey := range keys {
		if pubkeyFollowerCount[pubkey] >= runtime.MinimumFollowers && len(pubkey) == 64 && len(newTrustNetwork) < runtime.MaxTrustNetwork {
			newTrustNetworkMap[pubkey] = true
			newTrustNetwork = append(newTrustNetwork, pubkey)
			newTrustNetworkSet[pubkey] = true
		}
	}
	followerMutex.RUnlock()

	// Now atomically replace the active trust network
	trustNetworkMutex.Lock()
	trustNetworkMap = newTrustNetworkMap
	trustNetworkReady = true
	trustNetwork = newTrustNetwork
	trustNetworkSet = newTrustNetworkSet
	trustNetworkMutex.Unlock()

	log.Println("🌐 trust network map updated with", len(newTrustNetwork), "keys")

	// Cleanup follower count map periodically to prevent unbounded growth
	followerMutex.Lock()
	if len(pubkeyFollowerCount) > runtime.MaxOneHopNetwork && len(pubkeyFollowerCount)-runtime.MaxOneHopNetwork > runtime.MaxOneHopNetwork {
		log.Println("🧹 cleaning follower count map")
		newFollowerCount := make(map[string]int)
		for pubkey, count := range pubkeyFollowerCount {
			if count >= runtime.MinimumFollowers || newTrustNetworkMap[pubkey] {
				newFollowerCount[pubkey] = count
			}
		}
		oldCount := len(pubkeyFollowerCount)
		pubkeyFollowerCount = newFollowerCount
		log.Printf("🧹 cleaned follower count map: %d -> %d entries", oldCount, len(newFollowerCount))
	}
	followerMutex.Unlock()
}

func hexToPubKeys(hexes []string) []nostr.PubKey {
	out := make([]nostr.PubKey, 0, len(hexes))
	for _, h := range hexes {
		if pk, err := nostr.PubKeyFromHex(h); err == nil {
			out = append(out, pk)
		}
	}
	return out
}

func refreshProfiles(ctx context.Context, runtime *RuntimeConfig) {
	atomic.AddUint64(&profileRefreshCount, 1)
	start := time.Now()

	// Get a snapshot of current trust network to avoid holding locks during network operations
	trustNetworkMutex.RLock()
	currentTrustNetwork := make([]string, len(trustNetwork))
	copy(currentTrustNetwork, trustNetwork)
	trustNetworkMutex.RUnlock()

	const (
		profileBatchSize    = 500
		profileConcurrency  = 5
		profileBatchTimeout = 30 * time.Second
	)

	sem := make(chan struct{}, profileConcurrency)
	var wg sync.WaitGroup

	for i := 0; i < len(currentTrustNetwork); i += profileBatchSize {
		end := i + profileBatchSize
		if end > len(currentTrustNetwork) {
			end = len(currentTrustNetwork)
		}
		batch := currentTrustNetwork[i:end]

		wg.Add(1)
		sem <- struct{}{}
		go func(batch []string) {
			defer wg.Done()
			defer func() { <-sem }()

			timeout, cancel := context.WithTimeout(ctx, profileBatchTimeout)
			defer cancel()

			filter := nostr.Filter{
				Authors: hexToPubKeys(batch),
				Kinds:   []nostr.Kind{nostr.KindProfileMetadata},
			}

			for ev := range pool.FetchMany(timeout, runtime.SeedRelays, filter, nostr.SubscriptionOptions{}) {
				if err := db.SaveEvent(ev.Event); err != nil {
					nostr.InfoLogger.Printf("save profile: %v", err)
				}
			}
		}(batch)
	}
	wg.Wait()
	duration := time.Since(start)
	log.Printf("👤 profiles refreshed: %d profiles in %v", len(currentTrustNetwork), duration)
}

// fetchDiscovery visits deduplicated candidate events, but succeeds only when
// every configured seed explicitly completes its stored-event query. Callers
// must discard candidate state on any error; pool.FetchMany channel closure
// alone also represents connection, CLOSED, timeout and stream failures.
func fetchDiscovery(ctx context.Context, seeds []string, filter nostr.Filter, visit func(nostr.Event)) error {
	if len(seeds) == 0 {
		return fmt.Errorf("discovery requires at least one seed relay")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[nostr.ID]bool)
	var firstErr error
	uniqueSeeds := make(map[string]bool)
	for _, seed := range seeds {
		seed = nostr.NormalizeURL(seed)
		if uniqueSeeds[seed] {
			continue
		}
		uniqueSeeds[seed] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := func() error {
				if err := ctx.Err(); err != nil {
					return err
				}
				relay, err := pool.EnsureRelay(seed)
				if err != nil {
					return err
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				// The dependency otherwise fabricates EOSE after seven seconds.
				// Require the actual protocol frame; ctx bounds failure, not success.
				sub, err := relay.Subscribe(ctx, filter, nostr.SubscriptionOptions{MaxWaitForEOSE: time.Duration(math.MaxInt64)})
				if err != nil {
					return err
				}
				defer sub.Unsub()
				for {
					select {
					case event, ok := <-sub.Events:
						if !ok {
							return fmt.Errorf("discovery stream ended before EOSE")
						}
						mu.Lock()
						if !seen[event.ID] {
							seen[event.ID] = true
							visit(event)
						}
						mu.Unlock()
					case eose := <-sub.EndOfStoredEvents:
						if err := ctx.Err(); err != nil {
							return err
						}
						if slices.Contains(eose.Hint, "more") {
							return fmt.Errorf("discovery EOSE reports incomplete results")
						}
						return nil
					case reason := <-sub.ClosedReason:
						return fmt.Errorf("discovery CLOSED before EOSE: %s", reason)
					case <-sub.Context.Done():
						return fmt.Errorf("discovery ended before EOSE: %w", context.Cause(sub.Context))
					}
				}
			}()
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				cancel()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func refreshTrustNetwork(ctx context.Context, relay *khatru.Relay, configUpdates <-chan struct{}) {
	runTrustNetworkRefresh := func(runtime *RuntimeConfig) error {
		atomic.AddUint64(&networkRefreshCount, 1)
		start := time.Now()

		// Build new networks in temporary variables to avoid disrupting the active network
		var newOneHopNetwork []string
		newOneHopNetworkSet := make(map[string]bool)
		newPubkeyFollowerCount := make(map[string]int)

		// Rebuild counts and relay discovery rather than accumulating the same
		// follows on every reload. Reduced limits must shrink the live inventory.
		var newRelays []string
		newRelaySet := make(map[string]bool)

		timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		ownerPk, err := nostr.PubKeyFromHex(config.RelayPubkey)
		if err != nil {
			return fmt.Errorf("invalid RELAY_PUBKEY: %w", err)
		}
		filter := nostr.Filter{
			Authors: []nostr.PubKey{ownerPk},
			Kinds:   []nostr.Kind{nostr.KindFollowList},
		}

		log.Println("🔍 fetching owner's follows")
		eventCount := 0
		if err := fetchDiscovery(timeoutCtx, runtime.SeedRelays, filter, func(ev nostr.Event) {
			eventCount++
			for contact := range ev.Tags.FindAll("p") {
				if len(contact) < 2 {
					continue
				}
				pubkey := contact[1]
				if isIgnored(pubkey, config.IgnoredPubkeys) {
					fmt.Println("ignoring follows from pubkey: ", pubkey)
					continue
				}
				newPubkeyFollowerCount[pubkey]++

				// Add to new one-hop network
				if !newOneHopNetworkSet[pubkey] && len(pubkey) == 64 && len(newOneHopNetwork) < runtime.MaxOneHopNetwork {
					newOneHopNetwork = append(newOneHopNetwork, pubkey)
					newOneHopNetworkSet[pubkey] = true
				}
			}
		}); err != nil {
			return fmt.Errorf("owner follows: %w", err)
		}
		log.Printf("🔍 processed %d follow list events", eventCount)

		log.Println("🌐 building web of trust graph")
		var totalProcessed int64
		var followerCountMu sync.Mutex

		const (
			wotBatchSize    = 500
			wotConcurrency  = 5
			wotBatchTimeout = 30 * time.Second
		)

		sem := make(chan struct{}, wotConcurrency)
		var wg sync.WaitGroup
		var completedBatches int64
		var discoveryErr error
		totalBatches := (len(newOneHopNetwork) + wotBatchSize - 1) / wotBatchSize

		for i := 0; i < len(newOneHopNetwork); i += wotBatchSize {
			end := i + wotBatchSize
			if end > len(newOneHopNetwork) {
				end = len(newOneHopNetwork)
			}
			batch := newOneHopNetwork[i:end]

			wg.Add(1)
			sem <- struct{}{}
			go func(batch []string) {
				defer wg.Done()
				defer func() { <-sem }()

				timeout, cancel := context.WithTimeout(ctx, wotBatchTimeout)
				defer cancel()

				filter := nostr.Filter{
					Authors: hexToPubKeys(batch),
					Kinds:   []nostr.Kind{nostr.KindFollowList, nostr.KindRelayListMetadata, nostr.KindProfileMetadata},
				}

				err := fetchDiscovery(timeout, runtime.SeedRelays, filter, func(ev nostr.Event) {
					atomic.AddInt64(&totalProcessed, 1)

					followerCountMu.Lock()
					for contact := range ev.Tags.FindAll("p") {
						if len(contact) > 1 {
							newPubkeyFollowerCount[contact[1]]++
						}
					}
					for relayTag := range ev.Tags.FindAll("r") {
						if len(relayTag) > 1 && !newRelaySet[relayTag[1]] && len(newRelays) < runtime.MaxRelays {
							newRelays = append(newRelays, relayTag[1])
							newRelaySet[relayTag[1]] = true
						}
					}

					followerCountMu.Unlock()

					if ev.Kind == nostr.KindProfileMetadata {
						if err := db.SaveEvent(ev); err != nil {
							nostr.InfoLogger.Printf("save profile: %v", err)
						}
					}
				})
				if err != nil {
					followerCountMu.Lock()
					if discoveryErr == nil {
						discoveryErr = err
					}
					followerCountMu.Unlock()
					return
				}

				done := atomic.AddInt64(&completedBatches, 1)
				if done%10 == 0 || done == int64(totalBatches) {
					log.Printf("🌐 wot graph: %d/%d batches complete (%d events so far)",
						done, totalBatches, atomic.LoadInt64(&totalProcessed))
				}
			}(batch)
		}
		wg.Wait()
		if discoveryErr != nil {
			return fmt.Errorf("one-hop discovery: %w", discoveryErr)
		}

		relayMutex.Lock()
		relays = newRelays
		relayMutex.Unlock()

		// Now atomically replace the active data structures
		oneHopMutex.Lock()
		oneHopNetwork = newOneHopNetwork
		oneHopNetworkSet = newOneHopNetworkSet
		oneHopMutex.Unlock()

		followerMutex.Lock()
		pubkeyFollowerCount = newPubkeyFollowerCount
		followerMutex.Unlock()

		duration := time.Since(start)
		log.Printf("🫂 total network size: %d (processed %d events in %v)", len(newPubkeyFollowerCount), atomic.LoadInt64(&totalProcessed), duration)
		relayMutex.RLock()
		log.Println("🔗 relays discovered:", len(relays))
		relayMutex.RUnlock()
		return nil
	}

	// Run initial refresh
	log.Println("🚀 performing initial trust network build...")
	initial := runtimeConfig.Load()
	initialErr := runTrustNetworkRefresh(initial)
	if initialErr != nil {
		// There is no successful graph to retain at startup. Do not leave the
		// temporary pre-build admission window open after discovery fails.
		trustNetworkMutex.Lock()
		trustNetworkReady = true
		trustNetworkMutex.Unlock()
		log.Printf("initial trust network discovery failed; no graph available; rejecting untrusted publications: %v", initialErr)
	} else {
		updateTrustNetworkFilter(initial)
		log.Println("✅ trust network initialized, relay is now active")
	}

	if err := deleteOldNotes(); err != nil {
		log.Printf("delete old notes: %v", err)
	}

	var cancelArchive context.CancelFunc
	startArchive := func(runtime *RuntimeConfig) {
		archiveCtx, cancel := context.WithCancel(ctx)
		cancelArchive = cancel
		go archiveTrustedNotes(archiveCtx, relay, runtime)
	}
	stopArchive := func() {
		if cancelArchive != nil {
			cancelArchive()
			cancelArchive = nil
		}
	}
	defer stopArchive()
	if initialErr == nil {
		startArchive(initial)
	}

	runRefreshSchedule(ctx, configUpdates, func(reloaded bool, runtime *RuntimeConfig) {
		if reloaded {
			log.Println("🔄 runtime configuration changed; refreshing trust network immediately...")
		} else {
			log.Println("🔄 refreshing trust network in background...")
		}
		if err := runTrustNetworkRefresh(runtime); err != nil {
			log.Printf("trust network discovery failed; keeping last-successful graph: %v", err)
			return
		}
		stopArchive()
		updateTrustNetworkFilter(runtime)
		if err := deleteOldNotes(); err != nil {
			log.Printf("delete old notes: %v", err)
		}
		startArchive(runtime)
		log.Println("✅ trust network refresh completed")
	}, newRefreshTicker)
}

type refreshTicker interface {
	Chan() <-chan time.Time
	Reset(time.Duration)
	Stop()
}

type realRefreshTicker struct {
	*time.Ticker
}

func (t *realRefreshTicker) Chan() <-chan time.Time {
	return t.C
}

func newRefreshTicker(interval time.Duration) refreshTicker {
	return &realRefreshTicker{Ticker: time.NewTicker(interval)}
}

func runRefreshSchedule(
	ctx context.Context,
	configUpdates <-chan struct{},
	refresh func(reloaded bool, runtime *RuntimeConfig),
	newTicker func(time.Duration) refreshTicker,
) {
	ticker := newTicker(runtimeConfig.Load().RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.Chan():
			refresh(false, runtimeConfig.Load())
		case _, ok := <-configUpdates:
			if !ok {
				return
			}
			runtime := runtimeConfig.Load()
			ticker.Reset(runtime.RefreshInterval)
			refresh(true, runtime)
		}
	}
}

func appendPubkey(pubkey string) {
	runtime := runtimeConfig.Load()
	trustNetworkMutex.Lock()
	defer trustNetworkMutex.Unlock()

	if len(trustNetwork) >= runtime.MaxTrustNetwork {
		return // Prevent unbounded growth
	}

	if trustNetworkSet[pubkey] {
		return // Already exists
	}

	if len(pubkey) != 64 {
		return
	}

	trustNetwork = append(trustNetwork, pubkey)
	trustNetworkSet[pubkey] = true
}

func archiveTrustedNotes(ctx context.Context, relay *khatru.Relay, runtimeCfg *RuntimeConfig) {
	timeout, cancel := context.WithTimeout(ctx, runtimeCfg.RefreshInterval)
	defer cancel()

	if !config.ArchivalSync {
		log.Println("🔄 web of trust will refresh in", runtimeCfg.RefreshInterval)
		<-timeout.Done()
		return
	}

	go refreshProfiles(timeout, runtimeCfg)

	filter := nostr.Filter{
		Kinds: config.ArchiveKinds,
		Since: nostr.Now(),
	}

	log.Println("📦 archiving trusted notes...")
	eventCount := 0
	for ev := range pool.SubscribeMany(timeout, runtimeCfg.SeedRelays, filter, nostr.SubscriptionOptions{}) {
		eventCount++

		// Check GC pressure every 1000 events
		if eventCount%1000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.NumGC > 0 && eventCount > 1000 {
				gcRate := float64(m.NumGC) / float64(eventCount/1000)
				if gcRate > 2.0 {
					log.Printf("⚠️ High GC pressure (%.1f GC/1000 events), slowing archive process", gcRate)
					time.Sleep(100 * time.Millisecond)
				}
			}
		}

		// Use semaphore to limit concurrent goroutines
		select {
		case archiveEventSemaphore <- struct{}{}:
			go func(event nostr.Event) {
				defer func() { <-archiveEventSemaphore }()
				archiveEvent(timeout, relay, event)
			}(ev.Event)
		case <-timeout.Done():
			log.Printf("📦 archive cycle stopped, processed %d events", eventCount)
			return
		default:
			archiveEvent(timeout, relay, ev.Event)
		}
	}

	log.Printf("📦 archived %d trusted notes and discarded %d untrusted notes (processed %d total events)",
		atomic.LoadUint64(&trustedNotes), atomic.LoadUint64(&untrustedNotes), eventCount)
}

func archiveEvent(ctx context.Context, relay *khatru.Relay, ev nostr.Event) {
	trustNetworkMutex.RLock()
	trusted := trustNetworkMap[ev.PubKey.Hex()]
	trustNetworkMutex.RUnlock()

	if trusted {
		if err := db.SaveEvent(ev); err != nil {
			nostr.InfoLogger.Printf("save event: %v", err)
		}
		relay.BroadcastEvent(ev)
		atomic.AddUint64(&trustedNotes, 1)
		atomic.AddUint64(&archivedEvents, 1)
	} else {
		atomic.AddUint64(&untrustedNotes, 1)
	}
}

func deleteOldNotes() error {
	if config.MaxAgeDays <= 0 {
		log.Printf("MAX_AGE_DAYS disabled")
		return nil
	}

	maxAgeSecs := nostr.Timestamp(config.MaxAgeDays * 86400)
	oldAge := nostr.Now() - maxAgeSecs
	if oldAge <= 0 {
		log.Printf("MAX_AGE_DAYS too large")
		return nil
	}

	filter := nostr.Filter{
		Until: oldAge,
		Kinds: config.ArchiveKinds,
		Limit: 1000,
	}

	count := 0
	for evt := range db.QueryEvents(filter, 1000) {
		if err := db.DeleteEvent(evt.ID); err != nil {
			log.Printf("error deleting note %s: %v", evt.ID, err)
			return err
		}
		count++
	}

	if count == 0 {
		log.Println("0 old notes found")
	} else {
		log.Printf("%d old (until %d) notes deleted", count, oldAge)
	}

	return nil
}

func isIgnored(pubkey string, ignoredPubkeys []string) bool {
	for _, ignored := range ignoredPubkeys {
		if pubkey == ignored {
			return true
		}
	}
	return false
}

// Add memory monitoring
func monitorMemoryUsage() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		relayMutex.RLock()
		relayCount := len(relays)
		relayMutex.RUnlock()

		trustNetworkMutex.RLock()
		trustNetworkCount := len(trustNetwork)
		trustNetworkMutex.RUnlock()

		oneHopMutex.RLock()
		oneHopCount := len(oneHopNetwork)
		oneHopMutex.RUnlock()

		followerMutex.RLock()
		followerCount := len(pubkeyFollowerCount)
		followerMutex.RUnlock()

		log.Printf("📊 Memory: Alloc=%d KB, Sys=%d KB, NumGC=%d",
			m.Alloc/1024, m.Sys/1024, m.NumGC)
		log.Printf("📊 Data structures: Relays=%d, TrustNetwork=%d, OneHop=%d, Followers=%d",
			relayCount, trustNetworkCount, oneHopCount, followerCount)
	}
}

// Add performance monitoring
func monitorPerformance() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	var lastGC uint32
	var lastEvents, lastRejected, lastArchived uint64

	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		currentEvents := atomic.LoadUint64(&totalEvents)
		currentRejected := atomic.LoadUint64(&rejectedEvents)
		currentArchived := atomic.LoadUint64(&archivedEvents)

		eventsPerMin := currentEvents - lastEvents
		rejectedPerMin := currentRejected - lastRejected
		archivedPerMin := currentArchived - lastArchived
		gcPerMin := m.NumGC - lastGC

		numGoroutines := runtime.NumGoroutine()

		log.Printf("⚡ Performance: Events/min=%d, Rejected/min=%d, Archived/min=%d, GC/min=%d, Goroutines=%d",
			eventsPerMin, rejectedPerMin, archivedPerMin, gcPerMin, numGoroutines)

		if gcPerMin > 60 {
			log.Printf("⚠️  HIGH GC ACTIVITY: %d garbage collections in last minute!", gcPerMin)
		}

		if numGoroutines > 1000 {
			log.Printf("⚠️  HIGH GOROUTINE COUNT: %d goroutines active!", numGoroutines)
		}

		lastGC = m.NumGC
		lastEvents = currentEvents
		lastRejected = currentRejected
		lastArchived = currentArchived
	}
}

// Debug handlers
func debugStatsHandler(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	relayMutex.RLock()
	relayCount := len(relays)
	relayMutex.RUnlock()
	trustNetworkMutex.RLock()
	trustCount := len(trustNetwork)
	trustNetworkMutex.RUnlock()
	oneHopMutex.RLock()
	oneHopCount := len(oneHopNetwork)
	oneHopMutex.RUnlock()
	followerMutex.RLock()
	followerCount := len(pubkeyFollowerCount)
	followerMutex.RUnlock()

	stats := fmt.Sprintf(`Debug Statistics:

Memory:
  Allocated: %d KB
  System: %d KB
  Total Allocations: %d
  GC Cycles: %d
  Goroutines: %d

Events:
  Total Events: %d
  Rejected Events: %d
  Archived Events: %d
  Trusted Notes: %d
  Untrusted Notes: %d

Refreshes:
  Profile Refreshes: %d
  Network Refreshes: %d

Data Structures:
  Relays: %d
  Trust Network: %d
  One Hop Network: %d
  Follower Count Map: %d
`,
		m.Alloc/1024,
		m.Sys/1024,
		m.Mallocs,
		m.NumGC,
		runtime.NumGoroutine(),
		atomic.LoadUint64(&totalEvents),
		atomic.LoadUint64(&rejectedEvents),
		atomic.LoadUint64(&archivedEvents),
		atomic.LoadUint64(&trustedNotes),
		atomic.LoadUint64(&untrustedNotes),
		atomic.LoadUint64(&profileRefreshCount),
		atomic.LoadUint64(&networkRefreshCount),
		relayCount,
		trustCount,
		oneHopCount,
		followerCount,
	)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(stats))
}

func debugGoroutinesHandler(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 1<<20)
	stackSize := runtime.Stack(buf, true)

	w.Header().Set("Content-Type", "text/plain")
	w.Write(buf[:stackSize])
}

// defaultLMDBMapSize is the map size reported for the live environment when the
// operator has not configured one. Ported from cascadia-relay@12ad754.
const defaultLMDBMapSize int64 = 1 << 38

func effectiveLMDBMapSize(mapSize int64) int64 {
	if mapSize > 0 {
		return mapSize
	}
	return defaultLMDBMapSize
}

func choose(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// trackedStore wraps the eventstore so every read transaction served through
// khatru is counted for /health and the reader monitor. It never opens a
// second LMDB environment; it only delegates to the single live backend.
// Ported from cascadia-relay@12ad754 (lockedStore, read-tracking subset).
type trackedStore struct {
	inner eventstore.Store
	reads *lmdbReadTracker
}

func (s *trackedStore) Init() error { return s.inner.Init() }

func (s *trackedStore) Close() { s.inner.Close() }

func (s *trackedStore) QueryEvents(filter nostr.Filter, maxLimit int) iter.Seq[nostr.Event] {
	seq := s.inner.QueryEvents(filter, maxLimit)
	if s.reads == nil {
		return seq
	}
	return s.reads.trackQuery(seq)
}

func (s *trackedStore) CountEvents(filter nostr.Filter) (uint32, error) {
	if s.reads != nil {
		s.reads.begin()
		defer s.reads.end()
	}
	return s.inner.CountEvents(filter)
}

func (s *trackedStore) SaveEvent(evt nostr.Event) error { return s.inner.SaveEvent(evt) }

func (s *trackedStore) ReplaceEvent(evt nostr.Event) ([]nostr.Event, error) {
	return s.inner.ReplaceEvent(evt)
}

func (s *trackedStore) DeleteEvent(id nostr.ID) error { return s.inner.DeleteEvent(id) }

// newHealthHandler reports relay identity plus LMDB state derived only from
// configuration and in-process counters. It must never open the live
// environment; see lmdb_runtime.go. It answers 503 status=degraded once any
// eventstore fault signature has been observed (lmdb_fault_monitor.go).
// Ported from cascadia-relay@12ad754.
func newHealthHandler(relayName string, lmdbRT lmdbRuntime, tracker *lmdbReadTracker, faults *lmdbFaultMonitor) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var divergence lmdbFaultSnapshot
		if faults != nil {
			divergence = faults.snapshot()
		}
		status, code := "ok", http.StatusOK
		if divergence.Detected {
			status, code = "degraded", http.StatusServiceUnavailable
		}
		body := map[string]any{
			"ok":                    !divergence.Detected,
			"status":                status,
			"lmdb_index_divergence": divergence,
			"name":                  relayName,
			"build":                 buildInfo(),
			"db":                    lmdbRT.Path,
			"backend":               "lmdb",
		}
		for k, v := range lmdbHealthFields(lmdbRT, tracker) {
			body[k] = v
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}
}
