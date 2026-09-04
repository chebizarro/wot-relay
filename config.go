package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"github.com/joho/godotenv"
)

type Config struct {
	RelayName        string
	RelayPubkey      string
	RelayDescription string
	DBPath           string
	RelayURL         string
	IndexPath        string
	StaticPath       string
	Port             string
	RefreshInterval  int
	MinimumFollowers int
	ArchivalSync     bool
	RelayContact     string
	RelayIcon        string
	MaxAgeDays       int
	ArchiveReactions bool
	IgnoredPubkeys   []string
	MaxTrustNetwork  int
	MaxRelays        int
	MaxOneHopNetwork int
	SeedRelays       []string
	ArchiveKinds     []nostr.Kind
}

var defaultSeedRelays = []string{
	"wss://nos.lol",
	"wss://nostr.mom",
	"wss://purplepag.es",
	"wss://purplerelay.com",
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://relay.snort.social",
	"wss://relayable.org",
	"wss://relay.primal.net",
	"wss://relay.nostr.bg",
	"wss://no.str.cr",
	"wss://nostr21.com",
	"wss://nostrue.com",
	"wss://relay.siamstr.com",
}

var defaultArchiveKinds = []nostr.Kind{
	nostr.KindArticle,
	nostr.KindDeletion,
	nostr.KindFollowList,
	nostr.KindEncryptedDirectMessage,
	nostr.KindMuteList,
	nostr.KindRelayListMetadata,
	nostr.KindRepost,
	nostr.KindZapRequest,
	nostr.KindZap,
	nostr.KindTextNote,
}

// RuntimeConfig is the immutable subset that may change without restarting.
// Slices are copied before publication and must not be mutated by readers.
type RuntimeConfig struct {
	RefreshInterval  time.Duration
	MinimumFollowers int
	MaxTrustNetwork  int
	MaxRelays        int
	MaxOneHopNetwork int
	SeedRelays       []string
}

type runtimeConfigStore struct {
	current atomic.Pointer[RuntimeConfig]
}

func (s *runtimeConfigStore) Store(cfg Config) {
	s.current.Store(&RuntimeConfig{
		RefreshInterval:  time.Duration(cfg.RefreshInterval) * time.Hour,
		MinimumFollowers: cfg.MinimumFollowers,
		MaxTrustNetwork:  cfg.MaxTrustNetwork,
		MaxRelays:        cfg.MaxRelays,
		MaxOneHopNetwork: cfg.MaxOneHopNetwork,
		SeedRelays:       append([]string(nil), cfg.SeedRelays...),
	})
}

func (s *runtimeConfigStore) Load() *RuntimeConfig {
	current := s.current.Load()
	if current == nil {
		panic("runtime config loaded before initialization")
	}
	return current
}

// LoadConfig rereads the process environment and .env (with the file taking
// precedence), applies defaults without mutating os.Environ, and returns only
// validated candidates.
func LoadConfig() (Config, error) {
	return loadConfig(".env", os.Environ())
}

func loadConfig(dotEnvPath string, environ []string) (Config, error) {
	values := make(map[string]string)
	dotEnv, err := godotenv.Read(dotEnvPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("read %s: %w", dotEnvPath, err)
	}
	for _, entry := range environ {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	// The file is the reloadable source of truth. Environment values remain a
	// fallback for deployments without a file or for keys omitted from it.
	for key, value := range dotEnv {
		values[key] = value
	}

	required := func(key string) (string, error) {
		value := strings.TrimSpace(values[key])
		if value == "" {
			return "", fmt.Errorf("environment variable %s must be set", key)
		}
		return value, nil
	}
	withDefault := func(key, fallback string) string {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
		return fallback
	}
	parseInt := func(key string, fallback, minimum int) (int, error) {
		raw := withDefault(key, strconv.Itoa(fallback))
		value, parseErr := strconv.Atoi(raw)
		if parseErr != nil || value < minimum {
			return 0, fmt.Errorf("%s must be an integer >= %d, got %q", key, minimum, raw)
		}
		return value, nil
	}
	parseBool := func(key string, fallback bool) (bool, error) {
		raw := strings.ToUpper(withDefault(key, strconv.FormatBool(fallback)))
		switch raw {
		case "TRUE":
			return true, nil
		case "FALSE":
			return false, nil
		default:
			return false, fmt.Errorf("%s must be TRUE or FALSE, got %q", key, raw)
		}
	}

	relayName, err := required("RELAY_NAME")
	if err != nil {
		return Config{}, err
	}
	relayPubkey, err := required("RELAY_PUBKEY")
	if err != nil {
		return Config{}, err
	}
	if _, err := nostr.PubKeyFromHex(relayPubkey); err != nil {
		return Config{}, fmt.Errorf("RELAY_PUBKEY must be a valid hex pubkey: %w", err)
	}
	relayDescription, err := required("RELAY_DESCRIPTION")
	if err != nil {
		return Config{}, err
	}
	dbPath, err := required("DB_PATH")
	if err != nil {
		return Config{}, err
	}
	relayURL, err := required("RELAY_URL")
	if err != nil {
		return Config{}, err
	}
	if err := validateWebsocketURL("RELAY_URL", relayURL); err != nil {
		return Config{}, err
	}
	indexPath, err := required("INDEX_PATH")
	if err != nil {
		return Config{}, err
	}
	staticPath, err := required("STATIC_PATH")
	if err != nil {
		return Config{}, err
	}

	refreshInterval, err := parseInt("REFRESH_INTERVAL_HOURS", 3, 1)
	if err != nil {
		return Config{}, err
	}
	minimumFollowers, err := parseInt("MINIMUM_FOLLOWERS", 1, 0)
	if err != nil {
		return Config{}, err
	}
	maxAgeDays, err := parseInt("MAX_AGE_DAYS", 0, 0)
	if err != nil {
		return Config{}, err
	}
	maxTrustNetwork, err := parseInt("MAX_TRUST_NETWORK", 40000, 1)
	if err != nil {
		return Config{}, err
	}
	maxRelays, err := parseInt("MAX_RELAYS", 1000, 1)
	if err != nil {
		return Config{}, err
	}
	maxOneHopNetwork, err := parseInt("MAX_ONE_HOP_NETWORK", 50000, 1)
	if err != nil {
		return Config{}, err
	}
	archivalSync, err := parseBool("ARCHIVAL_SYNC", true)
	if err != nil {
		return Config{}, err
	}
	archiveReactions, err := parseBool("ARCHIVE_REACTIONS", false)
	if err != nil {
		return Config{}, err
	}
	port := withDefault("PORT", "3334")
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return Config{}, fmt.Errorf("PORT must be an integer between 1 and 65535, got %q", port)
	}

	seedRelays := append([]string(nil), defaultSeedRelays...)
	if raw := strings.TrimSpace(values["SEED_RELAYS"]); raw != "" {
		seedRelays, err = parseCSV("SEED_RELAYS", raw)
		if err != nil {
			return Config{}, err
		}
	}
	for _, relay := range seedRelays {
		if err := validateWebsocketURL("SEED_RELAYS", relay); err != nil {
			return Config{}, err
		}
	}

	ignoredPubkeys := []string{}
	if raw := strings.TrimSpace(values["IGNORE_FOLLOWS_LIST"]); raw != "" {
		ignoredPubkeys, err = parseCSV("IGNORE_FOLLOWS_LIST", raw)
		if err != nil {
			return Config{}, err
		}
	}

	archiveKinds := append([]nostr.Kind(nil), defaultArchiveKinds...)
	if raw := strings.TrimSpace(values["ARCHIVE_KINDS"]); raw != "" {
		kindStrings, parseErr := parseCSV("ARCHIVE_KINDS", raw)
		if parseErr != nil {
			return Config{}, parseErr
		}
		archiveKinds = make([]nostr.Kind, 0, len(kindStrings))
		for _, kindString := range kindStrings {
			kind, parseErr := strconv.Atoi(kindString)
			if parseErr != nil || kind < 0 || kind > 65535 {
				return Config{}, fmt.Errorf("ARCHIVE_KINDS contains invalid kind %q", kindString)
			}
			archiveKinds = append(archiveKinds, nostr.Kind(kind))
		}
	}
	if archiveReactions && !containsKind(archiveKinds, nostr.KindReaction) {
		archiveKinds = append(archiveKinds, nostr.KindReaction)
	}

	return Config{
		RelayName:        relayName,
		RelayPubkey:      relayPubkey,
		RelayDescription: relayDescription,
		RelayContact:     withDefault("RELAY_CONTACT", relayPubkey),
		RelayIcon:        withDefault("RELAY_ICON", "https://pfp.nostr.build/56306a93a88d4c657d8a3dfa57b55a4ed65b709eee927b5dafaab4d5330db21f.png"),
		DBPath:           dbPath,
		RelayURL:         relayURL,
		IndexPath:        indexPath,
		StaticPath:       staticPath,
		Port:             port,
		RefreshInterval:  refreshInterval,
		MinimumFollowers: minimumFollowers,
		ArchivalSync:     archivalSync,
		MaxAgeDays:       maxAgeDays,
		ArchiveReactions: archiveReactions,
		IgnoredPubkeys:   ignoredPubkeys,
		MaxTrustNetwork:  maxTrustNetwork,
		MaxRelays:        maxRelays,
		MaxOneHopNetwork: maxOneHopNetwork,
		SeedRelays:       seedRelays,
		ArchiveKinds:     archiveKinds,
	}, nil
}

func parseCSV(key, raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			return nil, fmt.Errorf("%s must not contain empty entries", key)
		}
		values = append(values, value)
	}
	return values, nil
}

func validateWebsocketURL(key, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
		return fmt.Errorf("%s contains invalid websocket URL %q", key, raw)
	}
	return nil
}

func containsKind(kinds []nostr.Kind, target nostr.Kind) bool {
	for _, kind := range kinds {
		if kind == target {
			return true
		}
	}
	return false
}

func handleConfigReloads(
	ctx context.Context,
	signals <-chan os.Signal,
	load func() (Config, error),
	startup Config,
	store *runtimeConfigStore,
	updates chan<- struct{},
	logger *log.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			logger.Println("SIGHUP received; reloading runtime configuration")
			if err := reloadRuntimeConfig(load, startup, store, updates, logger); err != nil {
				logger.Printf("config reload failed; keeping last-valid runtime configuration: %v", err)
			}
		}
	}
}

func reloadRuntimeConfig(
	load func() (Config, error),
	startup Config,
	store *runtimeConfigStore,
	updates chan<- struct{},
	logger *log.Logger,
) error {
	candidate, err := load()
	if err != nil {
		return err
	}
	if candidate.RelayPubkey != startup.RelayPubkey {
		logger.Println("RELAY_PUBKEY changed on SIGHUP; root pubkey changes require a restart; keeping startup root pubkey")
	}
	if changes := restartOnlyConfigChanges(startup, candidate); len(changes) > 0 {
		logger.Printf("restart-only configuration changed on SIGHUP; keeping startup values until restart: %s", strings.Join(changes, ", "))
	}

	store.Store(candidate)
	logger.Printf(
		"runtime configuration reloaded: refresh_interval=%s minimum_followers=%d max_trust_network=%d max_relays=%d max_one_hop_network=%d seed_relays=%d",
		store.Load().RefreshInterval,
		candidate.MinimumFollowers,
		candidate.MaxTrustNetwork,
		candidate.MaxRelays,
		candidate.MaxOneHopNetwork,
		len(candidate.SeedRelays),
	)
	select {
	case updates <- struct{}{}:
	default:
	}
	return nil
}

func restartOnlyConfigChanges(startup, candidate Config) []string {
	changes := make([]string, 0)
	changed := func(name string, differs bool) {
		if differs {
			changes = append(changes, name)
		}
	}
	changed("RELAY_NAME", startup.RelayName != candidate.RelayName)
	changed("RELAY_DESCRIPTION", startup.RelayDescription != candidate.RelayDescription)
	changed("RELAY_CONTACT", startup.RelayContact != candidate.RelayContact)
	changed("RELAY_ICON", startup.RelayIcon != candidate.RelayIcon)
	changed("DB_PATH", startup.DBPath != candidate.DBPath)
	changed("RELAY_URL", startup.RelayURL != candidate.RelayURL)
	changed("INDEX_PATH", startup.IndexPath != candidate.IndexPath)
	changed("STATIC_PATH", startup.StaticPath != candidate.StaticPath)
	changed("PORT", startup.Port != candidate.Port)
	changed("ARCHIVAL_SYNC", startup.ArchivalSync != candidate.ArchivalSync)
	changed("MAX_AGE_DAYS", startup.MaxAgeDays != candidate.MaxAgeDays)
	changed("ARCHIVE_REACTIONS", startup.ArchiveReactions != candidate.ArchiveReactions)
	changed("IGNORE_FOLLOWS_LIST", !slices.Equal(startup.IgnoredPubkeys, candidate.IgnoredPubkeys))
	changed("ARCHIVE_KINDS", !slices.Equal(startup.ArchiveKinds, candidate.ArchiveKinds))
	return changes
}
