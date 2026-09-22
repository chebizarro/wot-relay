// Ported from cascadia-relay@12ad754
package main

import (
	"strings"
	"testing"
)

// The test binary carries the toolchain's build info, so module provenance
// must be reported for the storage-critical dependencies even without the
// Dockerfile's link-time variables.
func TestBuildInfoReportsStorageDependencyProvenance(t *testing.T) {
	p := buildInfo()
	for _, mod := range provenanceModules {
		v, ok := p.Modules[mod]
		if !ok || v == "" {
			t.Fatalf("provenance missing for %s: %+v", mod, p)
		}
	}
	if !strings.Contains(p.Modules["github.com/PowerDNS/lmdb-go"], "v1.9.3") {
		t.Fatalf("unexpected lmdb-go provenance %q", p.Modules["github.com/PowerDNS/lmdb-go"])
	}
	if !strings.HasPrefix(p.LMDBEngine, "LMDB 0.9.33") {
		t.Fatalf("unexpected LMDB engine version %q", p.LMDBEngine)
	}
	if p.GoVersion == "" || p.Revision == "" {
		t.Fatalf("incomplete provenance: %+v", p)
	}
}

func TestDefaultRelayVersionCarriesRevisionWhenKnown(t *testing.T) {
	prev := buildRevision
	t.Cleanup(func() { buildRevision = prev })

	buildRevision = ""
	if v := defaultRelayVersion(); v != "khatru-lmdb-docker" && !strings.HasPrefix(v, "khatru-lmdb-docker+") {
		t.Fatalf("unexpected default version %q", v)
	}
	buildRevision = "e3f0f5105cd2da9fba4ff7ca652a8dca371922fb"
	if v := defaultRelayVersion(); v != "khatru-lmdb-docker+e3f0f51" {
		t.Fatalf("version with revision = %q", v)
	}
}
