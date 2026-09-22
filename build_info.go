// Ported from cascadia-relay@12ad754
package main

// Build and dependency provenance.
//
// The 2026-09 incidents were investigated against an image whose source
// revision was known only from deploy notes. Every binary now carries its own
// provenance: the source revision and build time injected by the Dockerfile
// (-ldflags -X), the Go module graph recorded by the toolchain, and the LMDB
// engine version compiled into lmdb-go. /health and the startup log line
// report all of it; the image additionally ships /app/PROVENANCE.txt
// (`go version -m` output) and OCI labels.

import (
	"runtime"
	"runtime/debug"
)

// Set at link time by the Dockerfile:
//
//	-X main.buildRevision=<git sha> -X main.buildSource=<repo url> -X main.buildTime=<RFC3339>
var (
	buildRevision = ""
	buildSource   = ""
	buildTime     = ""
)

// Modules whose exact revision matters for storage behaviour.
var provenanceModules = []string{
	"fiatjaf.com/nostr",
	"github.com/PowerDNS/lmdb-go",
}

type buildProvenance struct {
	Revision    string            `json:"revision"`
	Source      string            `json:"source,omitempty"`
	BuildTime   string            `json:"build_time,omitempty"`
	GoVersion   string            `json:"go_version"`
	MainModule  string            `json:"main_module,omitempty"`
	Modules     map[string]string `json:"modules"` // path -> version[+sum]
	LMDBEngine  string            `json:"lmdb_engine"`
	VCSModified string            `json:"vcs_modified,omitempty"`
}

// buildInfo assembles provenance from link-time variables and the toolchain's
// embedded build info. It never fails; unknown fields are reported as such so
// an image built outside the Dockerfile is visibly unlabelled.
func buildInfo() buildProvenance {
	p := buildProvenance{
		Revision:   choose(buildRevision, "unknown"),
		Source:     buildSource,
		BuildTime:  buildTime,
		GoVersion:  runtime.Version(),
		Modules:    map[string]string{},
		LMDBEngine: lmdbEngineVersion(),
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return p
	}
	p.MainModule = info.Main.Path
	for _, dep := range info.Deps {
		for _, want := range provenanceModules {
			if dep.Path == want {
				v := dep.Version
				if dep.Replace != nil {
					v = dep.Replace.Path + "@" + dep.Replace.Version
				}
				if dep.Sum != "" {
					v += " " + dep.Sum
				}
				p.Modules[dep.Path] = v
			}
		}
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if buildRevision == "" {
				p.Revision = s.Value
			}
		case "vcs.modified":
			p.VCSModified = s.Value
		}
	}
	return p
}

// defaultRelayVersion is the NIP-11 "version" when the operator has not set
// one: the software label plus the short source revision, so a relay's
// running code is identifiable from the outside.
func defaultRelayVersion() string {
	p := buildInfo()
	if p.Revision == "unknown" {
		return "khatru-lmdb-docker"
	}
	return "khatru-lmdb-docker+" + p.shortRevision()
}

// shortRevision is the 7-character form used in image tags and NIP-11.
func (p buildProvenance) shortRevision() string {
	if len(p.Revision) >= 7 && p.Revision != "unknown" {
		return p.Revision[:7]
	}
	return p.Revision
}
