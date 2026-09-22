// Ported from cascadia-relay@12ad754
package main

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	plmdb "github.com/PowerDNS/lmdb-go/lmdb"
)

// TestLiveLMDBPathGuardRefusesSecondOpen: once the eventstore path is
// registered, no relay code can open it again, under any spelling.
func TestLiveLMDBPathGuardRefusesSecondOpen(t *testing.T) {
	resetLiveLMDBPath()
	t.Cleanup(resetLiveLMDBPath)

	root := t.TempDir()
	live := filepath.Join(root, "lmdb-live")
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "current")
	if err := os.Symlink(live, link); err != nil {
		t.Fatal(err)
	}
	if err := registerLiveLMDBPath(link); err != nil {
		t.Fatalf("register via symlink: %v", err)
	}

	for _, alias := range []string{live, link, filepath.Join(root, "x", "..", "lmdb-live"), live + string(filepath.Separator)} {
		env, err := openAuxiliaryLMDBEnv(alias, 1<<20, 16, 0)
		if env != nil {
			env.Close()
		}
		if !errors.Is(err, errLMDBLivePathOpen) {
			t.Fatalf("alias %q: expected errLMDBLivePathOpen, got env=%v err=%v", alias, env != nil, err)
		}
	}

	// A different path is still permitted (offline tooling on a copy).
	other := filepath.Join(root, "copy")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	env, err := openAuxiliaryLMDBEnv(other, 1<<20, 16, 0)
	if err != nil {
		t.Fatalf("non-live path should open: %v", err)
	}
	env.Close()

	// Registering a second, different live path is a startup failure.
	if err := registerLiveLMDBPath(other); err == nil {
		t.Fatal("registering a second live path must fail")
	}
}

// TestNoIndependentLMDBEnvInRelayPackage enforces the invariant statically:
// the only production call to lmdb.NewEnv in this package is the guarded
// helper in lmdb_runtime.go. Any new monitor or probe that opens its own
// environment fails this test before it can reach production. The scan covers
// only the relay's own package (the current directory); the separate binaries
// under tools/ and cmd/import-jsonl legitimately open LMDB and are not scanned.
func TestNoIndependentLMDBEnvInRelayPackage(t *testing.T) {
	const allowedFile = "lmdb_runtime.go"
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			text := string(src)
			if filepath.Base(name) == allowedFile {
				if strings.Count(text, "NewEnv(") != 1 {
					t.Fatalf("%s must contain exactly one NewEnv call (the guarded helper)", allowedFile)
				}
				continue
			}
			for _, imp := range file.Imports {
				if strings.Contains(imp.Path.Value, "lmdb-go") {
					offenders = append(offenders, name+" imports lmdb-go")
				}
			}
			if strings.Contains(text, "NewEnv(") {
				offenders = append(offenders, name+" calls NewEnv")
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("independent LMDB environment use outside %s:\n  %s", allowedFile, strings.Join(offenders, "\n  "))
	}
	_ = plmdb.NoTLS // keep the import honest: tests may use lmdb-go, production files may not
}

// TestNostrlibLMDBMaxReadersPinned keeps the reported reader ceiling honest by
// checking the vendored eventstore source for the value it hardcodes.
func TestNostrlibLMDBMaxReadersPinned(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "fiatjaf.com/nostr").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	src, err := os.ReadFile(filepath.Join(dir, "eventstore", "lmdb", "lib.go"))
	if err != nil {
		t.Fatal(err)
	}
	want := "env.SetMaxReaders(" + strconv.Itoa(nostrlibLMDBMaxReaders) + ")"
	if !strings.Contains(string(src), want) {
		t.Fatalf("nostrlib eventstore no longer sets %s; update nostrlibLMDBMaxReaders", want)
	}
	for _, flag := range []string{"NoSync", "NoMetaSync", "MapAsync"} {
		if strings.Contains(string(src), "lmdb."+flag) {
			t.Fatalf("nostrlib eventstore now references lmdb.%s; lmdbEffectiveSyncMode may be wrong", flag)
		}
	}
}

func TestLMDBReadTrackerCounts(t *testing.T) {
	tr := &lmdbReadTracker{}
	tr.begin()
	tr.begin()
	a, p, total := tr.snapshot()
	if a != 2 || p != 2 || total != 2 {
		t.Fatalf("after two begins: active=%d peak=%d total=%d", a, p, total)
	}
	tr.end()
	tr.begin()
	tr.end()
	tr.end()
	a, p, total = tr.snapshot()
	if a != 0 || p != 2 || total != 3 {
		t.Fatalf("after ends: active=%d peak=%d total=%d", a, p, total)
	}
}
