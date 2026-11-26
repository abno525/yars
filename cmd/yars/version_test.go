package main

import (
	"bytes"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// yars version names the build, the database schema it writes and the Go
// release it was built with.
func TestVersionCommand(t *testing.T) {
	var b bytes.Buffer
	if err := cmdVersion(nil, &b); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.HasPrefix(out, "yars ") || !strings.Contains(out, "schema ") {
		t.Fatalf("%q", out)
	}
	// a version set at build time is the one printed
	old := version
	defer func() { version = old }()
	version = "v1.0.0"
	b.Reset()
	if err := cmdVersion(nil, &b); err != nil {
		t.Fatal(err)
	}
	want := "yars v1.0.0 (schema " + strconv.Itoa(db.SchemaVersion) + ", " + runtime.Version() + ")\n"
	if b.String() != want {
		t.Fatalf("%q, want %q", b.String(), want)
	}
	if err := cmdVersion([]string{"x"}, &b); err == nil {
		t.Fatal("an argument is accepted")
	}
}

// The Source link is the module's own address: go.mod's module path, over
// https.
func TestSourceIsTheModulePath(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(b), "\n")
	mod, ok := strings.CutPrefix(first, "module ")
	if !ok || source != "https://"+mod {
		t.Fatalf("source is %q, go.mod's first line %q", source, first)
	}
}

// A go install build comes from the module cache: it has no VCS revision,
// and its module version stands for the version.
func TestGoInstallBuildShowsTheModuleVersion(t *testing.T) {
	installed := &debug.BuildInfo{Main: debug.Module{Path: "github.com/abno525/yars", Version: "v1.0.0"}}
	if v := infoVersion(installed); v != "v1.0.0" {
		t.Fatalf("a go install build: %q, want v1.0.0", v)
	}
	// a clone build keeps its git revision, whatever module version Go stamps
	clone := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.0.0-20261126120000-0123456789ab+dirty"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	if v := infoVersion(clone); v != "0123456789ab+dirty" {
		t.Fatalf("a clone build: %q", v)
	}
	// no revision and no module version: dev
	for _, mv := range []string{"", "(devel)"} {
		if v := infoVersion(&debug.BuildInfo{Main: debug.Module{Version: mv}}); v != "dev" {
			t.Fatalf("module version %q: %q, want dev", mv, v)
		}
	}
	if v := infoVersion(nil); v != "dev" {
		t.Fatalf("no build info: %q", v)
	}
}

// Without a version set at build time, the VCS revision stands for it.
func TestBuildVersionFallback(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = ""
	if v := buildVersion(); v == "" || strings.ContainsAny(v, " \n") {
		t.Fatalf("%q", v)
	}
	if v := revision("0123456789abcdef0123", false); v != "0123456789ab" {
		t.Fatalf("revision: %q", v)
	}
	if v := revision("0123456789abcdef0123", true); v != "0123456789ab+dirty" {
		t.Fatalf("modified: %q", v)
	}
	if v := revision("abc", false); v != "abc" {
		t.Fatalf("a short revision: %q", v)
	}
	if v := revision("", false); v != "dev" {
		t.Fatalf("none: %q", v)
	}
}
