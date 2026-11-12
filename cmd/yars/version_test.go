package main

import (
	"bytes"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"yars/internal/db"
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
	cmdVersion(nil, &b)
	want := "yars v1.0.0 (schema " + strconv.Itoa(db.SchemaVersion) + ", " + runtime.Version() + ")\n"
	if b.String() != want {
		t.Fatalf("%q, want %q", b.String(), want)
	}
	if err := cmdVersion([]string{"x"}, &b); err == nil {
		t.Fatal("an argument is accepted")
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
	if v := revision("", false); v != "dev" {
		t.Fatalf("none: %q", v)
	}
}
