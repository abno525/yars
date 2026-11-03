package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c, Default()) {
		t.Fatalf("got %+v", c)
	}
	want := []string{"Description", "Location", "Impact", "Steps to Reproduce", "Remediation", "References"}
	if !reflect.DeepEqual(c.Sections, want) {
		t.Fatalf("sections %v", c.Sections)
	}
	if !reflect.DeepEqual(c.Severities, []string{"critical", "high", "medium", "low", "info"}) {
		t.Fatalf("severities %v", c.Severities)
	}
}

func TestLoadPartial(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	os.WriteFile(filepath.Join(dir, ".yars", "config.yaml"), []byte("sections: [A, B]\n"), 0o644)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Sections, []string{"A", "B"}) || !reflect.DeepEqual(c.Severities, Default().Severities) {
		t.Fatalf("got %+v", c)
	}
}

func TestUsersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if us, err := LoadUsers(dir); err != nil || len(us) != 0 {
		t.Fatalf("missing file: %v %v", us, err)
	}
	in := []User{{Username: "alice", Email: "a@x", Role: "pentester", PasswordHash: "h"}}
	if err := SaveUsers(dir, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadUsers(dir)
	if err != nil || !reflect.DeepEqual(in, out) {
		t.Fatalf("got %v %v", out, err)
	}
}

func TestValidRole(t *testing.T) {
	if !ValidRole("director") || ValidRole("boss") {
		t.Fatal("ValidRole wrong")
	}
}
