package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"yars/internal/config"
)

// initSimple sets up a data folder with the simple workflow.
func initSimple(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{"--simple", dir}, &out); err != nil {
		t.Fatal(err)
	}
	return dir
}

// yars init --simple writes the workflow key at the top of config.yaml and
// the database setting, commits the config, and says which workflow it set
// up; the flag goes before the folder.
func TestInitSimple(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{"--simple", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "initialised "+dir+" (simple workflow)\n" {
		t.Errorf("output %q", got)
	}
	b, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil || !strings.HasPrefix(string(b), "workflow: simple\n") {
		t.Fatalf("config.yaml %v:\n%s", err, b)
	}
	cfg, err := config.Load(dir)
	if err != nil || !cfg.Simple() {
		t.Fatalf("config %+v %v", cfg, err)
	}
	if w, err := openDB(t, dir).Setting("workflow"); w != "simple" || err != nil {
		t.Fatalf("database setting %q %v", w, err)
	}
	if shown, err := exec.Command("git", "-C", dir, "show", "HEAD:.yars/config.yaml").Output(); err != nil || string(shown) != string(b) {
		t.Fatalf("committed config %v:\n%s", err, shown)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(st) != 0 {
		t.Fatalf("not clean after init:\n%s", st)
	}
	// a flag after the folder is not taken for a second folder, and nothing
	// is set up
	late := t.TempDir()
	if err := cmdInitOut([]string{late, "--simple"}, &out); err == nil || !strings.Contains(err.Error(), "flags go before the folder") {
		t.Fatalf("flag after the folder: %v", err)
	}
	if _, err := os.Stat(config.ConfigPath(late)); err == nil {
		t.Fatal("a folder was set up")
	}
}

// yars init without --simple writes the same config.yaml as before (no
// workflow key), no database setting, and says what it always said.
func TestInitStandardUnchanged(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := cmdInitOut([]string{dir}, &out); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "initialised "+dir+"\n" {
		t.Errorf("output %q", got)
	}
	want, _ := yaml.Marshal(config.Default())
	b, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil || string(b) != string(want) || strings.Contains(string(b), "workflow") {
		t.Fatalf("config.yaml %v:\n%s", err, b)
	}
	if cfg, _ := config.Load(dir); cfg.Simple() {
		t.Fatal("standard init runs the simple workflow")
	}
	if w, err := openDB(t, dir).Setting("workflow"); w != "" || err != nil {
		t.Fatalf("database setting %q %v", w, err)
	}
	// initData, which tests call, is the standard init
	other := t.TempDir()
	if err := initData(other); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(config.ConfigPath(other)); string(b2) != string(want) {
		t.Fatalf("initData config:\n%s", b2)
	}
}
