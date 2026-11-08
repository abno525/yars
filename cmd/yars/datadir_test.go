package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
)

// isolate keeps a test away from the developer's own default data folder
// (YARS_DATA and ~/.config/yars/config.yaml).
func isolate(t *testing.T) string {
	t.Helper()
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	t.Setenv("YARS_DATA", "")
	return cfg
}

func initDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// R4: yars unlock clears a user's login lockout, audited as the CLI's.
func TestUnlockCommand(t *testing.T) {
	isolate(t)
	dir := initDir(t)
	d := openDB(t, dir)
	d.AddUser(config.User{Username: "ann", Role: "director"})
	for range 5 {
		if ok, _, _ := d.LoginAttempt("ann"); ok {
			d.LoginDone("ann", false)
		}
	}
	if _, locked, _ := d.LockedUntil("ann"); !locked {
		t.Fatal("ann not locked out")
	}
	var out bytes.Buffer
	if err := cmdUnlock([]string{"--data", dir, "ann"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "unlocked ann" {
		t.Fatalf("output %q", out.String())
	}
	if _, locked, _ := d.LockedUntil("ann"); locked {
		t.Fatal("still locked out")
	}
	l, _ := d.AuditLog(1)
	if len(l) != 1 || l[0].Actor != "cli" || l[0].Action != "login.unlock" || l[0].Target != "ann" {
		t.Fatalf("audit %+v", l)
	}
	if err := cmdUnlock([]string{"--data", dir, "zed"}, &out); err == nil || !strings.Contains(err.Error(), "no user zed") {
		t.Fatalf("unknown user: %v", err)
	}
	if err := cmdUnlock([]string{"--data", dir}, &out); err == nil {
		t.Fatal("no username accepted")
	}
}

// P4: a database error is not blamed on the name.
func TestUnlockDatabaseError(t *testing.T) {
	isolate(t)
	d := openDB(t, initDir(t))
	d.Close()
	if err := knownUser(d, "ann"); err == nil || strings.Contains(err.Error(), "no user") {
		t.Fatalf("closed database: %v", err)
	}
}

// R4: the data folder comes from --data, then YARS_DATA, then data: in
// the config file, else ".".
func TestDataFolderOrder(t *testing.T) {
	cfgHome := isolate(t)
	resolve := func(args ...string) (string, string, error) {
		t.Helper()
		fs := flag.NewFlagSet("x", flag.ContinueOnError)
		data := dataFlag(fs)
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return resolveData(fs, *data)
	}
	if dir, src, err := resolve(); err != nil || dir != "." || src != "default" {
		t.Fatalf("nothing set: %q %q %v", dir, src, err)
	}
	file := filepath.Join(cfgHome, "yars", "config.yaml")
	os.MkdirAll(filepath.Dir(file), 0o700)
	os.WriteFile(file, []byte("data: /srv/yars\n"), 0o600)
	if dir, src, err := resolve(); err != nil || dir != "/srv/yars" || src != file {
		t.Fatalf("config file: %q %q %v", dir, src, err)
	}
	t.Setenv("YARS_DATA", "/srv/env")
	if dir, src, err := resolve(); err != nil || dir != "/srv/env" || src != "YARS_DATA" {
		t.Fatalf("env: %q %q %v", dir, src, err)
	}
	// a flag wins, "." included
	if dir, src, err := resolve("--data", "."); err != nil || dir != "." || src != "--data" {
		t.Fatalf("flag: %q %q %v", dir, src, err)
	}
	t.Setenv("YARS_DATA", "")
	// a broken file is an error naming it, not a silent "."
	os.WriteFile(file, []byte("data: [\n"), 0o600)
	if _, _, err := resolve(); err == nil || !strings.Contains(err.Error(), file) {
		t.Fatalf("broken file: %v", err)
	}
	os.WriteFile(file, []byte("data: rel/dir\n"), 0o600)
	if _, _, err := resolve(); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative data: %v", err)
	}
	// a relative XDG_CONFIG_HOME is ignored (XDG spec): ~/.config instead
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "relative")
	hf := filepath.Join(home, ".config", "yars", "config.yaml")
	os.MkdirAll(filepath.Dir(hf), 0o700)
	os.WriteFile(hf, []byte("data: /srv/home\n"), 0o600)
	if dir, src, err := resolve(); err != nil || dir != "/srv/home" || src != hf {
		t.Fatalf("~/.config: %q %q %v", dir, src, err)
	}
}

// R4: yars use writes the default (absolute, a YARS data folder only);
// without an argument it prints the default and where it came from.
func TestUseCommand(t *testing.T) {
	cfgHome := isolate(t)
	var out bytes.Buffer
	if err := cmdUse([]string{t.TempDir()}, &out); err == nil || !strings.Contains(err.Error(), "not a YARS data folder") {
		t.Fatalf("plain folder: %v", err)
	}
	dir := initDir(t)
	wd, _ := os.Getwd()
	rel, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmdUse([]string{rel}, &out); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(cfgHome, "yars", "config.yaml")
	b, err := os.ReadFile(file)
	if err != nil || strings.TrimSpace(string(b)) != "data: "+dir {
		t.Fatalf("config %q %v", b, err)
	}
	if fi, _ := os.Stat(file); fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(file)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode %v", fi.Mode())
	}
	out.Reset()
	if err := cmdUse(nil, &out); err != nil || strings.TrimSpace(out.String()) != dir+" (from "+file+")" {
		t.Fatalf("show: %q %v", out.String(), err)
	}
	t.Setenv("YARS_DATA", "/srv/env")
	out.Reset()
	if err := cmdUse(nil, &out); err != nil || strings.TrimSpace(out.String()) != "/srv/env (from YARS_DATA)" {
		t.Fatalf("show env: %q %v", out.String(), err)
	}
}

// R4: commands use the default data folder; seed never does (it would
// fill the real data folder with made-up data).
func TestCommandsUseDefaultData(t *testing.T) {
	isolate(t)
	dir := initDir(t)
	t.Setenv("YARS_DATA", dir)
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--role", "director", "ann"}, strings.NewReader("pw\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdRole([]string{"ann", "reviewer"}, &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnlock([]string{"ann"}, &out); err != nil {
		t.Fatal(err)
	}
	if code, err := cmdToken([]string{"list"}, &out); code != 0 {
		t.Fatal(code, err)
	}
	if code, err := cmdLint(nil, &out); code != 0 {
		t.Fatal(code, err)
	}
	if u, ok, _ := openDB(t, dir).User("ann"); !ok || u.Role != "reviewer" {
		t.Fatalf("ann %+v", u)
	}
	if err := cmdSeed([]string{"--engagements", "1"}, &out); err == nil {
		t.Fatal("seed used the default data folder")
	}
}
