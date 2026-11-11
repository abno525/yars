package backup

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

var alice = gitrepo.Author{Name: "alice", Email: "alice@yars.local"}

// dataFolder builds a data folder as the server keeps one: the main repo,
// the database at .yars/yars.db and one engagement repo per id, each with
// one finding.
func dataFolder(t *testing.T, engs ...string) (string, *db.DB, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".yars"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(dir, ".yars", "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, config.Default(), d)
	for _, id := range engs {
		if err := st.CreateEngagement(store.Engagement{ID: id, Name: strings.ToUpper(id)}, alice); err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateFinding(id, "SQL injection", alice); err != nil {
			t.Fatal(err)
		}
	}
	return dir, d, st
}

// zipOf writes a backup of dir and opens it.
func zipOf(t *testing.T, dir string, d *db.DB, l Locker, o Options) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	n, err := Write(&buf, dir, d, l, o)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("Write reported %d bytes, wrote %d", n, buf.Len())
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func entry(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func TestWriteHasSnapshotNotLiveDB(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme")
	// the live database is in WAL mode: its -wal and -shm files exist
	if _, err := os.Stat(filepath.Join(dir, ".yars", "yars.db-wal")); err != nil {
		t.Fatalf("no live WAL file to leave out: %v", err)
	}
	zr := zipOf(t, dir, d, nil, Options{})
	// one database entry, the snapshot, added last
	var dbs []int
	for i, f := range zr.File {
		if f.Name == ".yars/yars.db" {
			dbs = append(dbs, i)
		}
	}
	if len(dbs) != 1 || dbs[0] != len(zr.File)-1 {
		t.Fatalf(".yars/yars.db entries at %v of %d", dbs, len(zr.File))
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "-wal") || strings.HasSuffix(f.Name, "-shm") {
			t.Errorf("backup holds %s", f.Name)
		}
	}
	if entry(zr, "engagements/acme/.git/HEAD") == nil {
		t.Error("the engagement repo is missing")
	}
}

func TestWriteKeyOnlyWhenAsked(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme")
	if err := os.WriteFile(filepath.Join(dir, ".yars", "secret.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if entry(zipOf(t, dir, d, nil, Options{WithKey: false}), ".yars/secret.key") != nil {
		t.Error("the key is in a backup without --key")
	}
	if entry(zipOf(t, dir, d, nil, Options{WithKey: true}), ".yars/secret.key") == nil {
		t.Error("the key is missing from a backup with --key")
	}
}

func TestWriteSkipsSymlinksAndSnapshots(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme")
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".yars", "yars.db.before-v18"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a linked engagement folder
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(dir, "engagements", "evil")); err != nil {
		t.Fatal(err)
	}
	zr := zipOf(t, dir, d, nil, Options{})
	for _, name := range []string{"link.txt", ".yars/yars.db.before-v18", "engagements/evil/outside.txt", "engagements/evil/"} {
		if entry(zr, name) != nil {
			t.Errorf("backup holds %s", name)
		}
	}
}

// A linked engagements folder is not followed.
func TestWriteSkipsLinkedEngagementsFolder(t *testing.T) {
	dir, d, _ := dataFolder(t)
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "x", "f.txt"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(dir, "engagements")); err != nil {
		t.Fatal(err)
	}
	for _, f := range zipOf(t, dir, d, nil, Options{}).File {
		if strings.HasPrefix(f.Name, "engagements") {
			t.Errorf("backup holds %s", f.Name)
		}
	}
}

// A data folder reached through a link is backed up whole.
func TestWriteThroughLinkedDataFolder(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme")
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	zr := zipOf(t, link, d, nil, Options{})
	for _, name := range []string{".git/HEAD", "engagements/acme/.git/HEAD", ".yars/yars.db"} {
		if entry(zr, name) == nil {
			t.Errorf("backup lacks %s", name)
		}
	}
}

func TestWriteKeepsExecBit(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme")
	rules := filepath.Join(dir, ".yars", "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "check.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := entry(zipOf(t, dir, d, nil, Options{}), ".yars/rules/check.sh")
	if f == nil {
		t.Fatal("the rule script is missing")
	}
	if f.Mode()&0o111 != 0o111 {
		t.Errorf("mode %v: the executable bits are lost", f.Mode())
	}
}

// recLocker records each lock taken and released, and writes a marker file
// into the locked repository saying whether its lock is held: a copy made
// under the lock holds "locked".
type recLocker struct {
	t   *testing.T
	dir string
	log []string
}

func (l *recLocker) mark(rel, s string) {
	if err := os.WriteFile(filepath.Join(l.dir, rel), []byte(s), 0o644); err != nil {
		l.t.Fatal(err)
	}
}

func (l *recLocker) LockMain() func() {
	l.log = append(l.log, "lock main")
	l.mark("lock.txt", "locked")
	return func() { l.mark("lock.txt", "free"); l.log = append(l.log, "unlock main") }
}

func (l *recLocker) LockEngagement(id string) func() {
	l.log = append(l.log, "lock "+id)
	rel := filepath.Join("engagements", id, "lock.txt")
	l.mark(rel, "locked")
	return func() { l.mark(rel, "free"); l.log = append(l.log, "unlock "+id) }
}

func TestWriteHoldsLocks(t *testing.T) {
	dir, d, _ := dataFolder(t, "acme", "beta")
	l := &recLocker{t: t, dir: dir}
	zr := zipOf(t, dir, d, l, Options{})
	want := []string{"lock main", "unlock main", "lock acme", "unlock acme", "lock beta", "unlock beta"}
	if strings.Join(l.log, ",") != strings.Join(want, ",") {
		t.Fatalf("locks %v, want %v", l.log, want)
	}
	for _, name := range []string{"lock.txt", "engagements/acme/lock.txt", "engagements/beta/lock.txt"} {
		f := entry(zr, name)
		if f == nil {
			t.Fatalf("backup lacks %s", name)
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if string(b) != "locked" {
			t.Errorf("%s copied while its lock was %s", name, b)
		}
	}
}

func TestSkip(t *testing.T) {
	for rel, want := range map[string]bool{
		".yars/yars.db":            true,
		".yars/yars.db-wal":        true,
		".yars/yars.db-shm":        true,
		".yars/yars.db-journal":    true,
		".yars/yars.db.before-v18": true,
		".yars/secret.key":         true,
		".yars/config.yaml":        false,
		"engagements/acme/x.md":    false,
	} {
		if got := Skip(rel, false); got != want {
			t.Errorf("Skip(%q, false) = %v, want %v", rel, got, want)
		}
	}
	if Skip(".yars/secret.key", true) {
		t.Error("the key is skipped although asked for")
	}
}
