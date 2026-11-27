package backup

import (
	"archive/zip"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

// backupFile writes a backup of dir to a file and returns its path.
func backupFile(t *testing.T, dir string, d *db.DB, l Locker) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "backup.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(f, dir, d, l, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// handZip writes a ZIP whose entries are given by header; each regular
// file's body is its name.
func handZip(t *testing.T, hs ...*zip.FileHeader) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hand.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, h := range hs {
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if !h.Mode().IsDir() {
			fmt.Fprint(w, h.Name)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return p
}

func fileHeader(name string, mode fs.FileMode) *zip.FileHeader {
	h := &zip.FileHeader{Name: name, Method: zip.Store}
	h.SetMode(mode)
	return h
}

func gone(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("%s exists after a refused restore (%v)", dir, err)
	}
}

type idTitle struct{ id, title string }

func listAll(t *testing.T, st *store.Store, engs ...string) []idTitle {
	t.Helper()
	var out []idTitle
	for _, e := range engs {
		refs, err := st.ListFindings(e)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range refs {
			out = append(out, idTitle{e + "/" + r.F.Meta.ID, r.F.Meta.Title})
		}
	}
	return out
}

func TestRestoreRoundTrip(t *testing.T) {
	dir, d, st := dataFolder(t, "acme", "beta")
	if _, err := st.CreateFinding("acme", "Stored XSS", alice); err != nil {
		t.Fatal(err)
	}
	if err := d.TxFor("acme", func(tx *db.Tx) error {
		return tx.AddMessage("acme", "F-001", chat.Message{ID: "m1", User: "bob", Text: "x"})
	}); err != nil {
		t.Fatal(err)
	}
	zipPath := backupFile(t, dir, d, st)
	dest := filepath.Join(t.TempDir(), "restored")
	rep, err := Restore(zipPath, dest)
	if err != nil {
		t.Fatal(err)
	}
	want := Report{Schema: db.SchemaVersion, Engagements: 2, Findings: 3, HasKey: false, PointInTime: true}
	if rep != want {
		t.Fatalf("report %+v, want %+v", rep, want)
	}
	r2, err := gitrepo.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := db.Open(filepath.Join(dest, ".yars", "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	st2 := store.New(r2, config.Default(), d2)
	got, orig := listAll(t, st2, "acme", "beta"), listAll(t, st, "acme", "beta")
	if fmt.Sprint(got) != fmt.Sprint(orig) || len(got) != 3 {
		t.Fatalf("findings %v, want %v", got, orig)
	}
	n1, _ := d.ChatCount()
	n2, _ := d2.ChatCount()
	if n1 != 1 || n2 != n1 {
		t.Fatalf("chat %d restored, %d before", n2, n1)
	}
}

func TestRestoreRefusesNonEmpty(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	zipPath := backupFile(t, dir, d, st)
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "keep.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Restore(zipPath, dest)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("err %v", err)
	}
	ents, _ := os.ReadDir(dest)
	if len(ents) != 1 || ents[0].Name() != "keep.txt" {
		t.Fatalf("the folder changed: %v", ents)
	}
}

func TestRestoreRefusesZipSlip(t *testing.T) {
	ok := fileHeader(".yars/config.yaml", 0o644)
	for name, bad := range map[string]*zip.FileHeader{
		"dotdot":    fileHeader("../x", 0o644),
		"absolute":  fileHeader("/abs", 0o644),
		"backslash": fileHeader(`a\..\..\x`, 0o644),
		"symlink":   fileHeader("link", fs.ModeSymlink|0o777),
	} {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "restored")
			_, err := Restore(handZip(t, ok, bad), dest)
			if err == nil || !strings.Contains(err.Error(), "not a plain file inside the data folder") {
				t.Fatalf("err %v", err)
			}
			gone(t, dest)
		})
	}
}

func TestRestoreRefusesNewerSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "yars.db")
	d, err := db.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(fmt.Sprintf("PRAGMA user_version = %d", db.SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := d.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	d.Close()
	body, err := os.ReadFile(snap)
	if err != nil {
		t.Fatal(err)
	}
	zp := filepath.Join(t.TempDir(), "newer.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	w, _ := zw.CreateHeader(fileHeader(".yars/yars.db", 0o600))
	w.Write(body)
	zw.Close()
	f.Close()

	dest := filepath.Join(t.TempDir(), "restored")
	_, err = Restore(zp, dest)
	if !errors.Is(err, ErrNewer) {
		t.Fatalf("err %v", err)
	}
	if !strings.Contains(err.Error(), "upgrade yars first") {
		t.Fatalf("the refusal does not say what to do: %v", err)
	}
	gone(t, dest)
}

func TestRestoreRemovesBrokenResult(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	// lose one object of the engagement's repository
	objs := filepath.Join(dir, "engagements", "acme", ".git", "objects")
	var victim string
	filepath.WalkDir(objs, func(p string, e fs.DirEntry, err error) error {
		if err == nil && victim == "" && !e.IsDir() && len(filepath.Base(filepath.Dir(p))) == 2 {
			victim = p
		}
		return nil
	})
	if victim == "" {
		t.Fatal("no loose object to remove")
	}
	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}
	zipPath := backupFile(t, dir, d, st)
	dest := filepath.Join(t.TempDir(), "restored")
	_, err := Restore(zipPath, dest)
	if err == nil || !strings.Contains(err.Error(), "engagements/acme") {
		t.Fatalf("err %v", err)
	}
	gone(t, dest)
}

// A file a backup never holds (the database's side files, a migration
// snapshot, a git lock) refuses the restore before anything is written: a
// WAL file could change the database after its schema was read.
func TestRestoreRefusesSkippedEntries(t *testing.T) {
	dbh := fileHeader(".yars/yars.db", 0o600)
	for _, name := range []string{".yars/yars.db-wal", ".yars/yars.db.before-v3", ".git/index.lock"} {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "restored")
			_, err := Restore(handZip(t, dbh, fileHeader(name, 0o600)), dest)
			if err == nil || !strings.Contains(err.Error(), name+": not part of a backup") {
				t.Fatalf("err %v", err)
			}
			gone(t, dest)
		})
	}
}

// The report gives the schema of the backup as written, before the restore
// migrates it.
func TestRestoreReportsBackupSchema(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	if _, err := d.Exec(fmt.Sprintf("PRAGMA user_version = %d", db.SchemaVersion-1)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	rep, err := Restore(backupFile(t, dir, d, st), dest)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Schema != db.SchemaVersion-1 {
		t.Fatalf("schema %d, want %d", rep.Schema, db.SchemaVersion-1)
	}
	if v, err := db.SchemaOf(filepath.Join(dest, ".yars", "yars.db")); err != nil || v != db.SchemaVersion {
		t.Fatalf("restored database at %d %v", v, err)
	}
}

// The database and the key are unpacked private whatever mode the ZIP
// gives them.
func TestUnpackKeepsSecretsPrivate(t *testing.T) {
	zp := handZip(t, fileHeader(".yars/yars.db", 0o644), fileHeader(".yars/secret.key", 0o644), fileHeader(".yars/rules/x.sh", 0o755))
	zr, err := zip.OpenReader(zp)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	dest := t.TempDir()
	if err := unpack(zr.File, dest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".yars/yars.db", ".yars/secret.key"} {
		fi, err := os.Stat(filepath.Join(dest, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v, want 0600", name, fi, err)
		}
	}
	// any other file keeps the ZIP's mode (the owner's bits survive any umask)
	if fi, err := os.Stat(filepath.Join(dest, ".yars/rules/x.sh")); err != nil || fi.Mode().Perm()&0o700 != 0o700 {
		t.Errorf("x.sh: %v %v, want the owner's rwx kept", fi, err)
	}
}

func TestVerify(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	rep, err := Verify(backupFile(t, dir, d, st))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Engagements != 1 || rep.Findings != 1 {
		t.Fatalf("report %+v", rep)
	}
}
