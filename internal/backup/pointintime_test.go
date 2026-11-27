package backup

import (
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

// hookLocker is a Locker that runs before, when set, each time an
// engagement's lock is asked for and before it is taken: a commit that lands
// after the snapshot and before that repository is copied.
type hookLocker struct {
	Locker
	before     func(id string)
	beforeMain func() // the same for the main repository's lock
}

func (l *hookLocker) LockEngagement(id string) func() {
	if l.before != nil {
		l.before(id)
	}
	return l.Locker.LockEngagement(id)
}

func (l *hookLocker) LockMain() func() {
	if l.beforeMain != nil {
		l.beforeMain()
	}
	return l.Locker.LockMain()
}

// editZip copies the ZIP at src; edit gives each entry's new body, or false
// to leave the entry out.
func editZip(t *testing.T, src string, edit func(name string, body []byte) ([]byte, bool)) string {
	t.Helper()
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	p := filepath.Join(t.TempDir(), "edited.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, e := range zr.File {
		var body []byte
		if !e.Mode().IsDir() {
			rc, err := e.Open()
			if err != nil {
				t.Fatal(err)
			}
			body, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		body, keep := edit(e.Name, body)
		if !keep {
			continue
		}
		h := &zip.FileHeader{Name: e.Name, Method: zip.Deflate}
		h.SetMode(e.Mode())
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

// withMeta is the backup at src with its recorded commits replaced by js.
func withMeta(t *testing.T, src, js string) string {
	t.Helper()
	found := false
	p := editZip(t, src, func(name string, body []byte) ([]byte, bool) {
		if name == metaEntry {
			found = true
			return []byte(js), true
		}
		return body, true
	})
	if !found {
		t.Fatalf("the backup has no %s", metaEntry)
	}
	return p
}

func headOf(t *testing.T, dir string) string {
	t.Helper()
	h, err := gitrepo.ReadHead(dir)
	if err != nil || h == "" {
		t.Fatalf("HEAD of %s: %q %v", dir, h, err)
	}
	return h
}

// The backup records the commit of every repository in one entry, written
// just before the database; a file of that name in the data folder is not
// copied beside it.
func TestWriteRecordsHeads(t *testing.T) {
	dir, d, st := dataFolder(t, "acme", "beta")
	if err := os.WriteFile(filepath.Join(dir, ".yars", "backup.json"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	zr := zipOf(t, dir, d, st, Options{})
	var at []int
	for i, f := range zr.File {
		if f.Name == metaEntry {
			at = append(at, i)
		}
	}
	if len(at) != 1 || at[0] != len(zr.File)-2 {
		t.Fatalf("%s entries at %v of %d", metaEntry, at, len(zr.File))
	}
	f := zr.File[at[0]]
	if f.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", f.Mode())
	}
	m, ok := readMeta(f)
	if !ok {
		t.Fatal("the entry does not read")
	}
	if m.Main != headOf(t, dir) || len(m.Engagements) != 2 ||
		m.Engagements["acme"] != headOf(t, filepath.Join(dir, "engagements", "acme")) ||
		m.Engagements["beta"] != headOf(t, filepath.Join(dir, "engagements", "beta")) {
		t.Fatalf("recorded %+v", m)
	}
}

// An engagement made after the commits were read is not in the backup, and
// the main repository is restored as it was before it: the restored folder
// names no engagement it does not hold.
func TestRestoreLeavesOutLaterEngagement(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	main0 := headOf(t, dir)
	l := &hookLocker{Locker: st, beforeMain: func() {
		if err := st.CreateEngagement(store.Engagement{ID: "late", Name: "LATE"}, alice); err != nil {
			t.Fatal(err)
		}
	}}
	zipPath := backupFile(t, dir, d, l)
	if headOf(t, dir) == main0 {
		t.Fatal("the main repository did not move during the backup")
	}
	dest := filepath.Join(t.TempDir(), "restored")
	rep, err := Restore(zipPath, dest)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.PointInTime || rep.Engagements != 1 {
		t.Errorf("report %+v", rep)
	}
	if h := headOf(t, dest); h != main0 {
		t.Errorf("restored main repository at %s, want %s", h, main0)
	}
	ids, err := openRestored(t, dest).EngagementIDs()
	if err != nil || strings.Join(ids, ",") != "acme" {
		t.Errorf("restored engagements %v %v", ids, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, ".gitmodules")); err != nil || strings.Contains(string(b), "late") {
		t.Errorf(".gitmodules names the later engagement: %q %v", b, err)
	}
}

// A backup an earlier YARS wrote records no commits: it restores as it
// always did, and the report says it is not point-in-time.
func TestRestoreOldBackup(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	old := editZip(t, backupFile(t, dir, d, st), func(name string, body []byte) ([]byte, bool) {
		return body, name != metaEntry
	})
	dest := filepath.Join(t.TempDir(), "restored")
	rep, err := Restore(old, dest)
	if err != nil {
		t.Fatal(err)
	}
	want := Report{Schema: db.SchemaVersion, Engagements: 1, Findings: 1}
	if rep != want {
		t.Fatalf("report %+v, want %+v", rep, want)
	}
	if got := listAll(t, openRestored(t, dest), "acme"); len(got) != 1 {
		t.Fatalf("findings %v", got)
	}
}

// A purge rewrites an engagement's history after its commit was read: the
// recorded commit is no longer in it, and the backup fails instead of
// holding a history its database does not know.
func TestWriteFailsWhenHistoryRewritten(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	refs, err := st.ListFindings("acme")
	if err != nil || len(refs) != 1 {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(filepath.Join(dir, "engagements", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	p := "findings/" + refs[0].Dir + "/attachments/shot.png"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(r.Dir, p)), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{"the original", "redacted"} {
		if err := os.WriteFile(filepath.Join(r.Dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.Commit([]string{p}, "F-001: attach", alice); err != nil {
			t.Fatal(err)
		}
	}
	before := headOf(t, r.Dir)
	l := &hookLocker{Locker: st, before: func(string) {
		keep, err := r.BlobAt("HEAD", p)
		if err != nil || keep == "" {
			t.Fatalf("blob %q %v", keep, err)
		}
		if err := r.DropOldBlobs(p, keep); err != nil {
			t.Fatal(err)
		}
	}}
	var buf bytes.Buffer
	_, err = Write(&buf, dir, d, l, Options{})
	if headOf(t, r.Dir) == before {
		t.Fatal("the purge did not rewrite the history")
	}
	if err == nil || !strings.Contains(err.Error(), "engagements/acme: its history changed while the backup was taken") {
		t.Fatalf("err %v", err)
	}
}

// What the entry records comes from an uploaded file. A commit no object
// has, a value that is no commit id and a name outside the ZIP reset
// nothing and fail nothing: the repository stays as unpacked and is named.
func TestRestoreRecordedCommitUnusable(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	src := backupFile(t, dir, d, st)
	acme := headOf(t, filepath.Join(dir, "engagements", "acme"))
	main := headOf(t, dir)
	const absent = "0123456789abcdef0123456789abcdef01234567"
	for name, c := range map[string]struct{ js, notReset string }{
		"missing commit": {`{"version":1,"main":"` + main + `","engagements":{"acme":"` + absent + `"}}`, "acme"},
		"not a commit":   {`{"version":1,"main":"--upload-pack=touch","engagements":{"acme":"-q"}}`, "main, acme"},
		"a ref name":     {`{"version":1,"main":"HEAD","engagements":{"acme":"main"}}`, "main, acme"},
		"other names":    {`{"version":1,"main":"` + main + `","engagements":{"../../evil":"` + acme + `","beta":"` + acme + `"}}`, "acme"},
		"not recorded":   {`{"version":1,"main":"` + main + `"}`, "acme"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dest := filepath.Join(parent, "restored")
			rep, err := Restore(withMeta(t, src, c.js), dest)
			if err != nil {
				t.Fatal(err)
			}
			if rep.PointInTime || rep.NotReset != c.notReset || rep.Findings != 1 || rep.Engagements != 1 {
				t.Errorf("report %+v, want not reset: %s", rep, c.notReset)
			}
			if h := headOf(t, filepath.Join(dest, "engagements", "acme")); h != acme {
				t.Errorf("the engagement moved to %s", h)
			}
			if h := headOf(t, dest); h != main {
				t.Errorf("the main repository moved to %s", h)
			}
			if ents, _ := os.ReadDir(parent); len(ents) != 1 {
				t.Errorf("written beside the target: %v", ents)
			}
			if ents, _ := os.ReadDir(filepath.Join(dest, "engagements")); len(ents) != 1 {
				t.Errorf("engagement folders %v", ents)
			}
		})
	}
	// an entry that does not read is a backup that records nothing
	for name, js := range map[string]string{"no JSON": "stale", "another version": `{"version":2,"main":"` + main + `"}`} {
		t.Run(name, func(t *testing.T) {
			rep, err := Restore(withMeta(t, src, js), filepath.Join(t.TempDir(), "restored"))
			if err != nil || rep.PointInTime || rep.NotReset != "" {
				t.Fatalf("report %+v %v", rep, err)
			}
		})
	}
}

// The entry is a file: a folder of its name is no part of a backup.
func TestRestoreRefusesMetaFolder(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "restored")
	_, err := Restore(handZip(t, fileHeader(".yars/yars.db", 0o600), fileHeader(".yars/backup.json/", fs.ModeDir|0o700)), dest)
	if err == nil || !strings.Contains(err.Error(), "not part of a backup") {
		t.Fatalf("err %v", err)
	}
	gone(t, dest)
}

// approved makes the one finding of engagement id complete, approved for its
// file as it is, and returns its folder and that file.
func approved(t *testing.T, dir string, d *db.DB, st *store.Store, id string) (string, []byte) {
	t.Helper()
	refs, err := st.ListFindings(id)
	if err != nil || len(refs) != 1 {
		t.Fatalf("findings %v %v", refs, err)
	}
	fd := refs[0].Dir
	raw, err := os.ReadFile(filepath.Join(dir, "engagements", id, "findings", fd, "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.TxFor(id, func(tx *db.Tx) error {
		return tx.PutState(id, refs[0].F.Meta.ID, db.State{Status: "complete", ApprovedHash: store.ApprovalHash(raw)})
	}); err != nil {
		t.Fatal(err)
	}
	return fd, raw
}

// openRestored opens the store of a restored data folder.
func openRestored(t *testing.T, dest string) *store.Store {
	t.Helper()
	r, err := gitrepo.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(dest, ".yars", "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return store.New(r, config.Default(), d)
}

// A director's edit of an approved finding lands after the database snapshot
// and before its engagement is copied: the restored folder holds the
// finding as the snapshot knows it, approved, with the text of that moment.
func TestRestoreIsPointInTime(t *testing.T) {
	dir, d, st := dataFolder(t, "acme")
	fd, raw := approved(t, dir, d, st, "acme")
	edits := 0
	l := &hookLocker{Locker: st, before: func(id string) {
		edits++
		if err := st.UpdateSection(id, fd, "Impact", "Changed after the snapshot.", "", alice); err != nil {
			t.Fatal(err)
		}
	}}
	zipPath := backupFile(t, dir, d, l)
	if edits != 1 {
		t.Fatalf("%d edits during the backup", edits)
	}
	// the live folder has the edit, and its approval went with it
	if ref, err := st.Finding("acme", fd); err != nil || ref.F.Meta.Status != "complete" || ref.Full == store.ApprovalHash(raw) {
		t.Fatalf("live finding: %v %v", ref.F.Meta.Status, err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	rep, err := Restore(zipPath, dest)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.PointInTime || rep.NotReset != "" || rep.Findings != 1 || rep.Engagements != 1 {
		t.Errorf("report %+v", rep)
	}
	// the entry with the commits is read, never unpacked
	if _, err := os.Lstat(filepath.Join(dest, ".yars", "backup.json")); !os.IsNotExist(err) {
		t.Errorf(".yars/backup.json is in the restored folder (%v)", err)
	}
	st2 := openRestored(t, dest)
	ref, err := st2.Finding("acme", fd)
	if err != nil {
		t.Fatal(err)
	}
	if ref.F.Meta.Status != "complete" {
		t.Errorf("restored finding is %s, want complete: the files are newer than the database", ref.F.Meta.Status)
	}
	got, err := os.ReadFile(filepath.Join(dest, "engagements", "acme", "findings", fd, "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Errorf("restored finding.md is not the file of the snapshot's moment:\n%s", got)
	}
}
