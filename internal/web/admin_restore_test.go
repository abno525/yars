package web

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/gitrepo"
)

// uploadFile posts one file as the multipart field.
func (e *env) uploadFile(t *testing.T, user, path, field, name string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile(field, name)
	fw.Write(data)
	mw.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// restored lists the folders a restore made beside the data folder.
func (e *env) restored(t *testing.T) []string {
	t.Helper()
	got, err := filepath.Glob(e.dir + ".restored-*")
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func headOf(t *testing.T, dir string) string {
	t.Helper()
	h, err := gitrepo.ReadHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// D24: an uploaded backup is restored into a new folder beside the data
// folder; the running server keeps its own, and the page says how to switch.
func TestRestoreUploadMakesSiblingFolder(t *testing.T) {
	e := setupSerial(t)
	rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
	if rec.Code != 200 {
		t.Fatalf("backup %d", rec.Code)
	}
	before := headOf(t, e.dir)
	rec = e.uploadFile(t, "dora", "/admin/system/restore", "backup", "b.zip", rec.Body.Bytes())
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/admin/system") {
		t.Fatalf("restore %d:\n%s", rec.Code, rec.Body.String())
	}
	dirs := e.restored(t)
	if len(dirs) != 1 {
		t.Fatalf("restored folders %v", dirs)
	}
	if _, err := gitrepo.Open(dirs[0]); err != nil {
		t.Fatalf("the restored folder is no repository: %v", err)
	}
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	p := between(b, `id="restore"`, "</form>")
	for _, want := range []string{`<code id="restore-cmd" title="yars serve --data ` + dirs[0] + `">yars serve --data ` + dirs[0] + `</code>`, `data-copy="restore-cmd"`,
		`<span class="sl">Schema</span><span class="sv">v` + fmt.Sprint(db.SchemaVersion) + `</span>`, `<span class="sl">Engagements</span><span class="sv">1</span>`,
		`<span class="sl">Findings</span><span class="sv">1</span>`, `<span class="sl">Keys</span><span class="sv">without key</span>`, `title="` + dirs[0] + `"`} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel lacks %s:\n%s", want, p)
		}
	}
	if headOf(t, e.dir) != before {
		t.Fatal("the running data folder changed")
	}
	if l, _, _ := e.srv.Store.DB().AuditQuery(db.AuditFilter{Action: "restore.upload", Limit: 1}); len(l) != 1 || l[0].Target != dirs[0] || l[0].Actor != "dora" {
		t.Fatalf("audit %+v", l)
	}
	// the result is shown once; the last restore stays
	if p := between(e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(), `id="restore"`, "</form>"); strings.Contains(p, "restore-cmd") || !strings.Contains(p, dirs[0]) {
		t.Fatalf("panel on the next load:\n%s", p)
	}
}

// newerBackup is a ZIP holding a database a newer YARS wrote.
func newerBackup(t *testing.T) []byte {
	t.Helper()
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
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	h := &zip.FileHeader{Name: ".yars/yars.db", Method: zip.Deflate}
	h.SetMode(0o600)
	w, _ := zw.CreateHeader(h)
	w.Write(body)
	zw.Close()
	return buf.Bytes()
}

// D24, Review focus 4: a backup from a newer YARS is refused and leaves no
// folder.
func TestRestoreUploadRefusesNewerSchema(t *testing.T) {
	e := setupSerial(t)
	rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "new.zip", newerBackup(t))
	if rec.Code != http.StatusBadRequest || !strings.Contains(between(rec.Body.String(), `id="restore"`, "</form>"), "newer YARS") {
		t.Fatalf("newer %d:\n%s", rec.Code, rec.Body.String())
	}
	if dirs := e.restored(t); len(dirs) != 0 {
		t.Fatalf("left behind %v", dirs)
	}
}

// D24, Review focus 4: a file that is not a ZIP is refused and leaves
// nothing.
func TestRestoreUploadRefusesNonZip(t *testing.T) {
	e := setupSerial(t)
	rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "notes.txt", []byte("hello"))
	p := between(rec.Body.String(), `id="restore"`, "</form>")
	if rec.Code != http.StatusBadRequest || !strings.Contains(p, "not a ZIP file") {
		t.Fatalf("text %d:\n%s", rec.Code, rec.Body.String())
	}
	// the panel is far down the page: its file input takes the focus, so the
	// browser shows the reason
	if !strings.Contains(p, `name="backup" accept=".zip,application/zip" required aria-label="Backup" autofocus>`) {
		t.Fatalf("the refused panel is not brought into view:\n%s", p)
	}
	if dirs := e.restored(t); len(dirs) != 0 {
		t.Fatalf("left behind %v", dirs)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(e.dir), ".yars-restore-*"))
	if len(left) != 0 {
		t.Fatalf("the upload was left on disk: %v", left)
	}
}

// D24: a ZIP that is not a backup is refused naming the file uploaded, not
// the temporary copy.
func TestRestoreUploadNotABackupNamesTheUpload(t *testing.T) {
	e := setupSerial(t)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("hello"))
	zw.Close()
	rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "photos.zip", buf.Bytes())
	p := between(rec.Body.String(), `id="restore"`, "</form>")
	if rec.Code != http.StatusBadRequest || !strings.Contains(p, "photos.zip holds no .yars/yars.db") || strings.Contains(p, ".yars-restore-") {
		t.Fatalf("not a backup %d:\n%s", rec.Code, p)
	}
}

// D24, Review focus 5: an upload slower than the server's read timeout
// still arrives (the route lifts the deadlines).
func TestRestoreUploadOutlastsReadTimeout(t *testing.T) {
	e := setupSerial(t)
	backupZip := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil).Body.Bytes()
	srv := httptest.NewUnstartedServer(e.h)
	srv.Config.ReadTimeout = 200 * time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close)
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		fw, _ := mw.CreateFormFile("backup", "b.zip")
		for i := 0; i < len(backupZip); i += len(backupZip)/6 + 1 {
			fw.Write(backupZip[i:min(i+len(backupZip)/6+1, len(backupZip))])
			time.Sleep(100 * time.Millisecond) // about 0.6 s in all
		}
		mw.Close()
		pw.Close()
	}()
	req, _ := http.NewRequest("POST", srv.URL+"/admin/system/restore", pr)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("slow upload: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || len(e.restored(t)) != 1 {
		t.Fatalf("slow upload %d, restored %v", resp.StatusCode, e.restored(t))
	}
}

// D24: when nothing can be written beside the data folder (its parent is
// read-only), the Restore panel says so.
func TestRestoreUploadParentNotWritable(t *testing.T) {
	e := setupSerial(t)
	parent := filepath.Dir(e.dir)
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0o755) })
	if f, err := os.CreateTemp(parent, "probe-"); err == nil { // running as root: permissions do not hold
		f.Close()
		os.Remove(f.Name())
		t.Skip("the parent stays writable for this user")
	}
	rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "b.zip", []byte("PK"))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(between(rec.Body.String(), `id="restore"`, "</form>"), "cannot write beside "+e.dir) {
		t.Fatalf("read-only parent %d:\n%s", rec.Code, rec.Body.String())
	}
}

// D24: only an admin restores.
func TestRestoreUploadAdminOnly(t *testing.T) {
	e := setupSerial(t)
	if rec := e.uploadFile(t, "alice", "/admin/system/restore", "backup", "b.zip", []byte("PK")); rec.Code != http.StatusForbidden {
		t.Fatalf("alice %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	p := between(b, `<form class="panel sys" id="restore"`, "</form>")
	for _, want := range []string{`action="/admin/system/restore"`, `enctype="multipart/form-data"`, `<h2>Restore</h2>`, `type="file" name="backup"`,
		`<button class="btn primary sm w128">Restore</button>`, `<span class="sl">Last restore</span><span class="sv" title="—">—</span>`} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel lacks %s:\n%s", want, p)
		}
	}
	if i, j := strings.Index(b, `id="aiusage"`), strings.Index(b, `id="restore"`); j < i {
		t.Fatal("Restore is not after AI usage")
	}
}
