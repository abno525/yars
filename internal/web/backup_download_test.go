package web

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/backup"
)

// holdWriter is a client that takes nothing at first: its first Write
// blocks until release is closed. started closes when that Write begins.
type holdWriter struct {
	hdr     http.Header
	code    int
	body    bytes.Buffer
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func newHoldWriter() *holdWriter {
	return &holdWriter{hdr: http.Header{}, started: make(chan struct{}), release: make(chan struct{})}
}

func (h *holdWriter) Header() http.Header { return h.hdr }

func (h *holdWriter) WriteHeader(code int) {
	if h.code == 0 {
		h.code = code
	}
}

func (h *holdWriter) Write(p []byte) (int, error) {
	h.once.Do(func() { close(h.started) })
	<-h.release
	h.WriteHeader(http.StatusOK)
	return h.body.Write(p)
}

// backupRequest is dora's POST of the Download backup form.
func (e *env) backupRequest(form url.Values) *http.Request {
	req := httptest.NewRequest("POST", "/admin/system/backup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
	return req
}

// While a client takes the backup slowly, or not at all, no repository lock
// is held: the ZIP is built first, with the locks, and sent after. What
// arrives is a whole backup, with its length announced.
func TestBackupDownloadSendsWithoutLocks(t *testing.T) {
	e := setup(t)
	w := newHoldWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.h.ServeHTTP(w, e.backupRequest(url.Values{}))
	}()
	select {
	case <-w.started:
	case <-time.After(30 * time.Second):
		close(w.release)
		t.Fatal("the download never began")
	}
	free := make(chan struct{})
	go func() {
		e.srv.Store.LockMain()()
		e.srv.Store.LockEngagement("acme")()
		close(free)
	}()
	select {
	case <-free:
	case <-time.After(5 * time.Second):
		close(w.release)
		<-done
		t.Fatal("a repository lock is held while the client takes the download")
	}
	close(w.release)
	<-done
	if w.code != 200 || w.hdr.Get("Content-Type") != "application/zip" || w.hdr.Get("Content-Length") != strconv.Itoa(w.body.Len()) {
		t.Fatalf("the download: %d %v for %d bytes", w.code, w.hdr, w.body.Len())
	}
	p := filepath.Join(t.TempDir(), "backup.zip")
	if err := os.WriteFile(p, w.body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := backup.Verify(p); err != nil || rep.Engagements != 1 || rep.Findings != 1 {
		t.Fatalf("report %+v %v", rep, err)
	}
}

// failWriter is a client that went away: every Write fails.
type failWriter struct{ hdr http.Header }

func (f *failWriter) Header() http.Header       { return f.hdr }
func (f *failWriter) WriteHeader(int)           {}
func (f *failWriter) Write([]byte) (int, error) { return 0, errors.New("gone") }

// The ZIP a download is built in is the server's alone and is gone when the
// request ends: after a download, after a build that failed and after a
// client that went away. Only a download that arrived whole is audited.
func TestBackupDownloadLeavesNoFile(t *testing.T) {
	e := setupSerial(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	empty := func(when string) {
		t.Helper()
		if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
			t.Fatalf("%s: left in the temporary folder: %v", when, ents)
		}
	}
	audited := func() int {
		l, _ := e.srv.Store.DB().AuditLog(10)
		n := 0
		for _, row := range l {
			if row.Action == "backup" {
				n++
			}
		}
		return n
	}
	// while it is built the file is there, readable by its owner alone
	seen := false
	e.srv.backupBuilt = func(path string) {
		fi, err := os.Stat(path)
		seen = err == nil && fi.Mode().Perm() == 0o600 && filepath.Dir(path) == tmp
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil); rec.Code != 200 {
		t.Fatalf("download %d", rec.Code)
	}
	if !seen {
		t.Fatal("the ZIP was not built as a 0600 file in the temporary folder")
	}
	e.srv.backupBuilt = nil
	empty("after a download")
	if audited() != 1 {
		t.Fatalf("%d audit rows after a download", audited())
	}

	// a client that went away
	func() {
		defer func() { recover() }() // the handler aborts the connection
		e.h.ServeHTTP(&failWriter{hdr: http.Header{}}, e.backupRequest(url.Values{}))
	}()
	empty("after a client that went away")
	if audited() != 1 {
		t.Fatalf("a download that did not arrive is audited: %d rows", audited())
	}
	if n := len(e.log.With("backup: the download ended part way")); n != 1 {
		t.Fatalf("log:\n%s", e.log.Text())
	}

	// a build that fails part way: a file the server cannot read
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	bad := filepath.Join(e.dir, "unreadable")
	if err := os.WriteFile(bad, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Header().Get("Content-Type"), "zip") || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("a failed build: %d %v", rec.Code, rec.Header())
	}
	empty("after a failed build")
	if audited() != 1 {
		t.Fatalf("a failed build is audited: %d rows", audited())
	}
}
