package web

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// noise is n bytes a ZIP cannot make smaller, the same at every run.
func noise(n int) []byte {
	b := make([]byte, n)
	x := uint64(88172645463325252)
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
	return b
}

// deadlineRec is a client's connection with a write deadline
// (http.ResponseController finds SetWriteDeadline): it notes, in order, each
// deadline set at least half an hour ahead ("d") and each write ("w").
// Deadlines nearer than that, and lifted ones, are another part's.
type deadlineRec struct {
	mu     sync.Mutex
	hdr    http.Header
	code   int
	start  time.Time
	events []string
}

func (d *deadlineRec) Header() http.Header { return d.hdr }

func (d *deadlineRec) WriteHeader(code int) {
	if d.code == 0 {
		d.code = code
	}
}

func (d *deadlineRec) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.WriteHeader(http.StatusOK)
	d.events = append(d.events, "w")
	return len(p), nil
}

func (d *deadlineRec) SetWriteDeadline(at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if at.After(d.start.Add(30 * time.Minute)) {
		d.events = append(d.events, "d")
	}
	return nil
}

// The backup is sent under an idle deadline: it is set when the build ends
// (the request's own has passed by then on a large folder), moved ahead
// before each piece, so a slow line is never cut, and once more for what is
// flushed after the handler.
func TestBackupSendMovesDeadlinePerPiece(t *testing.T) {
	e := setup(t)
	// more than one piece of 32 KiB
	if err := os.WriteFile(filepath.Join(e.dir, "noise.bin"), noise(100<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	e.srv.backupIdle = time.Hour
	w := &deadlineRec{hdr: http.Header{}, start: time.Now()}
	e.h.ServeHTTP(w, e.backupRequest(url.Values{}))
	seq := strings.Join(w.events, "")
	writes := strings.Count(seq, "w")
	if w.code != 200 || writes < 3 {
		t.Fatalf("the download: %d, %d writes", w.code, writes)
	}
	if want := "d" + strings.Repeat("dw", writes) + "d"; seq != want {
		t.Fatalf("deadlines and writes: %s, want %s", seq, want)
	}
}

// A client that takes nothing of the download is cut once the idle time has
// passed: the handler ends with one error line, the file is gone and no
// audit row says the backup was downloaded.
func TestBackupDownloadCutWhenClientTakesNothing(t *testing.T) {
	e := setup(t)
	// far more than a connection's buffers hold
	if err := os.WriteFile(filepath.Join(e.dir, "noise.bin"), noise(16<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	e.srv.backupIdle = 200 * time.Millisecond
	built := make(chan string, 1)
	e.srv.backupBuilt = func(path string) { built <- path }
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// the form's POST, and then nothing is read
	fmt.Fprintf(conn, "POST /admin/system/backup HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n",
		strings.TrimPrefix(srv.URL, "http://"), auth.CookieName, e.toks["dora"])
	var file string
	select {
	case file = <-built:
	case <-time.After(60 * time.Second):
		t.Fatal("the backup was never built")
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(e.log.With("backup: the download ended part way")) == 0 {
		if len(e.log.With("backup downloaded")) > 0 {
			t.Skip("the whole backup fit the connection's buffers: nothing to cut")
		}
		if time.Now().After(deadline) {
			conn.Close() // lets the handler go, so the server can close
			t.Fatal("the download of a client that takes nothing was not cut")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// the handler's last steps follow its log line
	for {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ZIP of a cut download is still there")
		}
		time.Sleep(10 * time.Millisecond)
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	for _, row := range l {
		if row.Action == "backup" {
			t.Fatalf("a cut download is audited: %+v", row)
		}
	}
}

// One ZIP is built at a time. A download that comes while another is built
// waits its turn and then builds its own; one whose client left meanwhile
// builds nothing.
func TestBackupBuildsOneAtATime(t *testing.T) {
	e := setup(t)
	var builds atomic.Int32
	e.srv.backupBuilt = func(string) { builds.Add(1) }
	serve := func(req *http.Request) (*httptest.ResponseRecorder, chan struct{}) {
		rec, done := httptest.NewRecorder(), make(chan struct{})
		go func() {
			defer close(done)
			e.h.ServeHTTP(rec, req)
		}()
		return rec, done
	}
	// the first build stops at the main repository's lock, which the test holds
	unlock := e.srv.Store.LockMain()
	first, firstDone := serve(e.backupRequest(url.Values{}))
	deadline := time.Now().Add(30 * time.Second)
	for e.srv.backupMu.TryLock() {
		e.srv.backupMu.Unlock()
		if time.Now().After(deadline) {
			unlock()
			<-firstDone
			t.Fatal("a build takes no turn: two could run at once")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// two more come while it is built; the client of one leaves
	ctx, leave := context.WithCancel(context.Background())
	left, leftDone := serve(e.backupRequest(url.Values{}).WithContext(ctx))
	second, secondDone := serve(e.backupRequest(url.Values{}))
	leave()
	unlock()
	for _, done := range []chan struct{}{firstDone, leftDone, secondDone} {
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			t.Fatal("a download did not end")
		}
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{"the first": first, "the one that waited": second} {
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" || rec.Header().Get("Content-Length") != strconv.Itoa(rec.Body.Len()) {
			t.Fatalf("%s download: %d %v for %d bytes", name, rec.Code, rec.Header(), rec.Body.Len())
		}
	}
	if left.Code == 200 || strings.Contains(left.Header().Get("Content-Type"), "zip") {
		t.Fatalf("the download whose client left: %d %v", left.Code, left.Header())
	}
	if n := builds.Load(); n != 2 {
		t.Fatalf("%d ZIPs were built for two clients that stayed and one that left", n)
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
