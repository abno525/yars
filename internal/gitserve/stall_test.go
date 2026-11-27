package gitserve

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/logs"
)

// receiveLog is a Receive func that notes each push it is given.
type receiveLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *receiveLog) receive(eng string, u config.User, serve func()) {
	l.mu.Lock()
	l.seen = append(l.seen, u.Username+"@"+eng)
	l.mu.Unlock()
	serve()
}

func (l *receiveLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

// rawPost sends the head of a POST with the announced length and the given
// part of its body, then nothing, and returns what the server answers. The
// test's own wait is generous; the server's idle time is the short one.
func rawPost(t *testing.T, url, path string, length int, part string) string {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: %d\r\n\r\n%s", path, auth, length, part)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, _ := io.ReadAll(conn) // the server answers and closes
	return string(b)
}

// A push whose body stops part way never reaches Receive, where the store
// takes the repository's lock: the body is read whole before git starts.
// After the idle time the pusher gets 408 and the log one warn line, with
// the engagement, the user and the bytes read. So for an engagement and for
// the main repository, which any account can send a push to. No spool file
// is left.
func TestStalledPushNeverReachesReceive(t *testing.T) {
	var rl receiveLog
	lg, out := logs.NewRecorder()
	srv, _, _ := setupServer(t, func(gs *Server) {
		gs.Receive = rl.receive
		gs.IdleTimeout = 200 * time.Millisecond
		gs.Logger = lg
	})
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	for _, path := range []string{"/git/e/acme/git-receive-pack", "/git/yars/git-receive-pack"} {
		out.Reset()
		got := rawPost(t, srv.URL, path, 1000, "0094")
		if !strings.HasPrefix(got, "HTTP/1.1 408 ") || !strings.Contains(got, "the request was cut off") {
			t.Fatalf("%s: a stalled body got %q", path, got)
		}
		if seen := rl.all(); len(seen) != 0 {
			t.Fatalf("%s: the stalled push reached Receive: %v", path, seen)
		}
		recs := out.With("git: a request body stalled and was cut off")
		if len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Str("user") != "alice" || recs[0].Str("bytes") != "4" {
			t.Fatalf("%s: log:\n%s", path, out.Text())
		}
		if eng := recs[0].Str("eng"); (eng == "acme") != strings.Contains(path, "/e/acme/") {
			t.Fatalf("%s: the line's engagement is %q", path, eng)
		}
		if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
			t.Fatalf("%s: spool files left: %v", path, ents)
		}
	}
	// a fetch's body is spooled the same way: no git process waits for it
	if got := rawPost(t, srv.URL, "/git/e/acme/git-upload-pack", 1000, "0094"); !strings.HasPrefix(got, "HTTP/1.1 408 ") {
		t.Fatalf("a stalled fetch got %q", got)
	}
}

// A body announced over the cap is refused before a byte of it is read, with
// or without a chunked encoding, and never reaches Receive.
func TestPushOverCapRefusedBeforeRead(t *testing.T) {
	var rl receiveLog
	srv, _, _ := setupServer(t, func(gs *Server) {
		gs.Receive = rl.receive
		gs.MaxBody = 64 << 10
	})
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	got := rawPost(t, srv.URL, "/git/e/acme/git-receive-pack", 1<<20, "0094")
	if !strings.HasPrefix(got, "HTTP/1.1 413 ") {
		t.Fatalf("a body announced over the cap got %q", got)
	}
	if seen := rl.all(); len(seen) != 0 {
		t.Fatalf("the push reached Receive: %v", seen)
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("spool files left: %v", ents)
	}
}

// countingWriter is a client's connection as the handler sees it: it counts
// what was written to it.
type countingWriter struct {
	mu     sync.Mutex
	hdr    http.Header
	code   int
	body   bytes.Buffer
	writes int
}

func (c *countingWriter) Header() http.Header { return c.hdr }

func (c *countingWriter) WriteHeader(code int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.code == 0 {
		c.code = code
	}
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.code == 0 {
		c.code = 200
	}
	return c.body.Write(p)
}

func (c *countingWriter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// Nothing of a push's answer is written to the client inside Receive: a
// client that does not read cannot hold the lock the store has there. The
// answer is sent whole once Receive has returned.
func TestPushAnswerSentAfterReceive(t *testing.T) {
	w := &countingWriter{hdr: http.Header{}}
	inside := -1
	var gs *Server
	setupServer(t, func(s *Server) {
		s.Receive = func(eng string, u config.User, serve func()) {
			serve()
			inside = w.count()
		}
		gs = s
	})
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// a push that asks for nothing: git answers it without a change
	req := httptest.NewRequest("POST", "/git/e/acme/git-receive-pack", strings.NewReader("0000"))
	req.SetBasicAuth("alice", "pw")
	req.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	gs.Handler().ServeHTTP(w, req)
	if inside != 0 {
		t.Fatalf("%d writes reached the client inside Receive", inside)
	}
	if w.code != 200 || w.hdr.Get("Content-Type") != "application/x-git-receive-pack-result" {
		t.Fatalf("the answer: %d %v %q", w.code, w.hdr, w.body.String())
	}
	if cl := w.hdr.Get("Content-Length"); cl != fmt.Sprint(w.body.Len()) {
		t.Fatalf("Content-Length %q for %d bytes", cl, w.body.Len())
	}
	if ents, _ := os.ReadDir(tmp); len(ents) != 0 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

// The deadline of a body moves forward before every read, so a body that
// keeps coming is never cut, however long it takes; and the bytes are
// counted.
func TestIdleReaderMovesDeadlinePerRead(t *testing.T) {
	var set []time.Time
	r := &idleReader{r: iotest(3, "abcd"), idle: time.Hour, set: func(at time.Time) error {
		set = append(set, at)
		return nil
	}}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "abcdabcdabcd" || r.n != 12 {
		t.Fatalf("read %q (%d) %v", b, r.n, err)
	}
	// three reads with bytes and the one that ends the body
	if len(set) != 4 {
		t.Fatalf("the deadline was set %d times for 4 reads", len(set))
	}
	for i, at := range set {
		if at.IsZero() || (i > 0 && at.Before(set[i-1])) {
			t.Fatalf("deadline %d: %v after %v", i, at, set[:i])
		}
	}
}

// iotest reads as n chunks of s, one for each Read, then ends.
func iotest(n int, s string) io.Reader { return &chunks{n: n, s: s} }

type chunks struct {
	n int
	s string
}

func (c *chunks) Read(p []byte) (int, error) {
	if c.n == 0 {
		return 0, io.EOF
	}
	c.n--
	return copy(p, c.s), nil
}
