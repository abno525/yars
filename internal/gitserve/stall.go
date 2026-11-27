package gitserve

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// DefaultIdleTimeout is how long a git request may send nothing, or take
// nothing, before it is cut.
const DefaultIdleTimeout = 2 * time.Minute

// idle is the server's idle time.
func (s *Server) idle() time.Duration {
	if s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return DefaultIdleTimeout
}

// idleReader reads a request body under an idle deadline: before each read
// the deadline (set: the connection's read deadline) moves idle ahead. A
// body that keeps coming is never cut, however large and however slow; one
// that stops ends with the connection's timeout. n counts the bytes read.
type idleReader struct {
	r    io.Reader
	idle time.Duration
	set  func(time.Time) error
	n    int64
}

func (d *idleReader) Read(p []byte) (int, error) {
	d.set(time.Now().Add(d.idle)) // an error: not a net/http connection (tests)
	n, err := d.r.Read(p)
	d.n += int64(n)
	return n, err
}

// idleWriter writes an answer under an idle deadline: before each write the
// connection's write deadline moves idle ahead. A client that keeps reading
// is never cut; one that stops ends the request. The time git works without
// writing is not limited.
type idleWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (i *idleWriter) Write(p []byte) (int, error) {
	i.rc.SetWriteDeadline(time.Now().Add(i.idle))
	return i.ResponseWriter.Write(p)
}

// Unwrap lets http.ResponseController reach the connection.
func (i *idleWriter) Unwrap() http.ResponseWriter { return i.ResponseWriter }

// answer records what git answers to a push, in a temporary file, so that
// nothing is written to the client while the push holds its repository's
// lock: a client that does not read would hold the lock with it. send
// writes the record to the client afterwards.
type answer struct {
	hdr  http.Header
	code int
	f    *os.File
	err  error // the first failed write to the file
}

func newAnswer() (*answer, error) {
	f, err := os.CreateTemp("", "yars-git-answer-*") // 0600
	if err != nil {
		return nil, err
	}
	return &answer{hdr: http.Header{}, f: f}, nil
}

func (a *answer) Header() http.Header { return a.hdr }

func (a *answer) WriteHeader(code int) {
	if a.code == 0 {
		a.code = code
	}
}

// Write never fails: a failed write would make the CGI host kill git in the
// middle of a push. The failure is kept, and send answers with an error.
func (a *answer) Write(p []byte) (int, error) {
	a.WriteHeader(http.StatusOK)
	if a.err == nil {
		_, a.err = a.f.Write(p)
	}
	return len(p), nil
}

// send writes the recorded answer to w.
func (a *answer) send(w http.ResponseWriter) {
	size, err := a.f.Seek(0, io.SeekCurrent)
	if err == nil {
		_, err = a.f.Seek(0, io.SeekStart)
	}
	if a.err != nil || err != nil {
		http.Error(w, "git's answer could not be kept; fetch to see whether the push landed", http.StatusInternalServerError)
		return
	}
	for k, v := range a.hdr {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	code := a.code
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
	io.Copy(w, a.f)
}

// close removes the record.
func (a *answer) close() {
	a.f.Close()
	os.Remove(a.f.Name())
}
