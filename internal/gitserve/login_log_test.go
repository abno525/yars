package gitserve

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

// syncBuf is a log output written by the server's goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A wrong password over git is a failed login in the service log, with the
// name and the address; a request without credentials (git's first) and a
// good password write nothing, and the password is never logged.
func TestFailedGitPasswordReachesTheServiceLog(t *testing.T) {
	srv, _, _ := setupDB(t)
	var out syncBuf
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	get := func(user, pw string) int {
		t.Helper()
		req, _ := http.NewRequest("GET", srv.URL+"/git/e/acme/info/refs?service=git-upload-pack", nil)
		if user != "" {
			req.SetBasicAuth(user, pw)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := get("", ""); code != http.StatusUnauthorized || out.String() != "" {
		t.Fatalf("no credentials: %d, log %q", code, out.String())
	}
	if code := get("alice", "pw"); code != http.StatusOK || out.String() != "" {
		t.Fatalf("a good password: %d, log %q", code, out.String())
	}
	if code := get("alice", "wrong-secret"); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password: %d", code)
	}
	got := out.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, `git login failed: user "alice" from 127.0.0.1:`) || strings.Contains(got, "wrong-secret") {
		t.Fatalf("log %q", got)
	}
}
