package gitserve

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/logs"
)

// A wrong password over git is a failed login in the service log, with the
// name and the address; a request without credentials (git's first) and a
// good password write nothing, and the password is never logged.
func TestFailedGitPasswordReachesTheServiceLog(t *testing.T) {
	lg, out := logs.NewRecorder()
	srv, _, _ := setupServer(t, func(gs *Server) { gs.Logger, gs.Auth.Logger = lg, lg })
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
	if code := get("", ""); code != http.StatusUnauthorized || len(out.Records()) != 0 {
		t.Fatalf("no credentials: %d, log %q", code, out.Text())
	}
	if code := get("alice", "pw"); code != http.StatusOK || len(out.Records()) != 0 {
		t.Fatalf("a good password: %d, log %q", code, out.Text())
	}
	if code := get("alice", "wrong-secret"); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password: %d", code)
	}
	recs := out.Records()
	if len(recs) != 1 || recs[0].Msg != "git login failed" || recs[0].Str("user") != "alice" || recs[0].Level < slog.LevelInfo ||
		!strings.HasPrefix(recs[0].Str("remote"), "127.0.0.1:") || strings.Contains(out.Text(), "wrong-secret") {
		t.Fatalf("log %q", out.Text())
	}
}

// What git http-backend writes to stderr is a line of the service log each,
// with the engagement and the account, never free text on the process's own
// stderr.
func TestGitBackendStderrIsLogged(t *testing.T) {
	lg, out := logs.NewRecorder()
	w := logs.NewLineWriter(lg, slog.LevelWarn, "git http-backend", slog.String("eng", "acme"), slog.String("user", "alice"))
	w.Write([]byte("fatal: bad ob"))
	w.Write([]byte("ject\nerror: second\nlast"))
	w.Flush()
	recs := out.With("git http-backend")
	if len(recs) != 3 || recs[0].Str("err") != "fatal: bad object" || recs[1].Str("err") != "error: second" || recs[2].Str("err") != "last" ||
		recs[0].Str("eng") != "acme" || recs[0].Str("user") != "alice" || recs[0].Level != slog.LevelWarn {
		t.Fatalf("log:\n%s", out.Text())
	}
}
