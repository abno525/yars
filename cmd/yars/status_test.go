package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
)

// yars status asks the running server what it does now, over a socket in
// the data folder that only the service's account can open: no password, no
// token. It prints plain text: the version, the schema, the uptime, the
// counts and the last warn and error lines. It prints no setup code, no
// password and no escape sequence a client typed; it still answers when the
// database is closed; without a server it says so in one line.
func TestStatusCommand(t *testing.T) {
	// a socket's path is short: not under the test's own long folder
	base, err := os.MkdirTemp("", "ys")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "d")
	if len(statusSocket(dir)) > 100 {
		t.Skipf("the temporary folder is too long for a socket: %s", dir)
	}
	// a sandbox that refuses a connection to a socket cannot run this test
	probe := filepath.Join(base, "probe.sock")
	pl, err := net.Listen("unix", probe)
	if err != nil {
		t.Skipf("no Unix sockets here: %v", err)
	}
	pc, err := net.Dial("unix", probe)
	pl.Close()
	if err != nil {
		t.Skipf("no connection to a Unix socket here: %v", err)
	}
	pc.Close()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	status := func() (string, error) {
		var out bytes.Buffer
		err := cmdStatus([]string{"--data", dir}, &out)
		return out.String(), err
	}
	none := "no server is running on " + dir
	if out, err := status(); err == nil || err.Error() != none || out != "" {
		t.Fatalf("without a server: %q, %v", out, err)
	}

	// a start, by the functions cmdServe calls
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := startConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	var stderr lockedBuf
	lg, level, ring := serverLogRing(&stderr, cfg, "")
	d, st, err := prepareData(r, cfg, lg)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	code := firstRunCode(d, cfg, dir, lg)
	srv, err := serverParts(r, cfg, d, st, lg, "yars", false, code)
	if err != nil {
		t.Fatal(err)
	}
	srv.LogRing, srv.LogLevel = ring, level
	srv.HTTPServer("127.0.0.1:0")
	defer srv.Close()
	stop := startStatus(dir, srv, lg)
	defer stop()
	if !strings.Contains(stderr.String(), "setup_code="+code) || code == "" {
		t.Fatalf("no setup code in the log:\n%s", stderr.String())
	}
	fi, err := os.Stat(statusSocket(dir))
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the socket: %v, %v", fi, err)
	}
	// git does not see the socket: nothing to ignore, nothing to commit
	if b, err := exec.Command("git", "-C", dir, "status", "--porcelain").CombinedOutput(); err != nil || len(b) != 0 {
		t.Fatalf("git status with the socket: %v\n%s", err, b)
	}

	lg.Warn("login failed", "user", "x\x1b[2Jy", "remote", "198.51.100.7:1", "password", "zqpassword7f3kq")
	out, err := status()
	if err != nil {
		t.Fatalf("status: %v\n%s", err, stderr.String())
	}
	for _, want := range []string{"yars " + buildVersion(), "schema " + strconv.Itoa(db.SchemaVersion), " · up ", "log level: info\n", "checks: 0 running, 0 queued",
		"fixes: 0 running", "webhook deliveries: 0 waiting", "mails: 0 being sent", "event streams: none", "locks: none",
		"last warnings and errors: 1", ` WARN  msg="login failed" user=`, "remote=198.51.100.7:1"} {
		if !strings.Contains(out, want) {
			t.Errorf("the status lacks %q", want)
		}
	}
	if strings.Contains(out, code) || strings.Contains(out, "zq") || strings.Contains(out, "\x1b") || strings.Contains(out, "setup") {
		t.Errorf("the status holds the setup code, a password or an escape sequence")
	}
	if t.Failed() {
		t.Fatalf("status:\n%q", out)
	}

	// a held lock, and the database gone
	unlock := st.LockEngagement("acme")
	d.Close()
	out, err = status()
	unlock()
	if err != nil || !strings.Contains(out, "schema — ") || !strings.Contains(out, "webhook deliveries: — waiting") ||
		!strings.Contains(out, "locks: acme held ") || !strings.Contains(out, `msg="login failed"`) {
		t.Fatalf("status with the database closed: %v\n%s", err, out)
	}

	// stopped: the socket is gone
	stop()
	if _, err := os.Stat(statusSocket(dir)); !os.IsNotExist(err) {
		t.Fatalf("the socket after the stop: %v", err)
	}
	if out, err := status(); err == nil || err.Error() != none {
		t.Fatalf("after the stop: %q, %v", out, err)
	}
	// a socket left behind by a server that was killed is replaced at the next start
	stop = startStatus(dir, srv, lg)
	stop2 := startStatus(dir, srv, lg)
	if _, err := status(); err != nil {
		t.Fatalf("a second start over a left socket: %v", err)
	}
	stop2()
	stop()
}

// A socket that cannot be made (here: a data folder too long for a socket's
// address) is one warn line; the server starts anyway.
func TestStatusSocketFailureIsAWarning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("long", 40))
	if err := os.MkdirAll(filepath.Join(dir, ".yars"), 0o700); err != nil {
		t.Fatal(err)
	}
	var stderr lockedBuf
	lg, _, _ := serverLogRing(&stderr, config.Default(), "")
	stop := startStatus(dir, nil, lg)
	stop()
	if got := stderr.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, `level=WARN msg="status: the socket of yars status is not opened`) {
		t.Fatalf("log:\n%s", got)
	}
}
