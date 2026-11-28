package web

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// With Require Check off, an approve runs every rule (scripts, AI) inside the
// request, which may take longer than the server's write timeout: the action
// lifts it, so the browser gets the redirect instead of a dropped
// connection. (A submit runs the pattern and built-in rules only.)
func TestApproveOutlivesWriteTimeout(t *testing.T) {
	e := setupSerial(t)
	e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"bob"}}, nil)
	e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"high"}}, nil)
	e.rules(t, "- id: scripted\n  script: check.sh\n  level: warning\n", map[string]string{"check.sh": "cat >/dev/null; sleep 1; echo '[]'\n"})
	if err := e.srv.Store.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		act workflow.Action
		u   config.User
	}{{workflow.Submit, wAlice}, {workflow.Clear, wBob}} {
		if err := e.srv.Store.Transition("acme", fdir, step.act, "", step.u); err != nil {
			t.Fatalf("%s: %v", step.act, err)
		}
	}
	hs := e.srv.HTTPServer("127.0.0.1:0")
	hs.WriteTimeout = 300 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+fpath+"/action/approve", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["dora"]})
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("code %d", resp.StatusCode)
	}
	if e.status(t) != "complete" {
		t.Fatalf("status %s", e.status(t))
	}
}

// MCP lint and transition run every rule too: /mcp outlives the timeout.
func TestMCPOutlivesWriteTimeout(t *testing.T) {
	e := setupSerial(t)
	e.srv.MCP = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.Write([]byte("done"))
	})
	hs := e.srv.HTTPServer("127.0.0.1:0")
	hs.WriteTimeout = 300 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	resp, err := http.Get("http://" + ln.Addr().String() + "/mcp")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != "done" {
		t.Fatalf("err %v body %q", err, b)
	}
}
