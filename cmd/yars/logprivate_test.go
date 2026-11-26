package main

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
)

// lockedBuf is the stderr of a test's server.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// The service log holds IDs and usernames, never text (L.4), also for what
// comes in over MCP and by push. A server built as yars serve builds it,
// logging at debug through the service log's own handler, gets a finding
// over MCP with a marker in every text, an MCP call that fails inside the
// server, a push with marked text and a marked file name, and a push the
// hook refuses. No marker, password or token is in the log, in either
// format; the setup code, the accounts and the IDs are.
func TestNoPrivateTextInLogMCPAndPush(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	bin := hookBinary(t)
	for _, format := range []string{logs.Text, logs.JSON} {
		t.Run(format, func(t *testing.T) {
			var out lockedBuf
			cfg := config.Default()
			cfg.Log.Format = format
			lg, _ := serverLog(&out, cfg, "debug")
			var marks []string
			mark := func(what string) string {
				m := "zq" + what + "7f3kq"
				marks = append(marks, m)
				return m
			}
			pw := mark("password")
			s := serveLogged(t, lg, bin, pw)
			tokens := auth.NewTokens(s.d)
			tok := map[string]string{}
			for _, u := range []string{"alice", "dora"} {
				v, _, err := tokens.Create(u, u, db.TokenSpec{Kind: db.TokenMCP, Name: mark("label" + u), Scopes: []string{db.ScopeAll}})
				if err != nil {
					t.Fatal(err)
				}
				tok[u] = v
				marks = append(marks, v)
			}
			// the one line that holds a secret: the setup code of a first start
			fresh := t.TempDir()
			if err := initData(fresh); err != nil {
				t.Fatal(err)
			}
			code := firstRunCode(openDB(t, fresh), cfg, fresh, lg)

			call := func(user, tool string, args string) string {
				t.Helper()
				req, _ := http.NewRequest("POST", s.url+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`))
				req.Header.Set("Authorization", "Bearer "+tok[user])
				req.Header.Set("X-Request-ID", mark("reqid"))
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 {
					t.Fatalf("%s: %d %s", tool, resp.StatusCode, b)
				}
				return string(b)
			}
			ok := func(user, tool, args string) {
				t.Helper()
				if b := call(user, tool, args); strings.Contains(b, `"isError":true`) {
					t.Fatalf("%s: %s", tool, b)
				}
			}
			title := mark("title")
			ok("alice", "create_finding", `{"engagement":"acme","title":"`+title+`"}`)
			dir := "F-001-" + title
			if _, err := s.st.Finding("acme", dir); err != nil {
				t.Fatalf("the finding's folder is not %s: %v", dir, err)
			}
			f := `"engagement":"acme","finding":"F-001"`
			ok("alice", "update_section", `{`+f+`,"section":"Impact","body":"`+mark("section")+`"}`)
			ok("alice", "set_field", `{`+f+`,"field":"details.Location","value":"`+mark("details")+`"}`)
			ok("alice", "set_field", `{`+f+`,"field":"cvss","value":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"}`)
			ok("alice", "set_field", `{`+f+`,"field":"cvss_reason.AC","value":"`+mark("cvssreason")+`"}`)
			ok("alice", "set_field", `{`+f+`,"field":"reviewers","value":"dora"}`)
			ok("alice", "add_chat_message", `{`+f+`,"text":"`+mark("chat")+`"}`)
			ok("alice", "transition", `{`+f+`,"action":"submit"}`)
			ok("dora", "transition", `{`+f+`,"action":"return","reason":"`+mark("returnreason")+`"}`)
			call("alice", mark("tool"), `{}`)

			// a call that fails inside the server: the folder cannot be written
			folder := filepath.Join(s.dir, "engagements", "acme", "findings", dir)
			if err := os.Chmod(folder, 0o555); err != nil {
				t.Fatal(err)
			}
			failed := call("alice", "update_section", `{`+f+`,"section":"Impact","body":"`+mark("failedsave")+`"}`)
			os.Chmod(folder, 0o755)
			if !strings.Contains(failed, "server_error") {
				t.Fatalf("a save into a read-only folder: %s", failed)
			}

			// a push with marked text and a marked file name, then one the hook refuses
			clone := filepath.Join(t.TempDir(), "acme")
			remote := strings.Replace(s.url, "http://", "http://alice:"+url.QueryEscape(pw)+"@", 1) + "/git/e/acme"
			git := func(args ...string) (string, error) {
				cmd := exec.Command("git", append([]string{"-C", clone, "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "-c", "commit.gpgsign=false"}, args...)...)
				cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
				b, err := cmd.CombinedOutput()
				return string(b), err
			}
			if b, err := exec.Command("git", "clone", "-q", remote, clone).CombinedOutput(); err != nil {
				t.Fatalf("clone: %v %s", err, b)
			}
			file := filepath.Join(clone, "findings", dir, "finding.md")
			edit := func(old, new string) {
				t.Helper()
				b, err := os.ReadFile(file)
				if err != nil || !strings.Contains(string(b), old) {
					t.Fatalf("finding.md lacks %q: %v\n%s", old, err, b)
				}
				os.WriteFile(file, []byte(strings.Replace(string(b), old, new, 1)), 0o644)
			}
			os.MkdirAll(filepath.Join(clone, "findings", dir, "attachments"), 0o755)
			os.WriteFile(filepath.Join(clone, "findings", dir, "attachments", mark("pushfile")+".txt"), []byte(mark("pushcontent")), 0o644)
			b, _ := os.ReadFile(file)
			os.WriteFile(file, append(b, []byte("\n"+mark("pushtext")+"\n")...), 0o644)
			git("add", "-A")
			if b, err := git("commit", "-qm", mark("commitmessage")); err != nil {
				t.Fatalf("commit: %v %s", err, b)
			}
			if b, err := git("push", "-q", "origin", "HEAD:main"); err != nil {
				t.Fatalf("push: %v %s", err, b)
			}
			edit("author: alice\n", "author: alice\nstatus: complete\n")
			if b, err := git("commit", "-qam", mark("refusedmessage")); err != nil {
				t.Fatalf("commit: %v %s", err, b)
			}
			if b, err := git("push", "origin", "HEAD:main"); err == nil || !strings.Contains(b, "remote: yars:") {
				t.Fatalf("a push the hook refuses: %v %s", err, b)
			}

			got := out.String()
			low := strings.ToLower(got)
			for _, m := range marks {
				if strings.Contains(low, strings.ToLower(m)) {
					t.Errorf("the log holds %q", m)
				}
			}
			wants := []string{`setup_code=` + code, `msg=request `, `user=alice`, `user=dora`, `eng=acme`, `finding=F-001`, `tool=update_section`, `code=server_error`,
				`msg="mcp: a tool failed"`, "permission denied", `route="git receive-pack"`,
				// the two pushes, each with its one line
				`msg="push accepted" eng=acme user=alice`, `msg="push refused" eng=acme user=alice`}
			if format == logs.JSON {
				wants = []string{`"setup_code":"` + code + `"`, `"msg":"request"`, `"user":"alice"`, `"user":"dora"`, `"eng":"acme"`, `"finding":"F-001"`, `"tool":"update_section"`,
					`"code":"server_error"`, `"msg":"mcp: a tool failed"`, "permission denied", `"route":"git receive-pack"`,
					`"msg":"push accepted","eng":"acme","user":"alice"`, `"msg":"push refused","eng":"acme","user":"alice"`}
			}
			for _, want := range wants {
				if !strings.Contains(got, want) {
					t.Errorf("the log lacks %s", want)
				}
			}
			if t.Failed() {
				t.Logf("log:\n%s", got)
			}
		})
	}
}
