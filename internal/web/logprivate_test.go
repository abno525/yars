package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/workflow"
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

// The service log holds IDs and usernames, never text (L.4). A server that
// logs as yars serve does (logs.New, at debug) is driven through a finding's
// life with a marker of its own in every text a person types: the title,
// each section, a details row, a CVSS reason, an asset, an attachment's
// name and content, chat, the reasons of a Return and of a dismissal, an
// engagement's name and client, a search, a token's label and value, the
// passwords, the session cookies and two headers a client sets. Requests
// are made to fail on the way (a finding folder that cannot be written, a
// closed database), since an error's text carries paths and values. No
// marker may be in the log, in either format; what a line may hold is.
func TestNoPrivateTextInLog(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only folder")
	}
	for _, format := range []string{logs.Text, logs.JSON} {
		t.Run(format, func(t *testing.T) {
			var out lockedBuf
			e := newEnvLog(t, logs.New(&out, format, slog.LevelDebug))
			// every part that logs has the server's logger
			if e.srv.Store.Logger == nil || e.srv.Auth.Logger == nil || e.srv.Logger == nil || e.srv.Webhooks.Logger == nil || e.srv.Notifier.Logger == nil {
				t.Fatal("a part of the server has no logger")
			}
			var marks []string
			mark := func(what string) string {
				m := "zq" + what + "7f3kq"
				marks = append(marks, m)
				return m
			}
			hdr := map[string]string{"X-Request-ID": mark("reqid"), "Authorization": "Bearer " + mark("authz"), "Referer": "http://example.com/" + mark("referer")}
			do := func(user, method, path string, form url.Values) *httptest.ResponseRecorder {
				t.Helper()
				rec := e.do(t, user, method, path, form, hdr)
				if rec.Code >= 400 {
					b := rec.Body.String()
					t.Fatalf("%s %s: %d %s", method, path, rec.Code, b[:min(len(b), 300)])
				}
				return rec
			}

			// passwords: a new one, a wrong one, the right one
			pw := mark("password") + "A1"
			do("alice", "POST", "/settings/password", url.Values{"current": {"pw"}, "new": {pw}, "repeat": {pw}})
			if rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {mark("wrongpw")}}, hdr); rec.Code != http.StatusUnauthorized {
				t.Fatalf("wrong password: %d", rec.Code)
			}
			if res := e.loginAs(t, "alice", pw); res.StatusCode != http.StatusSeeOther {
				t.Fatalf("login %d", res.StatusCode)
			}

			// an engagement with a name and a client
			do("dora", "POST", "/engagements/new", url.Values{"id": {"mark"}, "name": {mark("engname")}, "client": {mark("client")}, "member": {"alice"}})
			do("dora", "GET", "/e/mark", nil)

			// a finding: its title is in its folder's name
			title := mark("title")
			do("alice", "POST", "/e/acme/findings/new", url.Values{"title": {title}})
			dir := "F-002-" + title
			fp := "/e/acme/f/" + dir
			if _, err := e.srv.Store.Finding("acme", dir); err != nil {
				t.Fatalf("the finding's folder is not %s: %v", dir, err)
			}
			for _, sec := range e.srv.Cfg.Sections {
				do("alice", "POST", fp+"/s/"+url.PathEscape(sec), url.Values{"body": {"Text " + mark("section"+strings.ToLower(sec[:3])) + "."}})
			}
			do("alice", "POST", fp+"/details", url.Values{"row:Location": {mark("details")}})
			do("alice", "POST", fp+"/cvss", vecForm(map[string]string{"reason_AC": mark("cvssreasonac"), "reason_C": mark("cvssreasonc"), "reason_I": mark("cvssreasoni")}))
			do("alice", "POST", fp+"/assets", url.Values{"n": {"1"}, "host_0": {mark("assethost") + ".example"}, "url_0": {"https://" + mark("asseturl") + ".example/x"}, "port_0": {"443"}, "note_0": {mark("assetnote")}})
			if rec := e.sendFile(t, "alice", fp+"/attachments", mark("filename")+".txt", []byte(mark("filecontent"))); rec.Code != 200 {
				t.Fatalf("attachment %d %s", rec.Code, rec.Body.String())
			}
			// a commit that fails: git's error names its command line, and the
			// commit message holds the attachment's name
			engDir := filepath.Join(e.dir, "engagements", "acme")
			hp, err := exec.Command("git", "-C", engDir, "rev-parse", "--git-path", "hooks/pre-commit").Output()
			if err != nil {
				t.Fatal(err)
			}
			hook := strings.TrimSpace(string(hp))
			if !filepath.IsAbs(hook) {
				hook = filepath.Join(engDir, hook)
			}
			os.MkdirAll(filepath.Dir(hook), 0o755)
			if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			refused := e.sendFile(t, "alice", fp+"/attachments", mark("failedfile")+".txt", []byte(mark("failedcontent")))
			os.Remove(hook)
			if refused.Code != http.StatusInternalServerError {
				t.Fatalf("an attachment whose commit fails: %d %s", refused.Code, refused.Body.String())
			}
			do("alice", "POST", fp+"/chat", url.Values{"text": {mark("chat")}})
			do("alice", "GET", "/e/acme?q="+mark("search"), nil)
			do("alice", "GET", fp+"?x="+mark("query"), nil)

			// a rule's error, dismissed with a reason; submit; Return with a reason
			e.rules(t, "- id: no-zq\n  target: title\n  regex_forbid: 'zqtitle'\n  message: No zq\n", nil)
			do("alice", "POST", fp+"/reviewers", url.Values{"reviewer": {"bob"}})
			if rec := e.do(t, "bob", "POST", fp+"/checks/dismiss", url.Values{"rule": {"no-zq"}, "quote": {"zqtitle"}, "reason": {mark("dismissreason")}}, hdr); rec.Code != 200 {
				t.Fatalf("dismiss %d %s", rec.Code, rec.Body.String())
			}
			do("alice", "POST", fp+"/action/submit", url.Values{})
			if ref, _ := e.srv.Store.Finding("acme", dir); ref.F.Meta.Status != "verification" {
				t.Fatalf("not submitted: %s\n%s", ref.F.Meta.Status, checksPanel(t, e.do(t, "alice", "GET", fp, nil, nil).Body.String()))
			}
			do("bob", "POST", fp+"/action/return", url.Values{"reason": {mark("returnreason")}})
			if ref, _ := e.srv.Store.Finding("acme", dir); ref.F.Meta.Status != "draft" {
				t.Fatalf("not returned: %s", ref.F.Meta.Status)
			}

			// a request that fails: the finding's folder cannot be written
			folder := filepath.Join(e.dir, "engagements", "acme", "findings", dir)
			if err := os.Chmod(folder, 0o555); err != nil {
				t.Fatal(err)
			}
			failed := e.do(t, "alice", "POST", fp+"/s/Impact", url.Values{"body": {mark("failedsave")}}, hdr)
			os.Chmod(folder, 0o755)
			if failed.Code != http.StatusInternalServerError {
				t.Fatalf("a save into a read-only folder: %d %s", failed.Code, failed.Body.String())
			}

			// to complete, then sent to a file destination
			do("alice", "POST", fp+"/action/submit", url.Values{})
			if rec := e.do(t, "bob", "POST", fp+"/checks", url.Values{}, hdr); rec.Code != 200 {
				t.Fatalf("check %d %s", rec.Code, rec.Body.String())
			}
			e.srv.Store.WaitChecks()
			if err := e.srv.Store.Transition("acme", dir, workflow.Clear, "", wBob); err != nil {
				t.Fatal(err)
			}
			if err := e.srv.Store.Transition("acme", dir, workflow.Approve, "", wDora); err != nil {
				t.Fatal(err)
			}
			if ref, _ := e.srv.Store.Finding("acme", dir); ref.F.Meta.Status != "complete" {
				t.Fatalf("not complete: %s", ref.F.Meta.Status)
			}
			e.exporters(t, fakePandoc)
			if rec := do("alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {dir}}); rec.Code != http.StatusSeeOther {
				t.Fatalf("export %d %s", rec.Code, rec.Body.String())
			}

			// a token: its label, and its value as the page shows it once
			do("alice", "POST", "/settings/tokens/new", url.Values{"name": {mark("tokenlabel")}, "kind": {"mcp"}, "access": {"read"}, "engs": {"all"}, "expires": {"30"}, "password": {pw}})
			tok := secretRe.FindString(do("alice", "GET", "/settings", nil).Body.String())
			if tok == "" {
				t.Fatal("no token on the page")
			}
			marks = append(marks, tok)
			for _, session := range e.toks {
				marks = append(marks, session)
			}

			// the database goes away under a request
			e.srv.Store.DB().Close()
			e.do(t, "alice", "GET", fp+"?x="+mark("afterclose"), nil, hdr)
			e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {pw}}, hdr)

			got := out.String()
			low := strings.ToLower(got)
			for _, m := range marks {
				if strings.Contains(low, strings.ToLower(m)) || strings.Contains(low, strings.ToLower(url.QueryEscape(m))) {
					t.Errorf("the log holds %q", m)
				}
			}
			// what a line may hold is there: a discarding logger does not pass
			wants := []string{`msg=request `, `user=alice`, `eng=acme`, `finding=F-002`, `msg="login failed"`, `msg="request failed"`, `route="POST /e/{eng}/f/{fid}/s/{section}"`, `status=500`, "permission denied", "git commit -q --only -- "}
			if format == logs.JSON {
				wants = []string{`"msg":"request"`, `"user":"alice"`, `"eng":"acme"`, `"finding":"F-002"`, `"msg":"login failed"`, `"msg":"request failed"`, `"route":"POST /e/{eng}/f/{fid}/s/{section}"`, `"status":500`, "permission denied", "git commit -q --only -- "}
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
