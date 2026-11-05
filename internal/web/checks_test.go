package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"yars/internal/gitrepo"
	"yars/internal/rules"
)

func (e *env) rules(t *testing.T, yaml string, scripts map[string]string) {
	t.Helper()
	rd := filepath.Join(e.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(yaml), 0o644)
	for name, body := range scripts {
		os.WriteFile(filepath.Join(rd, name), []byte("#!/bin/sh\n"+body), 0o755)
	}
	eng := rules.NewEngine(rd, e.srv.Cfg)
	e.srv.Rules = eng
	e.srv.Store.Linter = eng
}

// checksPanel is the checks panel (#checks) of a page or fragment.
func checksPanel(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `id="checks"`)
	if i < 0 {
		t.Fatalf("no checks panel:\n%s", b)
	}
	i = strings.LastIndex(b[:i], "<section")
	j := strings.Index(b[i:], "</section>")
	return b[i : i+j]
}

const styleRules = `
- id: title-word
  target: title
  regex_forbid: 'injection'
  message: Avoid the word injection
- id: scripted
  script: check.sh
  level: warning
`

func TestChecksPanel(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; sleep 0.3; echo '[{"message":"script says hi","quote":"q1","target":"section:Impact"}]'` + "\n"})
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	p := checksPanel(t, b)
	if !strings.Contains(p, "Avoid the word injection") || strings.Contains(p, "script says hi") {
		t.Fatalf("checks panel (fast only):\n%s", p)
	}
	if !strings.Contains(b[strings.Index(b, `id="workflow"`):], "Avoid the word injection") {
		t.Fatal("workflow bar doesn't list rule errors")
	}
	// the panel refetches itself on check events
	if !strings.Contains(p, `hx-get="/e/acme/f/001/checks"`) || !strings.Contains(p, "sse:check") || !strings.Contains(p, "data-sse") {
		t.Fatalf("no live refresh:\n%s", p)
	}
	rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	run := rec.Body.String()
	if rec.Code != 200 || !regexp.MustCompile(`<button[^>]*class="btn [^"]*w152"[^>]*disabled[^>]*>Checking \d/2</button>`).MatchString(run) {
		t.Fatalf("running panel %d:\n%s", rec.Code, run)
	}
	if !strings.Contains(run, `class="tag check-running"`) {
		t.Fatalf("no running state:\n%s", run)
	}
	e.srv.Store.WaitChecks()
	done := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(done, "script says hi") || !strings.Contains(done, "q1") || !strings.Contains(done, ">Impact<") {
		t.Fatalf("finished panel:\n%s", done)
	}
	if !regexp.MustCompile(`<button[^>]*class="btn [^"]*w152"[^>]*>Check</button>`).MatchString(done) || !strings.Contains(done, `class="tag check-done"`) {
		t.Fatalf("idle button / done state:\n%s", done)
	}
	// the violations were posted to the chat as check comments
	chat := e.do(t, "alice", "GET", fpath+"/chat", nil, nil).Body.String()
	if !strings.Contains(chat, "script says hi") || !strings.Contains(chat, "Avoid the word injection") {
		t.Fatalf("chat:\n%s", chat)
	}
}

func TestChecksPanelLayout(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"warn","quote":"q"}]'` + "\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Contains(p, "style=") {
		t.Fatalf("inline style:\n%s", p)
	}
	if !strings.Contains(p, `class="slot w128"`) || !strings.Contains(p, "<thead>") {
		t.Fatalf("status slot / headers:\n%s", p)
	}
	// alice (pentester) may dismiss the warning, not the error: the error's
	// button keeps its place
	if strings.Count(p, ">Dismiss</button>") != 1 || !strings.Contains(p, `<span class="slot w96"></span>`) {
		t.Fatalf("dismiss buttons for alice:\n%s", p)
	}
	if !regexp.MustCompile(`class="btn [^"]*w96"`).MatchString(p) {
		t.Fatalf("dismiss width:\n%s", p)
	}
	pb := e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Count(pb, ">Dismiss</button>") != 2 {
		t.Fatalf("dismiss buttons for bob:\n%s", pb)
	}
	if !strings.Contains(p, `<span class="badge">1</span>`) {
		t.Fatalf("counts:\n%s", p)
	}
}

func TestChecksDismiss(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	form := url.Values{"rule": {"title-word"}, "quote": {"injection"}}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", form, nil); rec.Code != 403 {
		t.Fatalf("pentester dismissed an error: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", url.Values{"rule": {"nope"}, "quote": {"x"}}, nil); rec.Code != 400 {
		t.Fatalf("unknown violation: %d", rec.Code)
	}
	rec := e.do(t, "bob", "POST", fpath+"/checks/dismiss", form, nil)
	if rec.Code != 200 {
		t.Fatalf("reviewer dismiss %d: %s", rec.Code, rec.Body.String())
	}
	p := rec.Body.String()
	if !strings.Contains(p, "Dismissed") || !strings.Contains(p, ">bob<") || !strings.Contains(p, "<details") {
		t.Fatalf("dismissed row:\n%s", p)
	}
	// the gate ignores it now
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	wf := b[strings.Index(b, `id="workflow"`):]
	wf = wf[:strings.Index(wf, "</section>")]
	if strings.Contains(wf, "Avoid the word injection") {
		t.Fatalf("dismissed error still in the gate:\n%s", wf)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/undismiss", form, nil); rec.Code != 403 {
		t.Fatalf("pentester restored an error: %d", rec.Code)
	}
	rec = e.do(t, "dora", "POST", fpath+"/checks/undismiss", form, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "<details") {
		t.Fatalf("undismiss %d:\n%s", rec.Code, rec.Body.String())
	}
}

func TestChecksStaleAndInvalid(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo not json\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `class="tag check-invalid"`) || !strings.Contains(p, "Invalid output") {
		t.Fatalf("invalid state:\n%s", p)
	}
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "changed", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	p = e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `class="tag check-stale"`) {
		t.Fatalf("stale state:\n%s", p)
	}
}

func TestChecksProgressEvents(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	sub := e.srv.Events.Subscribe("acme", "", 64)
	defer e.srv.Events.Unsubscribe(sub)
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	n := 0
	for len(sub.C()) > 0 {
		if ev := <-sub.C(); ev.Kind == "check" && ev.Fid == "F-001" {
			n++
		}
	}
	if n < 4 { // started, 0/2, 1/2, 2/2, finished
		t.Fatalf("%d check events", n)
	}
}

func TestPreviewShowsHints(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: impact-bt\n  target: section:Impact\n  regex_forbid: '`'\n  message: No backticks in Impact\n", nil)
	edit := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	var pv string
	for _, part := range strings.Split(edit, `hx-post="`)[1:] {
		u := part[:strings.Index(part, `"`)]
		if strings.Contains(u, "/preview") {
			pv = strings.ReplaceAll(u, "&amp;", "&")
		}
	}
	if pv == "" || !strings.Contains(pv, "s=Impact") {
		t.Fatalf("preview url %q", pv)
	}
	b := e.do(t, "alice", "POST", pv, url.Values{"body": {"uses `x`"}}, nil).Body.String()
	if !strings.Contains(b, "No backticks in Impact") {
		t.Fatalf("no hint:\n%s", b)
	}
}
