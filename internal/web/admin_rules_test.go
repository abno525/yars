package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"yars/internal/auth"
)

// mainCommit formats the newest commit of the main repo.
func (e *env) mainCommit(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", e.dir, "log", "-1", "--format=%an|%s").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func (e *env) ruleFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, ".yars", "rules", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// upload posts a multipart form with one file field "script".
func (e *env) upload(t *testing.T, user, path string, fields map[string]string, name, body string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if name != "" {
		fw, _ := mw.CreateFormFile("script", name)
		fw.Write([]byte(body))
	}
	mw.Close()
	req := httptest.NewRequest("POST", path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func TestAdminDirectorsOnly(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	for _, u := range []string{"alice", "bob"} {
		for _, r := range []struct{ method, path string }{
			{"GET", "/admin"}, {"GET", "/admin/rules"}, {"GET", "/admin/rules/bench?rule=title-word&eng=acme&fid=" + fdir},
			{"GET", "/admin/rules/bench/findings?eng=acme"}, {"POST", "/admin/rules/save"}, {"POST", "/admin/rules/toggle"}, {"POST", "/admin/rules/delete"},
		} {
			if rec := e.do(t, u, r.method, r.path, url.Values{"id": {"title-word"}}, nil); rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s: %d", u, r.method, r.path, rec.Code)
			}
		}
		if b := e.do(t, u, "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(b, `href="/admin"`) {
			t.Errorf("%s sees the Admin nav item", u)
		}
	}
	if rec := e.do(t, "dora", "GET", "/admin", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/rules" {
		t.Fatalf("/admin: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(b, `<a class="" href="/admin">Admin</a>`) {
		t.Fatalf("no Admin nav item for the director:\n%s", b)
	}
}

func TestAdminRulesPage(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	rec := e.do(t, "dora", "GET", "/admin/rules", nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("%d\n%s", rec.Code, b)
	}
	// exactly one active top-nav item: Admin
	nav := b[strings.Index(b, `<nav class="nav">`):]
	nav = nav[:strings.Index(nav, "</nav>")]
	if strings.Count(nav, `class="on"`) != 1 || !strings.Contains(nav, `<a class="on" href="/admin">Admin</a>`) {
		t.Fatalf("nav:\n%s", nav)
	}
	if strings.Contains(b, ` style="`) || strings.Contains(b, "<style") {
		t.Fatal("inline styles")
	}
	// the tab list keeps a slot for every admin area; only Rules is live
	if n := len(regexp.MustCompile(`class="atab[ "]`).FindAllString(b, -1)); n != 8 {
		t.Fatalf("%d tab slots", n)
	}
	if !strings.Contains(b, `<a class="atab on" href="/admin/rules">Rules</a>`) {
		t.Fatal("Rules tab")
	}
	for _, want := range []string{"<thead>", ">Rule<", ">Kind<", ">Applies to<", ">Level<", ">On<",
		"title-word", "Avoid the word injection", `class="tag kind-pattern"`, `class="tag kind-script"`, `class="tag lvl-error"`, `class="tag lvl-warning"`,
		`href="/admin/rules?edit=title-word"`, `class="btn primary sm w128" href="/admin/rules?new=1"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("rules page lacks %s:\n%s", want, b)
		}
	}
	// the editor for one rule, the bench beside it
	ed := e.do(t, "dora", "GET", "/admin/rules?edit=title-word", nil, nil).Body.String()
	for _, want := range []string{`name="old" value="title-word"`, `name="pattern"`, `value="injection"`, `name="kind" value="pattern" checked`,
		`<option value="title" selected>`, `class="btn primary sm w128">Save</button>`, `class="btn danger sm w112"`, `id="bench"`, `<option value="acme" selected>`, `value="` + fdir + `"`} {
		if !strings.Contains(ed, want) {
			t.Fatalf("editor lacks %s:\n%s", want, ed)
		}
	}
	// a new rule has no Delete, but its place stays
	nw := e.do(t, "dora", "GET", "/admin/rules?new=1", nil, nil).Body.String()
	if strings.Contains(nw, `class="btn danger sm w112"`) || !strings.Contains(nw, `<span class="slot w112"></span>`) {
		t.Fatalf("new rule footer:\n%s", nw)
	}
	for _, c := range []string{"table-cells-no-backticks", "cvss-explained", "not-empty"} {
		if !strings.Contains(nw, `name="check" value="`+c+`"`) {
			t.Fatalf("built-in %s missing", c)
		}
	}
}

func TestAdminRuleInvalidRegex(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	before := e.ruleFile(t, "style.yaml")
	form := url.Values{"old": {"title-word"}, "id": {"title-word"}, "kind": {"pattern"}, "level": {"error"}, "target": {"title"},
		"mode": {"forbid"}, "pattern": {"(["}, "message": {"m"}}
	rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("%d\n%s", rec.Code, b)
	}
	if !regexp.MustCompile(`name="pattern"[^>]*aria-invalid="true"`).MatchString(b) || !strings.Contains(b, "missing closing ]") {
		t.Fatalf("no inline field error:\n%s", b)
	}
	if !strings.Contains(b, `value="(["`) {
		t.Fatal("typed pattern lost")
	}
	if e.ruleFile(t, "style.yaml") != before {
		t.Fatal("file changed")
	}
	// a duplicate id is a field error too
	form = url.Values{"id": {"scripted"}, "kind": {"pattern"}, "level": {"error"}, "target": {"title"}, "mode": {"forbid"}, "pattern": {"x"}}
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil); rec.Code != http.StatusBadRequest || !regexp.MustCompile(`name="id"[^>]*aria-invalid="true"`).MatchString(rec.Body.String()) {
		t.Fatalf("duplicate id %d:\n%s", rec.Code, rec.Body.String())
	}
}

func TestAdminRuleSave(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	form := url.Values{"id": {"no-todo"}, "kind": {"pattern"}, "level": {"warning"}, "target": {"sections"},
		"mode": {"forbid"}, "pattern": {"todo"}, "icase": {"1"}, "message": {"No TODO left"}}
	rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/rules?edit=no-todo" {
		t.Fatalf("%d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if got := e.mainCommit(t); got != "dora|rules: save no-todo" {
		t.Fatalf("commit %q", got)
	}
	if f := e.ruleFile(t, "no-todo.yaml"); !strings.Contains(f, "regex_forbid: (?i)todo") || !strings.Contains(f, "level: warning") {
		t.Fatalf("file:\n%s", f)
	}
	r, ok := e.srv.Rules.Rule("no-todo")
	if !ok || r.Target != "sections" || r.Message != "No TODO left" {
		t.Fatalf("engine: %+v %v", r, ok)
	}
	// case-insensitive patterns come back as the Aa box
	ed := e.do(t, "dora", "GET", "/admin/rules?edit=no-todo", nil, nil).Body.String()
	if !strings.Contains(ed, `value="todo"`) || !strings.Contains(ed, `name="icase" value="1" checked`) {
		t.Fatalf("editor:\n%s", ed)
	}
	// editing a rule in a shared file keeps the others
	form = url.Values{"old": {"title-word"}, "id": {"title-word"}, "kind": {"builtin"}, "check": {"not-empty"}, "level": {"error"},
		"target": {"section:Impact"}, "message": {"Impact needed"}}
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("%d\n%s", rec.Code, rec.Body.String())
	}
	f := e.ruleFile(t, "style.yaml")
	if !strings.Contains(f, "check: not-empty") || strings.Contains(f, "regex_forbid") || !strings.Contains(f, "id: scripted") {
		t.Fatalf("style.yaml:\n%s", f)
	}
	if r, _ := e.srv.Rules.Rule("title-word"); r.Check != "not-empty" || r.Target != "section:Impact" {
		t.Fatalf("engine: %+v", r)
	}
	// delete
	if rec := e.do(t, "dora", "POST", "/admin/rules/delete", url.Values{"id": {"no-todo"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d", rec.Code)
	}
	if _, ok := e.srv.Rules.Rule("no-todo"); ok || e.mainCommit(t) != "dora|rules: delete no-todo" {
		t.Fatal("not deleted")
	}
}

func TestAdminRuleScriptUpload(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	fields := map[string]string{"id": "evidence", "kind": "script", "level": "warning", "target": ""}
	if rec := e.upload(t, "dora", "/admin/rules/save", fields, "", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("no file: %d", rec.Code)
	}
	rec := e.upload(t, "dora", "/admin/rules/save", fields, "evidence.sh", "#!/bin/sh\ncat >/dev/null\necho '[{\"message\":\"no screenshot\"}]'\n")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("%d\n%s", rec.Code, rec.Body.String())
	}
	out, _ := exec.Command("git", "-C", e.dir, "ls-files", "-s", ".yars/rules/evidence.sh", ".yars/rules/evidence.yaml").Output()
	if !strings.Contains(string(out), "100755") || !strings.Contains(string(out), "evidence.yaml") {
		t.Fatalf("committed: %s", out)
	}
	r, ok := e.srv.Rules.Rule("evidence")
	if !ok || r.Script != "evidence.sh" {
		t.Fatalf("engine %+v", r)
	}
	b := e.do(t, "dora", "GET", "/admin/rules/bench?rule=evidence&eng=acme&fid="+fdir, nil, nil).Body.String()
	if !strings.Contains(b, "no screenshot") {
		t.Fatalf("bench:\n%s", b)
	}
	// editing without a new file keeps the script
	if rec := e.upload(t, "dora", "/admin/rules/save", map[string]string{"old": "evidence", "id": "evidence", "kind": "script", "level": "error", "message": "Screenshots"}, "", ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit %d\n%s", rec.Code, rec.Body.String())
	}
	if r, _ := e.srv.Rules.Rule("evidence"); r.Script != "evidence.sh" || r.Level != "error" {
		t.Fatalf("engine %+v", r)
	}
	// a script name that would leave the rules folder is refused
	if rec := e.upload(t, "dora", "/admin/rules/save", map[string]string{"id": "x", "kind": "script", "level": "error"}, "..", "x"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", rec.Code)
	}
}

func TestAdminRuleToggle(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	rec := e.do(t, "dora", "POST", "/admin/rules/toggle", url.Values{"id": {"title-word"}, "on": {"0"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("%d\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(e.ruleFile(t, "style.yaml"), "enabled: false") || e.mainCommit(t) != "dora|rules: disable title-word" {
		t.Fatalf("file/commit:\n%s", e.ruleFile(t, "style.yaml"))
	}
	if r, _ := e.srv.Rules.Rule("title-word"); r.On() {
		t.Fatal("still on")
	}
	b := e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String()
	if !strings.Contains(b, `<tr class="off">`) || !strings.Contains(b, `aria-pressed="false"`) {
		t.Fatalf("row:\n%s", b)
	}
	// the finding's gate no longer sees the disabled rule
	if fb := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(fb, "Avoid the word injection") {
		t.Fatal("disabled rule still runs")
	}
	e.do(t, "dora", "POST", "/admin/rules/toggle", url.Values{"id": {"title-word"}, "on": {"1"}}, nil)
	if r, _ := e.srv.Rules.Rule("title-word"); !r.On() || strings.Contains(e.ruleFile(t, "style.yaml"), "enabled") {
		t.Fatal("not back on")
	}
	if e.mainCommit(t) != "dora|rules: enable title-word" {
		t.Fatal("commit")
	}
}

func TestAdminRuleBench(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	f := e.do(t, "dora", "GET", "/admin/rules/bench/findings?eng=acme", nil, nil).Body.String()
	if !strings.Contains(f, `id="bench-fid"`) || !strings.Contains(f, `value="`+fdir+`"`) {
		t.Fatalf("findings select:\n%s", f)
	}
	rec := e.do(t, "dora", "GET", "/admin/rules/bench?rule=title-word&eng=acme&fid="+fdir, nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `id="bench-out"`) || !strings.Contains(b, "Avoid the word injection") || !strings.Contains(b, "<code>injection</code>") {
		t.Fatalf("%d\n%s", rec.Code, b)
	}
	if !strings.Contains(b, "<thead>") || !strings.Contains(b, `<span class="badge">1</span>`) || strings.Contains(b, ` style="`) {
		t.Fatalf("bench output:\n%s", b)
	}
	// nothing is stored: no check run, no chat
	st, err := e.srv.Store.CheckStatus("acme", fdir)
	if err != nil || st.HasRun {
		t.Fatalf("stored a run: %+v %v", st, err)
	}
	if msgs, _ := e.srv.Store.Chat("acme", fdir); len(msgs) != 0 {
		t.Fatalf("chat %+v", msgs)
	}
	// a rule with no hits shows a black 0
	if b := e.do(t, "dora", "GET", "/admin/rules/bench?rule=scripted&eng=acme&fid="+fdir, nil, nil).Body.String(); !strings.Contains(b, `<span class="badge0">0</span>`) {
		t.Fatalf("no hits:\n%s", b)
	}
	if rec := e.do(t, "dora", "GET", "/admin/rules/bench?rule=nope&eng=acme&fid="+fdir, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown rule %d", rec.Code)
	}
}
