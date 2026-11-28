package web

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

func (e *env) mainHead(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", e.dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// packPanel is the Rule pack panel of Admin › Rules.
func packPanel(t *testing.T, body string) string {
	t.Helper()
	return between(body, `<form class="panel sys" id="rulepack"`, `</form>`)
}

// Add starter rules writes the starter set behind one button: every rule
// off, in one commit, into a file of its own. A rule that has a starter
// rule's ID is left as it is; a second press adds nothing and is no commit.
// Every stored check is out of date afterwards, as after any rules change.
func TestStarterRulesButton(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: no-placeholder\n  level: warning\n  target: title\n  regex_forbid: 'mine'\n", nil)
	e.commitRules(t)
	own := e.ruleFile(t, "style.yaml")
	starter := rules.Starter()
	n := len(starter)
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	e.srv.Store.WaitChecks()
	if g, err := e.srv.Store.CheckGate("acme", fdir); err != nil || g != "" {
		t.Fatalf("gate after a check: %q %v", g, err)
	}
	p := packPanel(t, e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String())
	if !strings.Contains(p, `<button class="btn secondary sm w152" formaction="/admin/rules/starter" formnovalidate>Add starter rules</button>`) {
		t.Fatalf("the button:\n%s", p)
	}
	for _, r := range starter { // every starter ID is one the editor takes
		if !store.ValidID(r.ID) {
			t.Errorf("starter rule %q: not an ID the editor takes", r.ID)
		}
	}
	// guarded as every rules write
	if rec := e.do(t, "dora", "GET", "/admin/rules/starter", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/starter", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/admin/rules/starter", nil, nil); rec.Code != http.StatusForbidden {
		t.Errorf("alice: %d", rec.Code)
	}
	at := e.mainHead(t)
	rec := e.do(t, "dora", "POST", "/admin/rules/starter", nil, nil)
	want := fmt.Sprintf("/admin/rules?added=%d&skipped=1", n-1)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Fatalf("press: %d %s (want %s)\n%s", rec.Code, rec.Header().Get("Location"), want, rec.Body.String())
	}
	if got := e.mainCommit(t); got != fmt.Sprintf("dora|rules: add starter rules (added %d, skipped 1)", n-1) {
		t.Fatalf("commit %q", got)
	}
	if out, _ := exec.Command("git", "-C", e.dir, "rev-list", "--count", at+"..HEAD").Output(); strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("%s commits for one press", strings.TrimSpace(string(out)))
	}
	if e.ruleFile(t, "style.yaml") != own {
		t.Fatal("the rule that existed was changed")
	}
	if r := mustRule(t, e, "no-placeholder"); !r.On() || r.RegexForbid != "mine" || r.File != "style.yaml" {
		t.Fatalf("the rule that existed: %+v", r)
	}
	file := e.ruleFile(t, "starter.yaml")
	if strings.Contains(file, "id: no-placeholder") || strings.Count(file, "enabled: false") != n-1 {
		t.Fatalf("starter.yaml:\n%s", file)
	}
	for _, s := range starter {
		if s.ID == "no-placeholder" {
			continue
		}
		if r := mustRule(t, e, s.ID); r.On() || r.File != "starter.yaml" || r.Message != s.Message {
			t.Errorf("%s: %+v", s.ID, r)
		}
	}
	b := e.do(t, "dora", "GET", want, nil, nil).Body.String()
	p = packPanel(t, b)
	if !strings.Contains(p, fmt.Sprintf(`<span class="pstate" title="added %d · skipped 1">added %d · skipped 1</span>`, n-1, n-1)) {
		t.Fatalf("the status slot:\n%s", p)
	}
	if !strings.Contains(p, ` formnovalidate disabled>Add starter rules</button>`) {
		t.Fatalf("the button after the press:\n%s", p)
	}
	if strings.Contains(b, `class="checkerr`) {
		t.Fatalf("a starter rule left a problem line:\n%s", b)
	}
	// the documented cost: the rules changed, so the stored check is out of date
	if g, err := e.srv.Store.CheckGate("acme", fdir); err != nil || g != store.GateRules {
		t.Fatalf("gate after the press: %q %v", g, err)
	}
	// a second press: nothing to add, no commit
	at = e.mainHead(t)
	rec = e.do(t, "dora", "POST", "/admin/rules/starter", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/admin/rules?added=0&skipped=%d", n) || e.mainHead(t) != at {
		t.Fatalf("a second press: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// A press that cannot be written is refused with words, not an internal
// error: here the starter's file exists and is no list of rules.
func TestStarterRulesRefusedWithWords(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: own\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	e.commitRules(t)
	if err := os.WriteFile(filepath.Join(e.dir, ".yars", "rules", "starter.yaml"), []byte("note: not a list\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.commitRules(t)
	at := e.mainHead(t)
	rec := e.do(t, "dora", "POST", "/admin/rules/starter", nil, nil)
	p := packPanel(t, rec.Body.String())
	if rec.Code != http.StatusBadRequest || !strings.Contains(p, `<span class="pstate error"`) || !strings.Contains(p, "not a list of rules") {
		t.Fatalf("%d\n%s", rec.Code, rec.Body.String())
	}
	if e.mainHead(t) != at || e.ruleFile(t, "starter.yaml") != "note: not a list\n" {
		t.Fatal("a refused press changed the folder")
	}
}

// Export downloads every loaded rule as one YAML list, the ones that are off
// too. Import on another server adds them, all off whatever the pack says,
// and never touches a rule that exists. A script rule is taken only when
// its script is in the rules folder already.
func TestRulePackExportImport(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	e.commitRules(t)
	if rec := e.do(t, "dora", "POST", "/admin/rules/toggle", map[string][]string{"id": {"title-word"}, "on": {"0"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("toggle %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/admin/rules/export", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("alice exports: %d", rec.Code)
	}
	rec := e.do(t, "dora", "GET", "/admin/rules/export", nil, nil)
	pack := rec.Body.String()
	if rec.Code != 200 || rec.Header().Get("Content-Disposition") != `attachment; filename="yars-rules.yaml"` || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/yaml") {
		t.Fatalf("export: %d %v", rec.Code, rec.Header())
	}
	for _, want := range []string{"- id: title-word\n", "enabled: false\n", "- id: scripted\n", "script: check.sh\n"} {
		if !strings.Contains(pack, want) {
			t.Fatalf("the pack lacks %q:\n%s", want, pack)
		}
	}
	p := packPanel(t, e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String())
	for _, want := range []string{` method="post" action="/admin/rules/import" enctype="multipart/form-data"`, `<input class="restorefile" type="file" name="pack"`,
		`<button class="btn primary sm w128">Import</button>`, `<a class="btn ghost sm w128" href="/admin/rules/export" download>Export</a>`, `<span class="pstate" title=""></span>`} {
		if !strings.Contains(p, want) {
			t.Fatalf("the panel lacks %s:\n%s", want, p)
		}
	}

	// another server
	o := setupSerial(t)
	o.rules(t, "- id: own\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	o.commitRules(t)
	at := o.mainHead(t)
	// the pack's script rule names a script this server does not have
	rec = o.uploadFile(t, "dora", "/admin/rules/import", "pack", "zqpackname9.yaml", []byte(pack))
	if b := packPanel(t, rec.Body.String()); rec.Code != http.StatusBadRequest || !strings.Contains(b, "rule scripted: the script check.sh is not in the rules folder") {
		t.Fatalf("a pack with a script the server lacks: %d\n%s", rec.Code, rec.Body.String())
	}
	if o.mainHead(t) != at {
		t.Fatal("a refused pack was committed")
	}
	if err := os.WriteFile(filepath.Join(o.dir, ".yars", "rules", "check.sh"), []byte("cat >/dev/null; echo '[]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec = o.uploadFile(t, "dora", "/admin/rules/import", "pack", "zqpackname9.yaml", []byte(pack))
	n := len(strings.Split(strings.TrimSpace(pack), "\n- id: "))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/admin/rules?added=%d&skipped=0", n) {
		t.Fatalf("import: %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if got := o.mainCommit(t); got != fmt.Sprintf("dora|rules: import a pack (added %d, skipped 0)", n) {
		t.Fatalf("commit %q", got)
	}
	file := o.ruleFile(t, "imported.yaml")
	if strings.Count(file, "enabled: false") != n {
		t.Fatalf("imported.yaml:\n%s", file)
	}
	for _, id := range []string{"title-word", "scripted"} {
		was, r := mustRule(t, e, id), mustRule(t, o, id)
		if r.On() || r.File != "imported.yaml" || r.RegexForbid != was.RegexForbid || r.Script != was.Script || r.Target != was.Target || r.Level != was.Level || r.Message != was.Message {
			t.Errorf("%s: %+v, exported as %+v", id, r, was)
		}
	}
	if strings.Contains(o.log.Text(), "zqpackname9") {
		t.Fatalf("the upload's file name is in the log:\n%s", o.log.Text())
	}
	if _, err := os.Stat(filepath.Join(o.dir, ".yars", "rules", "zqpackname9.yaml")); err == nil {
		t.Fatal("the upload's file name was used")
	}
	// again: everything exists, no commit
	at = o.mainHead(t)
	rec = o.uploadFile(t, "dora", "/admin/rules/import", "pack", "p.yaml", []byte(pack))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fmt.Sprintf("/admin/rules?added=0&skipped=%d", n) || o.mainHead(t) != at {
		t.Fatalf("a second import: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// an ID that exists is skipped and left as it is, the rest is added
	own := o.ruleFile(t, "style.yaml")
	rec = o.uploadFile(t, "dora", "/admin/rules/import", "pack", "p.yaml", []byte("- id: own\n  target: text\n  regex_forbid: 'other'\n- id: fresh\n  level: warning\n  target: title\n  regex_forbid: 'q'\n  enabled: true\n"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/rules?added=1&skipped=1" {
		t.Fatalf("a pack with an ID that exists: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if o.ruleFile(t, "style.yaml") != own || mustRule(t, o, "own").RegexForbid != "zzz" || mustRule(t, o, "fresh").On() {
		t.Fatalf("own: %+v, fresh: %+v", mustRule(t, o, "own"), mustRule(t, o, "fresh"))
	}
}

// A pack is other people's file: one problem refuses all of it, with words,
// and nothing is written.
func TestRulePackImportRefused(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: own\n  target: title\n  regex_forbid: 'zzz'\n", map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	e.commitRules(t)
	at := e.mainHead(t)
	good := "- id: fine\n  target: title\n  regex_forbid: 'q'\n"
	var many strings.Builder
	for i := range 201 {
		fmt.Fprintf(&many, "- id: r%d\n  target: title\n  regex_forbid: 'q'\n", i)
	}
	for name, c := range map[string]struct{ pack, want string }{
		"an ID the editor refuses": {good + "- id: 'a b'\n  regex_forbid: x\n", "rule a b: the ID takes letters, digits, . _ -"},
		"an ID that is a path":     {"- id: '../x'\n  regex_forbid: x\n", "the ID takes letters, digits, . _ -"},
		"an unknown key":           {good + "- id: a\n  regex_forbid: x\n  levle: error\n", "unknown field(s) levle"},
		"a bad pattern":            {good + "- id: a\n  regex_forbid: '(['\n", "missing closing ]"},
		"two kinds":                {good + "- id: a\n  regex_forbid: x\n  check: not-empty\n", "needs exactly one of"},
		"an ID twice":              {good + "- id: fine\n  regex_forbid: y\n", "duplicate rule id fine"},
		"a script in a folder":     {good + "- id: s\n  script: lib/x.sh\n", "rule s: the script name takes letters, digits, . _ -"},
		"a script outside":         {good + "- id: s\n  script: ../check.sh\n", "rule s: the script name takes letters, digits, . _ -"},
		"a script that is a rule":  {good + "- id: s\n  script: style.yaml\n", "rule s: the script name"},
		"a script not there":       {good + "- id: s\n  script: nope.sh\n", "rule s: the script nope.sh is not in the rules folder"},
		"no list":                  {"note: x\n", "not a list of rules"},
		"too many rules":           {many.String(), "at most 200 rules"},
		"too large":                {good + "# " + strings.Repeat("x", 300<<10) + "\n", "the file is larger than 256 KiB"},
	} {
		rec := e.uploadFile(t, "dora", "/admin/rules/import", "pack", "p.yaml", []byte(c.pack))
		body := rec.Body.String()
		if rec.Code != http.StatusBadRequest || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d, want %q\n%s", name, rec.Code, c.want, body)
			continue
		}
		if p := packPanel(t, body); !strings.Contains(p, `<span class="pstate error"`) || !strings.Contains(p, c.want) {
			t.Errorf("%s: the words are not in the panel's slot:\n%s", name, p)
		}
	}
	// a script rule whose script is there is taken, off
	rec := e.uploadFile(t, "dora", "/admin/rules/import", "pack", "p.yaml", []byte("- id: s\n  script: check.sh\n"))
	if rec.Code != http.StatusSeeOther || mustRule(t, e, "s").On() {
		t.Fatalf("a script rule with its script in the folder: %d\n%s", rec.Code, rec.Body.String())
	}
	if out, _ := exec.Command("git", "-C", e.dir, "rev-list", "--count", at+"..HEAD").Output(); strings.TrimSpace(string(out)) != "1" {
		t.Fatalf("%s commits: a refused pack was written", strings.TrimSpace(string(out)))
	}
	if _, ok := e.srv.Rules.Rule("fine"); ok {
		t.Fatal("a rule of a refused pack was added")
	}
	// no file, a link, another site, no admin
	if rec := e.do(t, "dora", "POST", "/admin/rules/import", nil, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no file: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "GET", "/admin/rules/import", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/import", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("a cross-site POST: %d", rec.Code)
	}
	if rec := e.uploadFile(t, "alice", "/admin/rules/import", "pack", "p.yaml", []byte(good)); rec.Code != http.StatusForbidden {
		t.Errorf("alice: %d", rec.Code)
	}
}
