package web

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

const emptyScript = "cat >/dev/null; echo '[]'\n"

// A rule renamed on Admin › Rules keeps its dismissals: they move to the new
// ID, the finding still shows the result dismissed, and the audit log names
// both IDs and the count.
func TestAdminRuleRenameKeepsDismissals(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": emptyScript})
	form := url.Values{"rule": {"title-word"}, "quote": {"injection"}, "reason": {"Injection is the client's term"}}
	if rec := e.do(t, "bob", "POST", fpath+"/checks/dismiss", form, nil); rec.Code != 200 {
		t.Fatalf("dismiss %d: %s", rec.Code, rec.Body.String())
	}
	// a dismissal an earlier rule of the new name left for the same place
	// stays as it is; the moved one does not replace it
	save := url.Values{"old": {"title-word"}, "id": {"title-term"}, "kind": {"pattern"}, "level": {"error"}, "target": {"title"},
		"mode": {"forbid"}, "pattern": {"injection"}, "message": {"Avoid the word injection"}}
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", save, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d\n%s", rec.Code, rec.Body.String())
	}
	ds, err := e.srv.Store.Dismissals("acme", "F-001")
	if err != nil {
		t.Fatal(err)
	}
	qh := db.ViolationHash("title", "injection")
	moved, ok := ds[db.DismissKey("title-term", qh)]
	if _, old := ds[db.DismissKey("title-word", qh)]; old || !ok || len(ds) != 1 || moved.By != "bob" || moved.Reason != "Injection is the client's term" {
		t.Fatalf("dismissals after the rename: %+v", ds)
	}
	// the page: the error is still dismissed (the gate's two are left)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if wf := wfBar(t, b); !strings.Contains(wf, ">2 errors to fix<") {
		t.Fatalf("the renamed rule's error counts again:\n%s", wf)
	}
	if p := checksPanel(t, b); !strings.Contains(p, `<details class="dismissed"`) {
		t.Fatalf("not shown dismissed:\n%s", p)
	}
	l, _ := e.srv.Store.DB().AuditLog(5)
	found := false
	for _, a := range l {
		if a.Action == "rules.rename" {
			found = a.Actor == "dora" && a.Target == "title-term" && a.Detail == "title-word → title-term · 1 dismissal moved"
		}
	}
	if !found {
		t.Fatalf("audit: %+v", l)
	}
	// a save that keeps the ID moves nothing and writes no such row
	save.Set("old", "title-term")
	save.Set("message", "Another message")
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", save, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("second save %d", rec.Code)
	}
	n := 0
	l, _ = e.srv.Store.DB().AuditLog(20)
	for _, a := range l {
		if a.Action == "rules.rename" {
			n++
		}
	}
	if ds, _ := e.srv.Store.Dismissals("acme", "F-001"); len(ds) != 1 || n != 1 {
		t.Fatalf("after a plain save: %+v, %d rename rows", ds, n)
	}
}

// rulesHas reports whether .yars/rules has the file name.
func (e *env) rulesHas(name string) bool {
	_, err := os.Stat(filepath.Join(e.dir, ".yars", "rules", name))
	return err == nil
}

// lastFiles are the paths the newest commit of the main repo changed.
func (e *env) lastFiles(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", e.dir, "show", "--name-only", "--format=", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// commitRules commits .yars/rules as it is, as a push of the rules would.
func (e *env) commitRules(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{{"add", ".yars/rules"}, {"-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "rules"}} {
		if out, err := exec.Command("git", append([]string{"-C", e.dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// Deleting a script rule removes its script with it, in the same commit;
// a script another rule still names stays.
func TestAdminRuleDeleteRemovesScript(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules+"- id: twin\n  script: shared.sh\n- id: twin2\n  script: shared.sh\n  enabled: false\n",
		map[string]string{"check.sh": emptyScript, "shared.sh": emptyScript, "helper.sh": emptyScript})
	e.commitRules(t)
	if rec := e.do(t, "dora", "POST", "/admin/rules/delete", url.Values{"id": {"scripted"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d\n%s", rec.Code, rec.Body.String())
	}
	if e.rulesHas("check.sh") {
		t.Fatal("check.sh is still there")
	}
	if files := e.lastFiles(t); !strings.Contains(files, ".yars/rules/check.sh") || !strings.Contains(files, ".yars/rules/style.yaml") {
		t.Fatalf("the commit holds:\n%s", files)
	}
	// a script a second rule names (a disabled one too) stays
	if rec := e.do(t, "dora", "POST", "/admin/rules/delete", url.Values{"id": {"twin"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete twin %d", rec.Code)
	}
	if !e.rulesHas("shared.sh") {
		t.Fatal("shared.sh went with the first of its two rules")
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/delete", url.Values{"id": {"twin2"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete twin2 %d", rec.Code)
	}
	// a file no rule named is never touched
	if e.rulesHas("shared.sh") || !e.rulesHas("helper.sh") {
		t.Fatalf("shared.sh %v, helper.sh %v", e.rulesHas("shared.sh"), e.rulesHas("helper.sh"))
	}
}

// A rule file written by hand can name a path outside the rules folder, or a
// rule file: deleting such a rule removes the rule and no file.
func TestAdminRuleDeleteLeavesOtherFiles(t *testing.T) {
	e := setupSerial(t)
	conf := filepath.Join(e.dir, ".yars", "config.yaml")
	os.MkdirAll(filepath.Dir(conf), 0o700)
	before, err := os.ReadFile(conf)
	if err != nil {
		before = []byte("workflow: standard\n")
		if err := os.WriteFile(conf, before, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.rules(t, styleRules+"- id: up\n  script: ../config.yaml\n- id: self\n  script: other.yaml\n- id: deep\n  script: lib/../../config.yaml\n- id: abs\n  script: "+conf+"\n",
		map[string]string{"check.sh": emptyScript})
	os.WriteFile(filepath.Join(e.dir, ".yars", "rules", "other.yaml"), []byte("[]\n"), 0o644)
	e.commitRules(t)
	for _, id := range []string{"up", "self", "deep", "abs"} {
		if rec := e.do(t, "dora", "POST", "/admin/rules/delete", url.Values{"id": {id}}, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("delete %s: %d\n%s", id, rec.Code, rec.Body.String())
		}
		if _, ok := e.srv.Rules.Rule(id); ok {
			t.Fatalf("%s is still a rule", id)
		}
	}
	if after, err := os.ReadFile(conf); err != nil || string(after) != string(before) {
		t.Fatalf("config.yaml: %v\n%s", err, after)
	}
	if !e.rulesHas("other.yaml") || !e.rulesHas("check.sh") {
		t.Fatal("a file the rule did not own is gone")
	}
}

// A script rule saved with a script of another name, or as another kind,
// leaves no script behind.
func TestAdminRuleSaveRemovesOldScript(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": emptyScript})
	e.commitRules(t)
	fields := map[string]string{"old": "scripted", "id": "scripted", "kind": "script", "level": "warning", "target": ""}
	if rec := e.upload(t, "dora", "/admin/rules/save", fields, "check2.sh", "#!/bin/sh\n"+emptyScript); rec.Code != http.StatusSeeOther {
		t.Fatalf("upload %d\n%s", rec.Code, rec.Body.String())
	}
	if e.rulesHas("check.sh") || !e.rulesHas("check2.sh") {
		t.Fatalf("after a new upload: check.sh %v, check2.sh %v", e.rulesHas("check.sh"), e.rulesHas("check2.sh"))
	}
	// the same name uploaded again replaces the file and removes nothing
	if rec := e.upload(t, "dora", "/admin/rules/save", fields, "check2.sh", "#!/bin/sh\n"+emptyScript+"# v2\n"); rec.Code != http.StatusSeeOther || !e.rulesHas("check2.sh") {
		t.Fatalf("same name: %d, there %v", rec.Code, e.rulesHas("check2.sh"))
	}
	form := url.Values{"old": {"scripted"}, "id": {"scripted"}, "kind": {"pattern"}, "level": {"warning"}, "target": {"title"}, "mode": {"forbid"}, "pattern": {"x"}}
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("to pattern %d\n%s", rec.Code, rec.Body.String())
	}
	if e.rulesHas("check2.sh") {
		t.Fatal("check2.sh stays after the rule became a pattern")
	}
}
