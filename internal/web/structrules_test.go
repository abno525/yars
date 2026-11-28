package web

import (
	"context"
	"maps"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
)

// A section or details row renamed on Admin › Structure is renamed in the
// rule targets too, in the commit that writes config.yaml: rules that are on
// and off, with the file's comments and its other rules kept. Before, a
// not-empty rule on the old name reported an empty part on every finding
// and blocked Submit (pre1 7.11).
func TestStructureRenameMovesRuleTargets(t *testing.T) {
	e := setupSerial(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Data loss.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	row := v["detail"][0]
	e.rules(t, "# house rules\n- id: impact-filled\n  target: section:Impact\n  check: not-empty\n  message: Impact is empty\n"+
		"# not yet\n- id: impact-off\n  target: \"section:Impact\"\n  regex_forbid: 'TODO'\n  enabled: false\n"+
		"- id: row-filled\n  level: warning\n  target: details:"+row+"\n  regex_forbid: 'zzz'\n"+
		"- id: other\n  target: section:Description\n  regex_forbid: 'zzz'\n", nil)
	e.commitRules(t)
	before := e.ruleFile(t, "style.yaml")
	v["section"] = replaced(v["section"], "Impact", "Business impact")
	v["detail"] = replaced(v["detail"], row, row+" two")
	v.Set("op", "save")
	// a page read before another save: nothing is written, no rule file either
	stale := maps.Clone(v)
	stale.Set("base", "0000000000000000")
	if rec := e.do(t, "dora", "POST", "/admin/structure", stale, nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale save %d", rec.Code)
	}
	if e.ruleFile(t, "style.yaml") != before {
		t.Fatal("a refused save changed the rule file")
	}
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	f := e.ruleFile(t, "style.yaml")
	if strings.Contains(f, "section:Impact") || strings.Count(f, "section:Business impact") != 2 || !strings.Contains(f, "target: details:"+row+" two\n") {
		t.Fatalf("targets:\n%s", f)
	}
	for _, kept := range []string{"# house rules", "# not yet", "enabled: false", "target: section:Description", "message: Impact is empty", "regex_forbid: 'TODO'"} {
		if !strings.Contains(f, kept) {
			t.Fatalf("the file lost %q:\n%s", kept, f)
		}
	}
	// one commit holds config.yaml and the rule file
	commitOf := func(path string) string {
		out, err := exec.Command("git", "-C", e.dir, "log", "-1", "--format=%H %s", "--", path).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	if c := commitOf(".yars/rules/style.yaml"); c != commitOf(".yars/config.yaml") || !strings.HasSuffix(c, " config: report structure") {
		t.Fatalf("the rule file's commit %q, config.yaml's %q", c, commitOf(".yars/config.yaml"))
	}
	// the rules as loaded: the renamed section has text, so nothing is reported
	for _, id := range []string{"impact-filled", "impact-off"} {
		if r := mustRule(t, e, id); r.Target != "section:Business impact" {
			t.Fatalf("%s: target %q", id, r.Target)
		}
	}
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range e.srv.Rules.Lint(context.Background(), ref.F, rules.Fast) {
		if x.Rule == "impact-filled" || x.Target == "rules" {
			t.Fatalf("after the rename: %+v", x)
		}
	}
}
