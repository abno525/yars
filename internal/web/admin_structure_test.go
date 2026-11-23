package web

import (
	"net/http"
	"strings"
	"testing"
)

// Renaming a report section in Admin › Structure keeps the text written
// under the old name.
func TestStructureRenameKeepsReportText(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateReportSection("acme", "Scope", "The web portal.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	v := e.structForm()
	v["report"] = []string{"Methodology", "Executive summary", "Scope and approach"} // moved and renamed
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	b := e.do(t, "alice", "GET", "/e/acme/report", nil, nil).Body.String()
	if !strings.Contains(b, "Scope and approach") || !strings.Contains(b, "The web portal.") {
		t.Fatalf("report tab:\n%s", b)
	}
}

// Saving Admin › Structure reaches the style rules engine too.
func TestStructureSaveUpdatesRules(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: biz\n  target: section:Business context\n  regex_forbid: 'x'\n", nil)
	if len(e.srv.Rules.Rules().Problems) != 1 {
		t.Fatalf("problems before: %+v", e.srv.Rules.Rules().Problems)
	}
	v := e.structForm()
	v["section"] = append(v["section"], "Business context")
	v.Set("op", "save")
	if rec := e.do(t, "dora", "POST", "/admin/structure", v, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if ps := e.srv.Rules.Rules().Problems; len(ps) != 0 {
		var msgs []string
		for _, p := range ps {
			msgs = append(msgs, p.Message)
		}
		t.Fatalf("problems after save: %s", strings.Join(msgs, "; "))
	}
}
