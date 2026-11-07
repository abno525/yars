package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Searching the picker keeps the picked template when it still matches,
// else picks the first match, and the preview always follows the pick.
func TestTemplateSearchKeepsPreviewInStep(t *testing.T) {
	e := setup(t)
	e.addTemplate(t, "missing-hsts", "Missing HSTS header")
	e.addTemplate(t, "verbose-errors", "Verbose error pages")
	hx := map[string]string{"HX-Request": "true"}
	b := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	if !strings.Contains(b, `hx-include="#tpllist input[name=template]:checked"`) {
		t.Fatalf("search does not send the pick:\n%s", b)
	}
	// the pick still matches: kept
	frag := e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=e&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `value="verbose-errors" checked`) || strings.Contains(frag, `value="missing-hsts" checked`) ||
		!strings.Contains(frag, `id="tplpreview" hx-swap-oob="true"`) || !strings.Contains(frag, "Verbose error pages.") {
		t.Fatalf("kept pick:\n%s", frag)
	}
	// the pick is filtered out: the first match is picked and previewed
	frag = e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=hsts&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `value="missing-hsts" checked`) || strings.Contains(frag, "Verbose error pages.") || !strings.Contains(frag, "Missing HSTS header.") {
		t.Fatalf("first match:\n%s", frag)
	}
	// nothing matches: the preview empties
	frag = e.do(t, "alice", "GET", "/e/acme/findings/new/templates?q=zzz&template=verbose-errors", nil, hx).Body.String()
	if !strings.Contains(frag, `id="tplpreview" hx-swap-oob="true"`) || strings.Contains(frag, "Verbose error pages.") || strings.Contains(frag, "<h3>") {
		t.Fatalf("no match:\n%s", frag)
	}
	// Template without a pick is refused, not made blank
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"x"}, "mode": {"template"}, "q": {"zzz"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no pick %d", rec.Code)
	}
	if _, err := e.srv.Store.Finding("acme", "2"); err == nil {
		t.Fatal("finding made without a template")
	}
}

// What the team wrote in the Report tab is in the exported report.
func TestExportIncludesReportTab(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if err := e.srv.Store.UpdateReportSection("acme", "Executive summary", "Two **critical** issues.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil).Body.String()
	if !strings.Contains(b, "Two <strong>critical</strong> issues.") {
		t.Fatalf("preview lacks the executive summary:\n%s", b)
	}
}

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
