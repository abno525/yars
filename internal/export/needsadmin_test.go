package export

import "testing"

// Where a service destination sends the keys and the findings is an admin's
// to set: its address, key variables, project or space, parent page and
// issue type. The rest is a director's: a script destination and its script,
// a pandoc destination with its template and arguments (--variable too).
func TestNeedsAdmin(t *testing.T) {
	jira := func(mod func(*Exporter)) Exporter {
		e := Exporter{ID: "jira", Name: "Jira", Type: "jira", Statuses: []string{"complete"},
			Jira: &JiraConf{BaseURL: "https://jira.firm.example", Project: "PEN", IssueType: "Bug", UserEnv: "JIRA_USER", TokenEnv: "JIRA_TOKEN"}}
		if mod != nil {
			mod(&e)
		}
		return e
	}
	conf := func(mod func(*Exporter)) Exporter {
		e := Exporter{ID: "wiki", Name: "Wiki", Type: "confluence",
			Confluence: &ConfluenceConf{BaseURL: "https://wiki.firm.example", Space: "PEN", ParentID: "100", UserEnv: "CONFLUENCE_USER", TokenEnv: "CONFLUENCE_TOKEN"}}
		if mod != nil {
			mod(&e)
		}
		return e
	}
	script := Exporter{ID: "csv", Name: "CSV", Type: "script", Script: "csv.py", Extension: "csv"}
	pandoc := Exporter{ID: "word", Name: "Word", Type: "pandoc", Format: "docx"}
	styled := Exporter{ID: "word", Name: "Word", Type: "pandoc", Format: "docx", Template: "firm.docx"}
	vars := Exporter{ID: "pdf", Name: "PDF", Type: "pandoc", Format: "pdf", Args: []string{"--toc", "--variable=mainfont:Arial"}}
	plainPDF := Exporter{ID: "pdf", Name: "PDF", Type: "pandoc", Format: "pdf", Args: []string{"--toc"}}
	file := Exporter{ID: "html", Name: "HTML", Type: "confluence"}
	no := false
	p := func(e Exporter) *Exporter { return &e }
	for _, c := range []struct {
		name string
		prev *Exporter
		ex   Exporter
		want bool
	}{
		// an admin's
		{"a new service", nil, jira(nil), true},
		{"jira address", p(jira(nil)), jira(func(e *Exporter) { e.Jira.BaseURL = "https://attacker.example" }), true},
		{"jira user env", p(jira(nil)), jira(func(e *Exporter) { e.Jira.UserEnv = "JIRA_OTHER" }), true},
		{"jira token env", p(jira(nil)), jira(func(e *Exporter) { e.Jira.TokenEnv = "JIRA_OTHER" }), true},
		{"jira project", p(jira(nil)), jira(func(e *Exporter) { e.Jira.Project = "PUBLIC" }), true},
		{"jira issue type", p(jira(nil)), jira(func(e *Exporter) { e.Jira.IssueType = "Epic" }), true},
		{"confluence address", p(conf(nil)), conf(func(e *Exporter) { e.Confluence.BaseURL = "https://attacker.example" }), true},
		{"confluence space", p(conf(nil)), conf(func(e *Exporter) { e.Confluence.Space = "PUBLIC" }), true},
		{"confluence parent page", p(conf(nil)), conf(func(e *Exporter) { e.Confluence.ParentID = "1" }), true},
		{"confluence parent page removed", p(conf(nil)), conf(func(e *Exporter) { e.Confluence.ParentID = "" }), true},
		{"pandoc turned into a service", p(pandoc), jira(nil), true},
		{"a script turned into a service", p(script), jira(nil), true},
		{"a file confluence turned into a push", p(file), conf(nil), true},
		{"jira turned into confluence at the same address", p(jira(nil)), conf(func(e *Exporter) { e.Confluence.BaseURL = "https://jira.firm.example" }), true},
		// a director's: scripts, templates and pandoc arguments
		{"a new script", nil, script, false},
		{"another script", p(script), Exporter{ID: "csv", Name: "CSV", Type: "script", Script: "other.sh", Extension: "csv"}, false},
		{"pandoc turned into a script", p(pandoc), script, false},
		{"script name, extension and mark", p(script), Exporter{ID: "csv", Name: "Summary", Type: "script", Script: "csv.py", Extension: "tsv", MarkReported: &no}, false},
		{"a new pandoc", nil, pandoc, false},
		{"a new pandoc with a template", nil, styled, false},
		{"a template added", p(pandoc), styled, false},
		{"another template", p(styled), Exporter{ID: "word", Name: "Word", Type: "pandoc", Format: "docx", Template: "other.docx"}, false},
		{"a template removed", p(styled), pandoc, false},
		{"a new pandoc with a variable", nil, vars, false},
		{"a variable added", p(plainPDF), vars, false},
		{"another variable", p(vars), Exporter{ID: "pdf", Name: "PDF", Type: "pandoc", Format: "pdf", Args: []string{"--toc", "--variable=mainfont:Georgia"}}, false},
		{"a variable added beside a template", p(styled), Exporter{ID: "word", Name: "Word", Type: "pandoc", Format: "docx", Template: "firm.docx", Args: []string{"--variable=k:v"}}, false},
		{"a variable removed", p(vars), plainPDF, false},
		{"pandoc format and args", p(pandoc), Exporter{ID: "word", Name: "Word", Type: "pandoc", Format: "odt", Args: []string{"--toc", "--metadata=lang:de"}}, false},
		{"a script turned into pandoc", p(script), pandoc, false},
		// a director's: the rest of a service
		{"a new confluence file", nil, file, false},
		{"jira name, statuses and mark", p(jira(nil)), jira(func(e *Exporter) {
			e.Name, e.Statuses, e.MarkReported = "Jira PEN", []string{"complete", "reported"}, &no
		}), false},
		{"jira issue type left out where it was Bug", p(jira(nil)), jira(func(e *Exporter) { e.Jira.IssueType = "" }), false},
		{"jira address with a trailing slash", p(jira(nil)), jira(func(e *Exporter) { e.Jira.BaseURL += "/" }), false},
		{"confluence name and mark", p(conf(nil)), conf(func(e *Exporter) { e.Name, e.MarkReported = "Client wiki", &no }), false},
		{"a service turned into a file", p(jira(nil)), pandoc, false},
		{"a service turned into a script", p(jira(nil)), script, false},
	} {
		if got := NeedsAdmin(c.prev, c.ex); got != c.want {
			t.Errorf("%s: NeedsAdmin %v, want %v", c.name, got, c.want)
		}
	}
}
