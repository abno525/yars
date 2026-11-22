package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"yars/internal/config"
	"yars/internal/db"
)

func retentionForm(audit, runs, sessions string) url.Values {
	return url.Values{"audit_days": {audit}, "check_run_days": {runs}, "session_days": {sessions}}
}

// D24: the Retention panel saves the three settings, audited; a value out
// of 0–3650 answers 400 and stores nothing.
func TestRetentionFormSaves(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	p := between(b, `<form class="panel sys" id="retention"`, "</form>")
	for _, want := range []string{`action="/admin/system/retention"`, `<h2>Retention</h2>`, `name="audit_days" min="0" max="3650" value="0"`,
		`name="check_run_days" min="0" max="3650" value="90"`, `name="session_days" min="0" max="3650" value="14"`, `class="btn save sm w96">Save</button>`,
		`<span class="sl">Last prune</span><span class="sv" title="—">—</span>`} {
		if !strings.Contains(p, want) {
			t.Fatalf("panel lacks %s:\n%s", want, p)
		}
	}
	if i, j := strings.Index(b, `id="backup"`), strings.Index(b, `id="retention"`); i < 0 || j < i {
		t.Fatal("Retention is not after Backup")
	}
	if rec := e.do(t, "dora", "POST", "/admin/system/retention", retentionForm("365", "30", "7"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	if r, _ := d.Retention(); r != (db.Retention{AuditDays: 365, CheckRunDays: 30, SessionDays: 7}) {
		t.Fatalf("stored %+v", r)
	}
	if l, _ := d.AuditLog(1); len(l) != 1 || l[0].Action != "setting.retention" || l[0].Actor != "dora" {
		t.Fatalf("audit %+v", l)
	}
	for bad, says := range map[*url.Values]string{
		{"audit_days": {"-1"}, "check_run_days": {"30"}, "session_days": {"7"}}:    "Audit log: 0 to 3650 days",
		{"audit_days": {"365"}, "check_run_days": {"4000"}, "session_days": {"7"}}: "Check runs: 0 to 3650 days",
		{"audit_days": {"365"}, "check_run_days": {"30"}, "session_days": {"x"}}:   "Sessions: 0 to 3650 days",
	} {
		rec := e.do(t, "dora", "POST", "/admin/system/retention", *bad, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(between(rec.Body.String(), `id="retention"`, "</form>"), `title="`+says+`">`+says+`</span>`) {
			t.Fatalf("bad %v: %d\n%s", *bad, rec.Code, between(rec.Body.String(), `id="retention"`, "</form>"))
		}
	}
	if r, _ := d.Retention(); r != (db.Retention{AuditDays: 365, CheckRunDays: 30, SessionDays: 7}) {
		t.Fatalf("a refused form stored %+v", r)
	}
	// the refused field takes the focus, so the browser shows the panel
	rec := e.do(t, "dora", "POST", "/admin/system/retention", retentionForm("365", "4000", "7"), nil)
	if !strings.Contains(rec.Body.String(), `name="check_run_days" min="0" max="3650" value="30" autofocus>`) {
		t.Fatalf("the refused field is not focused:\n%s", between(rec.Body.String(), `id="retention"`, "</form>"))
	}
	if rec := e.do(t, "alice", "POST", "/admin/system/retention", retentionForm("1", "1", "1"), nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin %d", rec.Code)
	}
}

// D24: a prune that deleted something is audited by yars, and the panel
// shows the last one.
func TestRetentionPruneAudited(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	d.AddUser(config.User{Username: "old", Role: "pentester"})
	d.CreateSession("stale", "old")
	d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = 'stale'", time.Now().AddDate(0, 0, -30).UTC().Format(time.RFC3339))
	if _, err := e.srv.prune(d); err != nil {
		t.Fatal(err)
	}
	l, _, _ := d.AuditQuery(db.AuditFilter{Action: "retention.prune", Limit: 1})
	if len(l) != 1 || l[0].Actor != "yars" || l[0].Detail != "audit 0 · check runs 0 · sessions 1" {
		t.Fatalf("prune audit %+v", l)
	}
	p := between(e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(), `id="retention"`, "</form>")
	if !strings.Contains(p, "audit 0 · check runs 0 · sessions 1") {
		t.Fatalf("panel after a prune:\n%s", p)
	}
	// nothing to delete: nothing audited
	e.srv.prune(d)
	if l, _, _ := d.AuditQuery(db.AuditFilter{Action: "retention.prune", Limit: 5}); len(l) != 1 {
		t.Fatalf("an empty prune was audited: %+v", l)
	}
	// stored rule results past the check runs' days count too (Q1 review)
	d.PutRuleResult("k", "ai", "{}")
	d.Exec("UPDATE rule_cache SET created = ?", time.Now().AddDate(0, 0, -91).Unix())
	if _, err := e.srv.prune(d); err != nil {
		t.Fatal(err)
	}
	if l, _, _ := d.AuditQuery(db.AuditFilter{Action: "retention.prune", Limit: 1}); len(l) != 1 || l[0].Detail != "audit 0 · check runs 0 · sessions 0 · rule results 1" {
		t.Fatalf("prune audit %+v", l)
	}
}
