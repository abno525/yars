package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

const noneRule = "- id: none\n  target: title\n  regex_forbid: 'zzz'\n"

// R1: with Require Check on, the finding page keeps Sign off and Approve
// in their slots, disabled, with "Run Check first" as the state; a check
// run on the content enables them, an edit disables them again (the bar
// as it refreshes itself too).
func TestRequireCheckBar(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	btn := slotButton(t, b, "clear")
	if !strings.Contains(btn, " disabled") || !strings.Contains(btn, `class="btn w112 primary"`) || !strings.Contains(btn, `aria-describedby="wf-state"`) {
		t.Fatalf("sign off without a run: %s", btn)
	}
	if !strings.Contains(wfBar(t, b), `<span class="wfstate" id="wf-state" title="Run Check first">Run Check first</span>`) {
		t.Fatalf("state:\n%s", wfBar(t, b))
	}
	e.checked(t, "acme", fdir)
	bar := e.do(t, "bob", "GET", fpath+"/workflow", nil, nil).Body.String()
	if strings.Contains(slotButton(t, bar, "clear"), " disabled") || strings.Contains(bar, "Run Check first") {
		t.Fatalf("after a run:\n%s", bar)
	}
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "More.", "", wBob); err != nil {
		t.Fatal(err)
	}
	bar = e.do(t, "bob", "GET", fpath+"/workflow", nil, nil).Body.String()
	if !strings.Contains(slotButton(t, bar, "clear"), " disabled") || !strings.Contains(bar, ">Run Check first<") {
		t.Fatalf("after an edit:\n%s", bar)
	}
	// the store refuses the same way when posted anyway
	if b := e.denied(t, "bob", fpath+"/action/clear", url.Values{}); !strings.Contains(b, store.GateStale) {
		t.Fatal("posted sign off: no refusal on the page")
	}
}

// A check run whose AI rule could not run, with a provider set up, holds
// nothing: Sign off is enabled, the state is not "Run Check first", the
// posted sign-off goes through, and the bar still says "AI checks failed".
func TestRequireCheckBarOpenWhenAIFailed(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	e.srv.Rules.Runner.(*rules.Runner).Stored = func() (config.AIConfig, string) {
		return config.AIConfig{Provider: "openai", BaseURL: "http://127.0.0.1:1", Model: "m"}, "key"
	}
	if !e.srv.Rules.AIConfigured() {
		t.Fatal("no AI provider set up")
	}
	e.toVerification(t)
	st := e.srv.Store
	ref, err := st.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	failed := "AI check failed: HTTP 503"
	id, _ := st.DB().StartRun("acme", ref.F.Meta.ID, ref.Hash, "bob", st.RulesVersion())
	st.DB().AddSteps([]db.CheckStep{{RunID: id, Pos: 0, Rule: "none", Kind: "pattern", State: db.StepPass}, {RunID: id, Pos: 1, Rule: "ai-x", Kind: "ai", State: db.StepFailed, Message: failed}})
	st.DB().TxFor("acme", func(tx *db.Tx) error {
		return tx.FinishRun(id, db.RunDone, "", []db.CheckResult{{Rule: "ai-x", Level: "warning", Message: failed, Target: "ai", QuoteHash: "n"}})
	})
	bar := e.do(t, "bob", "GET", fpath+"/workflow", nil, nil).Body.String()
	if strings.Contains(slotButton(t, bar, "clear"), " disabled") || strings.Contains(bar, "Run Check first") || !strings.Contains(bar, "AI checks failed") {
		t.Fatalf("the bar after a run with a failed AI rule:\n%s", bar)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil); rec.Code >= 400 {
		t.Fatalf("posted sign off: %d\n%s", rec.Code, rec.Body.String())
	}
	if got, _ := st.Finding("acme", fdir); len(got.F.Meta.ClearedBy) != 1 || got.F.Meta.ClearedBy[0] != "bob" {
		t.Fatalf("not signed off: %+v", got.F.Meta)
	}
	// Ready to approve lists it for the director
	gates, err := st.CheckGates([]store.GateKey{{Eng: "acme", Fid: ref.F.Meta.ID, Hash: ref.Full}})
	if err != nil || len(gates) != 0 {
		t.Fatalf("gates %v %v", gates, err)
	}
}

// P10: a reviewer who already signed off is not told to run Check when a
// later run failed: their Sign off is disabled for that reason, not the
// check.
func TestRequireCheckStateOnlyWhenItBlocks(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	e.toVerification(t)
	st := e.srv.Store
	e.checked(t, "acme", fdir)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	ref, _ := st.Finding("acme", fdir)
	id, _ := st.DB().StartRun("acme", "F-001", ref.Hash, "bob", "")
	st.DB().TxFor("acme", func(tx *db.Tx) error { return tx.FinishRun(id, db.RunFailed, "script crashed", nil) })
	if bar := wfBar(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()); strings.Contains(bar, "Run Check first") {
		t.Fatalf("signed-off reviewer told to run Check:\n%s", bar)
	}
	// the director, whose Approve it blocks, is
	if bar := wfBar(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(bar, ">Run Check first<") {
		t.Fatalf("director:\n%s", bar)
	}
}

// R1: Ready to approve (list, count, nav badge, bulk Approve) leaves out a
// signed-off finding whose latest run is not a finished one on its content;
// with the setting off it is listed again.
func TestRequireCheckReadyToApprove(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	e.toVerification(t)
	st := e.srv.Store
	e.checked(t, "acme", fdir)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	approve := func() string { return queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve") }
	if !strings.Contains(approve(), "SQL injection") {
		t.Fatal("checked, signed-off finding not listed")
	}
	// a run after the sign-off that failed
	ref, _ := st.Finding("acme", fdir)
	id, _ := st.DB().StartRun("acme", "F-001", ref.Hash, "bob", "")
	st.DB().TxFor("acme", func(tx *db.Tx) error { return tx.FinishRun(id, db.RunFailed, "script crashed", nil) })
	if q := approve(); strings.Contains(q, "SQL injection") {
		t.Fatalf("listed after a failed run:\n%s", q)
	}
	if b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(b, `Inbox <span class="badge">`) {
		t.Fatal("the nav badge still counts it")
	}
	form := url.Values{"action": {"approve"}, "id": {"acme/" + fdir}}
	if r := row(e.do(t, "dora", "POST", "/inbox/bulk", form, nil).Body.String(), "acme/F-001"); !strings.Contains(r, `class="denied"`) || !strings.Contains(r, store.GateFailed) {
		t.Fatalf("bulk approve:\n%s", r)
	}
	// off: listed again, at once (no stale cache)
	if rec := e.do(t, "dora", "POST", "/admin/rules/require-check", url.Values{"on": {"0"}}, nil); rec.Code != 303 {
		t.Fatalf("toggle %d", rec.Code)
	}
	if !strings.Contains(approve(), "SQL injection") {
		t.Fatal("not listed with the setting off")
	}
}

// R1: the setting is a row of Admin › Rules, admin only, audited.
func TestRequireCheckAdmin(t *testing.T) {
	e := setup(t)
	e.rules(t, noneRule, nil)
	page := e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String()
	tbl := between(page, `<table class="table ruletable settingtable">`, "</table>")
	// P9: the empty action column's header is for screen readers only
	if !strings.Contains(tbl, `<th class="c-act"><span class="sr">Action</span></th>`) {
		t.Fatalf("action header:\n%s", tbl)
	}
	if !strings.Contains(tbl, "<th>Setting</th>") || !strings.Contains(tbl, ">Require Check before Sign off and Approve<") ||
		!strings.Contains(tbl, `action="/admin/rules/require-check"`) || !strings.Contains(tbl, `<button class="toggle on" role="switch" aria-checked="true"`) {
		t.Fatalf("settings table:\n%s", tbl)
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		if rec := e.do(t, u, "POST", "/admin/rules/require-check", url.Values{"on": {"0"}}, nil); rec.Code == 303 {
			t.Fatalf("%s turned it off", u)
		}
	}
	if !e.srv.Store.RequireCheck() {
		t.Fatal("turned off by a non-admin")
	}
	if rec := e.do(t, "dora", "POST", "/admin/rules/require-check", url.Values{"on": {"0"}}, nil); rec.Code != 303 {
		t.Fatalf("toggle %d", rec.Code)
	}
	if e.srv.Store.RequireCheck() {
		t.Fatal("still on")
	}
	l, _ := e.srv.Store.DB().AuditLog(1)
	if len(l) != 1 || l[0].Actor != "dora" || l[0].Action != "setting.require_check" || l[0].Detail != "off" {
		t.Fatalf("audit %+v", l)
	}
	page = e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String()
	if tbl := between(page, `<table class="table ruletable settingtable">`, "</table>"); !strings.Contains(tbl, `<button class="toggle" role="switch" aria-checked="false"`) || !strings.Contains(tbl, `name="on" value="1"`) {
		t.Fatalf("off:\n%s", tbl)
	}
}
