package web

import (
	"image/color"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

var (
	wAlice = config.User{Username: "alice", Role: "pentester"}
	wBob   = config.User{Username: "bob", Role: "reviewer"}
	wDora  = config.User{Username: "dora", Role: "director"}
)

const fdir = "F-001-sql-injection"

// fshort is the finding's URL as pages link it.
const fshort = "/e/acme/f/001"

func (e *env) status(t *testing.T) string {
	t.Helper()
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	return ref.F.Meta.Status
}

// toVerification assigns bob, sets a severity and submits as alice.
func (e *env) toVerification(t *testing.T) {
	t.Helper()
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	if err := st.Transition("acme", fdir, workflow.Submit, "", wAlice); err != nil {
		t.Fatal(err)
	}
}

// pen2 adds a second pentester on the acme team.
func (e *env) pen2(t *testing.T) {
	t.Helper()
	e.addUser(t, config.User{Username: "pen2", Role: "pentester"})
	if err := e.srv.Store.DB().AddMembers("acme", "pen2"); err != nil {
		t.Fatal(err)
	}
}

func (e *env) toComplete(t *testing.T) {
	t.Helper()
	e.toVerification(t)
	st := e.srv.Store
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", fdir, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
}

// D3: the problems are listed in the Checks strip only, not under the bar.
func TestNoGateListUnderBar(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `class="gate"`) {
		t.Fatalf("a gate list:\n%s", wfBar(t, b))
	}
}

// D3: the bar's count is the strip's Errors count.
func TestOneErrorCount(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	e.srv.Store.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if wf := wfBar(t, b); !strings.Contains(wf, ">2 errors to fix<") {
		t.Fatalf("bar:\n%s", wf)
	}
	if p := checksPanel(t, b); !strings.Contains(p, `Errors <span class="badge">2</span>`) {
		t.Fatalf("strip:\n%s", p)
	}
	// a viewer who cannot submit is not told to fix anything
	if wf := wfBar(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()); strings.Contains(wf, "to fix") {
		t.Fatalf("bob's bar:\n%s", wf)
	}
}

// D3: the state text opens the strip, so it is a button only when there is
// something to show there.
func TestStateIsButtonOnlyWithProblems(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(wf, `<button type="button" class="wfstate error" id="wf-state" data-open-checks`) {
		t.Fatalf("no state button with errors:\n%s", wf)
	}
	st := e.srv.Store
	st.SetReviewers("acme", fdir, []string{"bob"}, wAlice)
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	if wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); strings.Contains(wf, "data-open-checks") || !strings.Contains(wf, `<span class="wfstate" id="wf-state"`) {
		t.Fatalf("state on a clean draft:\n%s", wf)
	}
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); !strings.Contains(js, "[data-open-checks]") {
		t.Fatal("app.js does not open the strip")
	}
}

func TestWorkflowButtonsByRole(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil) // the gate's problems are listed in the Checks strip
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	i := strings.Index(b, "Submit for verification")
	if i < 0 || !strings.Contains(b[max(0, i-200):i], "disabled") || !strings.Contains(b, "assign at least one reviewer") {
		t.Fatalf("alice should see disabled submit with gate problems:\n%s", b)
	}
	if b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, "Submit for verification") {
		t.Fatal("bob sees submit")
	}
}

func TestSubmitAndClearFlow(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"bob"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("reviewers code %d %s", rec.Code, rec.Body.String())
	}
	e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"high"}}, nil)
	if rec := e.do(t, "alice", "POST", fpath+"/action/submit", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("submit code %d %s", rec.Code, rec.Body.String())
	}
	if e.status(t) != "verification" {
		t.Fatal("not in verification")
	}
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "/e/acme/f/001/action/clear") || !strings.Contains(b, "Return to draft") {
		t.Fatalf("bob lacks review actions:\n%s", b)
	}
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	if b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `class="rev cleared" title="bob"`) || !strings.Contains(b, "/e/acme/f/001/action/approve") {
		t.Fatalf("dora page:\n%s", b)
	}
	e.do(t, "dora", "POST", fpath+"/action/approve", url.Values{}, nil)
	if e.status(t) != "complete" {
		t.Fatal("not complete")
	}
	if got := e.events(t); got != "alice:submit bob:clear dora:approve" {
		t.Fatalf("events %q", got)
	}
}

// Q25: a director who wrote a finding signs it off from the bar; Approve
// waits for another reviewer's sign-off. A pentester author has no Sign off.
func TestDirectorSignsOffOwnFindingBar(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	f, err := st.CreateFinding("acme", "XSS", e.authorOf(wDora))
	if err != nil {
		t.Fatal(err)
	}
	st.SetReviewers("acme", f.Dir, []string{"bob"}, wDora)
	st.UpdateSeverity("acme", f.Dir, "high", "", e.authorOf(wDora))
	if err := st.Transition("acme", f.Dir, workflow.Submit, "", wDora); err != nil {
		t.Fatal(err)
	}
	wf := wfSection(t, e.do(t, "dora", "GET", "/e/acme/f/002", nil, nil).Body.String())
	if !strings.Contains(wf, `<button class="btn w112 primary" id="wf-clear" aria-keyshortcuts="Shift&#43;O" data-action="clear" title="Sign off">Sign off</button>`) {
		t.Fatalf("no enabled Sign off for the director author:\n%s", wf)
	}
	if !strings.Contains(wf, `id="wf-approve" aria-keyshortcuts="Shift&#43;A" data-action="approve" disabled`) {
		t.Fatalf("Approve does not wait:\n%s", wf)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/f/002/action/clear", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign off %d", rec.Code)
	}
	if ref, _ := st.Finding("acme", f.Dir); !slices.Contains(ref.F.Meta.ClearedBy, "dora") {
		t.Fatalf("not signed off: %v", ref.F.Meta.ClearedBy)
	}
	e.toVerification(t)
	if wf := wfSection(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); strings.Contains(wf, `data-action="clear"`) {
		t.Fatalf("Sign off for a pentester author:\n%s", wf)
	}
}

// events lists the finding's workflow events as "user:event".
func (e *env) events(t *testing.T) string {
	t.Helper()
	msgs, err := e.srv.Store.Chat("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range msgs {
		if m.Event != "" {
			out = append(out, m.User+":"+m.Event)
		}
	}
	return strings.Join(out, " ")
}

func TestWithdrawAndRestoreWeb(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, fshort+"/action/withdraw") {
		t.Fatal("author lacks withdraw")
	}
	if b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, fshort+"/action/withdraw") {
		t.Fatal("reviewer sees withdraw")
	}
	if b := e.denied(t, "alice", fpath+"/action/withdraw", url.Values{"reason": {" "}}); !strings.Contains(b, "reason is required") {
		t.Fatal("withdraw without reason")
	}
	if b := e.denied(t, "bob", fpath+"/action/withdraw", url.Values{"reason": {"x"}}); !strings.Contains(b, `class="error`) || e.status(t) != "verification" {
		t.Fatal("reviewer withdrew")
	}
	e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {"Duplicate of F-002"}}, nil)
	if e.status(t) != "withdrawn" {
		t.Fatalf("status %s", e.status(t))
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, fshort+"/action/revise") || !strings.Contains(b, "Restore") || !strings.Contains(b, "Duplicate of F-002") {
		t.Fatalf("withdrawn page:\n%s", b)
	}
	// out of the inbox and the default board, in the Withdrawn filter
	if b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(section(b, "Awaiting my review"), "SQL injection") {
		t.Fatal("withdrawn finding in the inbox")
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(b, `href="/e/acme/f/001"`) || !strings.Contains(b, "status=withdrawn") {
		t.Fatalf("board:\n%s", b)
	}
	if b := e.do(t, "alice", "GET", "/e/acme?status=withdrawn", nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme/f/001"`) {
		t.Fatal("withdrawn filter empty")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/revise", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "draft" {
		t.Fatalf("restore code %d status %s", rec.Code, e.status(t))
	}
}

func TestSignOffAlias(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, ">Sign off<") || !strings.Contains(b, fshort+"/action/clear") {
		t.Fatalf("bob page lacks Sign off:\n%s", b)
	}
	if rec := e.do(t, "bob", "POST", fpath+"/action/sign_off", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign_off code %d %s", rec.Code, rec.Body.String())
	}
	if got := e.events(t); got != "alice:submit bob:clear" {
		t.Fatalf("events %q", got)
	}
}

func TestMarkReportedAction(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.pen2(t)
	if b := e.do(t, "pen2", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, fshort+"/action/report") {
		t.Fatal("other pentester sees Mark reported")
	}
	for _, u := range []string{"alice", "dora"} {
		if b := e.do(t, u, "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, fshort+"/action/report") || !strings.Contains(b, "Mark reported") {
			t.Fatalf("%s lacks Mark reported", u)
		}
	}
	if b := e.denied(t, "pen2", fpath+"/action/report", url.Values{}); !strings.Contains(b, `class="error`) || e.status(t) != "complete" {
		t.Fatalf("other pentester reported: %s", e.status(t))
	}
	if rec := e.do(t, "dora", "POST", fpath+"/action/report", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "reported" {
		t.Fatalf("report code %d status %s", rec.Code, e.status(t))
	}
}

// The author marks their own complete finding reported.
func TestAuthorMarksReported(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	if rec := e.do(t, "alice", "POST", fpath+"/action/report", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "reported" {
		t.Fatalf("author report code %d status %s", rec.Code, e.status(t))
	}
}

// R4: Revert sits in Complete's and Reported's first slot, for the author
// and a director: a secondary button that opens its reason panel.
func TestWorkflowBarRevertSlots(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	check := func(user, act, head string, want bool) {
		t.Helper()
		wf := wfSection(t, e.do(t, user, "GET", fpath, nil, nil).Body.String())
		// its title says which revert, as the panel's head does
		btn := `<button type="button" class="btn w136 secondary" id="wf-` + act + `" aria-keyshortcuts="Shift&#43;U" data-slot="` + act + `" data-action="` + act + `" title="` + head + `" aria-controls="wf-` + act + `-reason" aria-expanded="false" data-reason-toggle>Revert</button>`
		panel := `<form method="post" action="/e/acme/f/001/action/` + act + `" class="wfpanel ` + act + `" id="wf-` + act + `-reason" hidden>
    <div class="panelhead"><h2>` + head + `</h2></div>`
		has := strings.Contains(wf, btn) && strings.Contains(wf, panel) && strings.Contains(wf, `<button class="btn secondary sm w96" aria-keyshortcuts="Control+Enter">Revert</button>`)
		if has != want || (!want && strings.Contains(wf, `data-action="`+act+`"`)) {
			t.Errorf("%s on %s: Revert %v, want %v:\n%s", user, act, has, want, wf)
		}
	}
	for u, want := range map[string]bool{"dora": true, "alice": true, "bob": false} {
		check(u, "reopen", "Revert to verification", want)
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Report, "", wDora); err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{"dora": true, "alice": true, "bob": false} {
		check(u, "unreport", "Revert to complete", want)
	}
	// Return and Withdraw stay red
	if wf := wfSection(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(wf, `<button class="btn danger sm w96" aria-keyshortcuts="Control+Enter">Withdraw</button>`) {
		t.Fatalf("withdraw panel:\n%s", wf)
	}
}

// R4: the revert's reason is required on the page too.
func TestRevertPostNeedsReason(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Report, "", wDora); err != nil {
		t.Fatal(err)
	}
	for _, blank := range []url.Values{{}, {"reason": {"  "}}} {
		b := e.denied(t, "dora", fpath+"/action/unreport", blank)
		if !strings.Contains(b, "a reason is required") || !strings.Contains(b, `id="wf-unreport-reason">`) || e.status(t) != "reported" {
			t.Fatalf("without a reason %v: status %s:\n%s", blank, e.status(t), b)
		}
	}
	if rec := e.do(t, "dora", "POST", fpath+"/action/unreport", url.Values{"reason": {"sent too early"}}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "complete" {
		t.Fatalf("with a reason: code %d status %s", rec.Code, e.status(t))
	}
}

func TestReturnRequiresReason(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	if b := e.denied(t, "bob", fpath+"/action/return", url.Values{"reason": {" "}}); !strings.Contains(b, "reason is required") || e.status(t) != "verification" {
		t.Fatalf("without a reason:\n%s", b)
	}
	e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {"Steps are incomplete"}}, nil)
	if e.status(t) != "draft" {
		t.Fatal("not returned")
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "Steps are incomplete") || !strings.Contains(b, "Returned by") {
		t.Fatalf("no returned banner:\n%s", b)
	}
}

// Sign off and Approve are for the version the page showed: the bar sends
// its content hash, and a finding changed since is refused with what to do
// (backlog, M10).
func TestSignOffBindsToViewedVersion(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	seenOf := func(user string) string {
		t.Helper()
		m := regexp.MustCompile(`<input type="hidden" name="seen" value="([0-9a-f]+)">`).FindStringSubmatch(e.do(t, user, "GET", fshort, nil, nil).Body.String())
		if m == nil {
			t.Fatalf("%s's bar sends no viewed version", user)
		}
		return m[1]
	}
	seen := seenOf("bob")
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Changed while bob read.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	b := e.denied(t, "bob", fshort+"/action/clear", url.Values{"seen": {seen}})
	if !strings.Contains(b, "the finding changed since you opened it; read it again") {
		t.Fatal("no refusal on the page")
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatal("bob signed off a version he did not see")
	}
	// the bar names the version by its full SHA-256; the first 16 digits,
	// which another file can be made to share, are not that version
	now := seenOf("bob")
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(now) != 64 || now != ref.Full {
		t.Fatalf("the bar sends %q, the finding's digest is %q", now, ref.Full)
	}
	b = e.denied(t, "bob", fshort+"/action/clear", url.Values{"seen": {now[:16]}})
	if !strings.Contains(b, "the finding changed since you opened it; read it again") {
		t.Fatal("no refusal of the short hash on the page")
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatal("bob signed off with the first 16 digits")
	}
	if rec := e.do(t, "bob", "POST", fshort+"/action/clear", url.Values{"seen": {seenOf("bob")}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign off on the current version: %d", rec.Code)
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.ClearedBy) != 1 {
		t.Fatal("bob's sign-off on the current version did not count")
	}
}

// A sign-off is for the attachments the page showed too: the bar sends
// them, and an upload since is refused as a text edit is.
func TestSignOffBindsToViewedAttachments(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	formOf := func(user string) url.Values {
		t.Helper()
		m := regexp.MustCompile(`<input type="hidden" name="seen" value="([0-9a-f]+)"><input type="hidden" name="seenfiles" value="([0-9a-f]+)">`).FindStringSubmatch(e.do(t, user, "GET", fshort, nil, nil).Body.String())
		if m == nil {
			t.Fatalf("%s's bar sends no viewed attachments", user)
		}
		return url.Values{"seen": {m[1]}, "seenfiles": {m[2]}}
	}
	form := formOf("bob")
	if _, err := e.srv.Store.AddAttachment("acme", fdir, "shot.png", testPNG(t, color.White), wAlice); err != nil {
		t.Fatal(err)
	}
	b := e.denied(t, "bob", fshort+"/action/clear", form)
	if !strings.Contains(b, "the finding changed since you opened it; read it again") {
		t.Fatal("no refusal on the page")
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatal("bob signed off attachments he did not see")
	}
	if rec := e.do(t, "bob", "POST", fshort+"/action/clear", formOf("bob"), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign off on the current version: %d", rec.Code)
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.ClearedBy) != 1 {
		t.Fatal("bob's sign-off on the current attachments did not count")
	}
}

// denied posts an action that must be refused. The answer sends the browser
// back to the finding's own page (303), returned here as the user then sees
// it; the caller checks the error is on it.
func (e *env) denied(t *testing.T, user, path string, form url.Values) string {
	t.Helper()
	rec := e.do(t, user, "POST", path, form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fshort {
		t.Fatalf("%s: code %d to %q", path, rec.Code, rec.Header().Get("Location"))
	}
	return e.do(t, user, "GET", fshort, nil, nil).Body.String()
}

func TestDeniedActionShowsError(t *testing.T) {
	e := setup(t)
	if b := e.denied(t, "alice", fpath+"/action/approve", url.Values{}); !strings.Contains(b, `class="error`) {
		t.Fatal("no error on the page")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/bogus", url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bogus action code %d", rec.Code)
	}
}

// A denied action goes back to the finding's own URL, so a reload posts
// nothing again; the page says why and opens the action's reason panel
// again with the reason typed. The next visit is the plain page (backlog, M3).
func TestDeniedActionKeepsReason(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	typed := " \t "
	b := e.denied(t, "bob", fpath+"/action/return", url.Values{"reason": {typed}})
	if !strings.Contains(b, "a reason is required to return a finding") {
		t.Fatal("the page does not say why")
	}
	if !strings.Contains(b, `id="wf-return-reason">`) || !strings.Contains(b, `<textarea name="reason" required rows="4" maxlength="4000">`+typed+`</textarea>`) || !strings.Contains(b, `aria-controls="wf-return-reason" aria-expanded="true"`) {
		t.Fatalf("the reason panel is not open with the reason:\n%s", wfSection(t, b))
	}
	if b := e.do(t, "bob", "GET", fshort, nil, nil).Body.String(); !strings.Contains(b, `id="wf-return-reason" hidden>`) || strings.Contains(b, "a reason is required") {
		t.Fatal("the denial is shown twice")
	}
}

func TestLockedEditForbidden(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	before := e.lastCommit(t)
	reqs := []struct{ method, path string }{
		{"GET", fpath + "/s/Impact/edit"},
		{"POST", fpath + "/s/Impact"},
		{"GET", fpath + "/cvss/edit"},
		{"POST", fpath + "/cvss"},
		{"POST", fpath + "/severity"},
		{"GET", fpath + "/details/edit"},
		{"POST", fpath + "/details"},
	}
	for _, r := range reqs {
		var form url.Values
		if r.method == "POST" {
			form = url.Values{"body": {"x"}, "severity": {"low"}, "row:Location": {"x"}, "action": {"clear"}}
		}
		if rec := e.do(t, "alice", r.method, r.path, form, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: code %d", r.method, r.path, rec.Code)
		}
	}
	if e.lastCommit(t) != before {
		t.Fatal("locked finding changed")
	}
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, "/s/Impact/edit") || strings.Contains(b, "/details/edit") || strings.Contains(b, "/cvss/edit") {
		t.Fatal("edit buttons shown on locked finding")
	}
	if rec := e.do(t, "dora", "GET", fpath+"/s/Impact/edit", nil, nil); rec.Code != 200 {
		t.Fatalf("director edit code %d", rec.Code)
	}
}

// Finding URLs are just the number: /e/acme/f/001.
func TestShortFindingURLs(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme/f/001"`) || strings.Contains(b, "/f/F-001") {
		t.Fatalf("table links not short:\n%s", b)
	}
	b := e.do(t, "alice", "GET", "/e/acme/f/001", nil, nil).Body.String()
	if !strings.Contains(b, "SQL injection") || !strings.Contains(b, `/e/acme/f/001/details/edit`) || strings.Contains(b, "/f/F-001") {
		t.Fatalf("finding page links not short:\n%s", b)
	}
	e.do(t, "alice", "POST", "/e/acme/f/001/reviewers", url.Values{"reviewer": {"bob"}}, nil)
	e.srv.Store.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	if rec := e.do(t, "alice", "POST", "/e/acme/f/001/action/submit", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001" {
		t.Fatalf("submit code %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"XSS"}}, nil); rec.Header().Get("Location") != "/e/acme/f/002" {
		t.Fatalf("new finding redirect %q", rec.Header().Get("Location"))
	}
}

// One press assigns every reviewer-role account (directors stay as they were).
func TestReviewersAssignAll(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `name="all"`) {
		t.Fatal("no assign-all button")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("code %d", rec.Code)
	}
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "bob,carol" {
		t.Fatalf("reviewers %q", got)
	}
}

// The picker's boxes are the list as the page read it. Saved after someone
// else added a reviewer, they would drop that reviewer and their sign-off:
// the save is refused on the bar. Assign all only adds, so it goes through
// from the same old page.
func TestReviewersStaleFormRefused(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	ref, _ := st.Finding("acme", fdir)
	base := store.ReviewersHash(ref.F.Meta)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `class="picker">
          <input type="hidden" name="base" value="`+base+`">`) {
		t.Fatalf("no base in the picker:\n%s", between(b, `class="wfrevs"`, "</form>"))
	}
	if err := st.AddReviewers("acme", fdir, []string{"dora"}, wDora); err != nil {
		t.Fatal(err)
	}
	reviewers := func() string {
		ref, _ := st.Finding("acme", fdir)
		return strings.Join(ref.F.Meta.Reviewers, ",")
	}
	if b := e.denied(t, "alice", fpath+"/reviewers", url.Values{"reviewer": {"bob"}, "base": {base}}); !strings.Contains(b, "the reviewers changed since you opened the page") {
		t.Fatal("no refusal on the page")
	}
	if got := reviewers(); got != "bob,dora" {
		t.Fatalf("after the stale save: %q", got)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}, "base": {base}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("assign all %d", rec.Code)
	}
	if got := reviewers(); got != "bob,carol,dora" {
		t.Fatalf("after assign all: %q", got)
	}
	// the page as it is now saves
	ref, _ = st.Finding("acme", fdir)
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"bob"}, "base": {store.ReviewersHash(ref.F.Meta)}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("fresh save %d", rec.Code)
	}
	if got := reviewers(); got != "bob" {
		t.Fatalf("after the fresh save: %q", got)
	}
}

// Q25: a director who signed off her own finding is on its reviewers;
// Assign all adds the reviewers and keeps her sign-off.
func TestReviewersAssignAllAfterOwnSignOff(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	f, err := st.CreateFinding("acme", "XSS", e.authorOf(wDora))
	if err != nil {
		t.Fatal(err)
	}
	st.SetReviewers("acme", f.Dir, []string{"bob"}, wDora)
	st.UpdateSeverity("acme", f.Dir, "high", "", e.authorOf(wDora))
	st.Transition("acme", f.Dir, workflow.Submit, "", wDora)
	if err := st.Transition("acme", f.Dir, workflow.Clear, "", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/f/002/reviewers", url.Values{"all": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("code %d", rec.Code)
	}
	ref, _ := st.Finding("acme", f.Dir)
	if got := strings.Join(ref.F.Meta.Reviewers, ","); got != "bob,carol,dora" || !slices.Equal(ref.F.Meta.ClearedBy, []string{"dora"}) {
		t.Fatalf("reviewers %q cleared %v", got, ref.F.Meta.ClearedBy)
	}
}

func TestReviewersRejectUnknown(t *testing.T) {
	e := setup(t)
	if b := e.denied(t, "alice", fpath+"/reviewers", url.Values{"reviewer": {"mallory"}}); !strings.Contains(b, "unknown or ineligible reviewer mallory") {
		t.Fatal("no refusal on the page")
	}
	e.pen2(t)
	reviewers := func() string {
		ref, _ := e.srv.Store.Finding("acme", fdir)
		return strings.Join(ref.F.Meta.Reviewers, ",")
	}
	if b := e.denied(t, "pen2", fpath+"/reviewers", url.Values{"reviewer": {"dora"}}); !strings.Contains(b, `class="error`) || reviewers() != "" {
		t.Fatalf("other pentester assigned: %q", reviewers())
	}
	// a reviewer may assign other reviewers, never themselves
	if b := e.denied(t, "bob", fpath+"/reviewers", url.Values{"reviewer": {"bob", "carol"}}); !strings.Contains(b, `class="error`) || reviewers() != "" {
		t.Fatalf("bob assigned himself: %q", reviewers())
	}
	if rec := e.do(t, "bob", "POST", fpath+"/reviewers", url.Values{"reviewer": {"carol"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("reviewer assign code %d", rec.Code)
	}
}

// A disabled account is no reviewer: not in the list, not added by "all",
// refused when posted or bulk assigned.
func TestDisabledNotReviewer(t *testing.T) {
	e := setup(t)
	e.srv.Store.DB().SetDisabled("carol", true)
	if b := e.do(t, "alice", "GET", fpath+"/workflow", nil, nil).Body.String(); strings.Contains(b, "carol") {
		t.Fatal("reviewer list offers a disabled account")
	}
	if b := e.denied(t, "alice", fpath+"/reviewers", url.Values{"reviewer": {"carol"}}); !strings.Contains(b, "unknown or ineligible reviewer carol") {
		t.Fatal("assigned a disabled account")
	}
	e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}}, nil)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if slices.Contains(ref.F.Meta.Reviewers, "carol") || !slices.Contains(ref.F.Meta.Reviewers, "bob") {
		t.Fatalf("all: %v", ref.F.Meta.Reviewers)
	}
	e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}, "reviewer": {"carol"}}, nil)
	if ref, _ := e.srv.Store.Finding("acme", fdir); slices.Contains(ref.F.Meta.Reviewers, "carol") {
		t.Fatalf("bulk added a disabled account: %v", ref.F.Meta.Reviewers)
	}
}
