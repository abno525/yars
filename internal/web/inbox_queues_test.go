package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"yars/internal/chat"
	"yars/internal/db"
	"yars/internal/workflow"
)

var queueHead = regexp.MustCompile(`<h2>([^<]+) <span class="qcnt[^"]*">(\d+)</span></h2>`)

// queues lists the inbox's queue headings in page order, with their counts.
func queues(b string) (names []string, counts []string) {
	for _, m := range queueHead.FindAllStringSubmatch(b, -1) {
		names = append(names, m[1])
		counts = append(counts, m[2])
	}
	return names, counts
}

// queue returns the HTML of one queue section.
func queue(b, name string) string {
	i := strings.Index(b, `<section class="q q-`+name+`"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(b[i:], "</section>")
	return b[i : i+j]
}

// One layout for every role: the role's own queues in one fixed order, each
// with a header row and a count; a queue of another role shows only when it
// holds something of the user's (a reviewer's own returned finding, say).
func TestInboxQueuesPerRole(t *testing.T) {
	e := setup(t)
	for u, want := range map[string]string{
		"alice": "Returned to me,Open threads on my findings,New on team board,My drafts",
		"bob":   "Awaiting my review,Open threads on my findings,New on team board",
		"dora":  "Ready to approve,Ready to mark reported,New on team board",
	} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		names, _ := queues(b)
		if got := strings.Join(names, ","); got != want {
			t.Errorf("%s: %s, want %s", u, got, want)
		}
		for _, gone := range []string{"New finding", `class="side`, "Status</th>", "Result</th>", `class="bulkbar"`, `class="bulkform"`} {
			if strings.Contains(b, gone) {
				t.Errorf("%s: page has %q", u, gone)
			}
		}
		if strings.Count(b, "<thead>") != len(names) {
			t.Errorf("%s: %d header rows for %d queues", u, strings.Count(b, "<thead>"), len(names))
		}
	}
	// a reviewer who wrote a finding that came back sees it, in the fixed place
	ref, err := e.srv.Store.CreateFinding("acme", "Weak TLS", e.authorOf(wBob))
	if err != nil {
		t.Fatal(err)
	}
	st := e.srv.Store
	st.SetReviewers("acme", ref.Dir, []string{"carol"}, wBob)
	st.UpdateSeverity("acme", ref.Dir, "low", "", e.authorOf(wBob))
	if err := st.Transition("acme", ref.Dir, workflow.Submit, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", ref.Dir, workflow.Return, "add a PoC", wDora); err != nil {
		t.Fatal(err)
	}
	names, _ := queues(e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String())
	if got := strings.Join(names, ","); got != "Returned to me,Awaiting my review,Open threads on my findings,New on team board" {
		t.Errorf("bob with a returned finding: %s", got)
	}
}

// An empty queue keeps its header, a black 0 and one row across every
// column; the director's pick column counts too.
func TestInboxEmptyQueues(t *testing.T) {
	e := setup(t)
	e.srv.Store.Archive("acme", wDora) // alice's draft leaves her queues
	for u, want := range map[string]int{"alice": 4, "bob": 3, "dora": 3} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		_, counts := queues(b)
		if len(counts) != want || strings.Count(b, `<span class="qcnt zero">0</span>`) != want {
			t.Fatalf("%s: counts %v:\n%s", u, counts, b)
		}
		picks := 0
		if u == "dora" {
			picks = 2
		}
		if n := strings.Count(b, `<tr class="emptyrow"><td colspan="7">—</td></tr>`); n != picks {
			t.Errorf("%s: %d empty rows over 7 columns", u, n)
		}
		if n := strings.Count(b, `<tr class="emptyrow"><td colspan="6">—</td></tr>`); n != want-picks {
			t.Errorf("%s: %d empty rows over 6 columns", u, n)
		}
		if strings.Contains(b, `Inbox <span class="badge">`) {
			t.Errorf("%s: badge above 0", u)
		}
	}
}

// Rows read title | tag | engagement · ID | who · what | time | one action;
// each queue says who did what.
func TestInboxRowsSayWhoDidWhat(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	// My drafts: alice's draft, not checked yet
	b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	q := queue(b, "drafts")
	for _, want := range []string{"SQL injection", `<span class="engid">acme</span> · <span class="fid">F-001</span>`, "Not checked", `>Continue</a>`, "btn secondary sm w104"} {
		if !strings.Contains(q, want) {
			t.Errorf("drafts lack %q:\n%s", want, q)
		}
	}
	if !strings.Contains(b, `Inbox <span class="badge">1</span>`) {
		t.Error("the drafts are not in the badge")
	}
	e.toVerification(t)
	b = e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if q := queue(b, "review"); !strings.Contains(q, "<strong>alice</strong> · submitted") || !strings.Contains(q, `<span class="tag sev-high">high</span>`) || !strings.Contains(q, ">Review</a>") {
		t.Errorf("review row:\n%s", q)
	}
	// returned, fixed and sent again: edited after bob's review
	if err := st.Transition("acme", fdir, workflow.Return, "add a PoC", wBob); err != nil {
		t.Fatal(err)
	}
	q = queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "returned")
	if !strings.Contains(q, "<strong>bob</strong> · add a PoC") || !strings.Contains(q, `btn primary sm w104" href="`+fshort+`">Fix</a>`) {
		t.Errorf("returned row:\n%s", q)
	}
	if q := queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "drafts"); strings.Contains(q, "SQL injection") {
		t.Error("a returned draft is in My drafts too")
	}
	if err := st.Transition("acme", fdir, workflow.Submit, "", wAlice); err != nil {
		t.Fatal(err)
	}
	if q := queue(e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(), "review"); !strings.Contains(q, "<strong>alice</strong> · edited after your review") {
		t.Errorf("resubmitted row:\n%s", q)
	}
	st.Transition("acme", fdir, workflow.Clear, "", wBob)
	if q := queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "approve"); !strings.Contains(q, "<strong>bob</strong> · signed off") || !strings.Contains(q, ">Approve</a>") {
		t.Errorf("approve row:\n%s", q)
	}
	st.Transition("acme", fdir, workflow.Approve, "", wDora)
	if q := queue(e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(), "report"); !strings.Contains(q, "<strong>dora</strong> · approved") || !strings.Contains(q, ">Mark reported</a>") {
		t.Errorf("report row:\n%s", q)
	}
}

// Open threads on my findings: one row per open thread whose last message
// is someone else's, on findings the user wrote or reviews; the text is one
// plain line, and Reply goes to the thread's section.
func TestInboxOpenThreads(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	m, err := st.PostChat("acme", fdir, chat.Message{Text: "Is the **impact** real?\n\n```\ncurl -i x\n```", Section: "Impact"}, wBob)
	if err != nil {
		t.Fatal(err)
	}
	st.PostChat("acme", fdir, chat.Message{Text: "<img src=x onerror=alert(1)>"}, wBob)
	// a check run's thread with no human reply stays out
	st.DB().TxFor("acme", func(tx *db.Tx) error {
		return tx.AddMessage("acme", "F-001", chat.Message{ID: chat.NewID(), User: "yars", Kind: chat.KindCheck, Text: "rule hit"})
	})
	st.Invalidate("acme")
	b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	q := queue(b, "threads")
	if strings.Count(q, "<tr data-key") != 2 || strings.Contains(q, "rule hit") {
		t.Fatalf("threads:\n%s", q)
	}
	for _, want := range []string{"<strong>bob</strong> · Is the impact real? curl -i x", `href="` + fshort + `#s-impact">Reply</a>`, `href="` + fshort + `#chat">Reply</a>`, "&lt;img src=x onerror=alert(1)"} {
		if !strings.Contains(q, want) {
			t.Errorf("threads lack %q:\n%s", want, q)
		}
	}
	if strings.Contains(b, "<img src=x") {
		t.Fatal("thread text not escaped")
	}
	// bob neither wrote nor reviews it: not his
	if q := queue(e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(), "threads"); strings.Contains(q, "SQL injection") {
		t.Fatalf("bob sees threads of a finding he does not review:\n%s", q)
	}
	// alice answers: nothing left for her on that thread; bob reviews it now
	st.PostChat("acme", fdir, chat.Message{Text: "Only after login", Reply: m.ID}, wAlice)
	st.SetReviewers("acme", fdir, []string{"bob"}, wAlice)
	if q := queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "threads"); strings.Count(q, "<tr data-key") != 1 {
		t.Fatalf("alice after her reply:\n%s", q)
	}
	if q := queue(e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String(), "threads"); !strings.Contains(q, "<strong>alice</strong> · Only after login") || strings.Count(q, "<tr data-key") != 1 {
		t.Fatalf("bob as reviewer:\n%s", q)
	}
}

// My drafts says how the last check went; Submit only when it passed on
// this content and the draft is ready, Continue otherwise. Both are links.
func TestInboxDraftChecks(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	ref, _ := st.Finding("acme", fdir)
	run := func(hash string, res ...db.CheckResult) {
		id, err := st.DB().StartRun("acme", "F-001", hash, "alice", "")
		if err != nil {
			t.Fatal(err)
		}
		st.DB().TxFor("acme", func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", res) })
	}
	draft := func() string { return queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "drafts") }
	run(ref.Hash, db.CheckResult{Rule: "a", Level: "error", QuoteHash: "1"}, db.CheckResult{Rule: "b", Level: "warning", QuoteHash: "2"})
	if q := draft(); !strings.Contains(q, `class="c-what bad"`) || !strings.Contains(q, "1 error · 1 warning") || !strings.Contains(q, ">Continue</a>") {
		t.Fatalf("errors:\n%s", q)
	}
	run(ref.Hash)
	if q := draft(); !strings.Contains(q, `class="c-what good"`) || !strings.Contains(q, "Checks pass") || !strings.Contains(q, ">Continue</a>") {
		t.Fatalf("pass but no reviewer yet:\n%s", q)
	}
	st.SetReviewers("acme", fdir, []string{"bob"}, wAlice)
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	// the severity edit changed the file: the run is stale
	if q := draft(); !strings.Contains(q, "Edited since the check") || !strings.Contains(q, ">Continue</a>") {
		t.Fatalf("stale:\n%s", q)
	}
	ref, _ = st.Finding("acme", fdir)
	run(ref.Hash, db.CheckResult{Rule: "b", Level: "warning", QuoteHash: "2"}, db.CheckResult{Rule: "c", Level: "warning", QuoteHash: "3"})
	if q := draft(); !strings.Contains(q, "2 warnings") || !strings.Contains(q, `btn primary sm w104" href="`+fshort+`">Submit</a>`) {
		t.Fatalf("ready:\n%s", q)
	}
	if strings.Contains(draft(), "<form") {
		t.Fatal("a row action posts")
	}
}

// Q13: after a rule change a draft's last check is out of date, as on its
// page: no "Checks pass", no Submit.
func TestInboxDraftAfterRuleChange(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	st := e.srv.Store
	st.SetReviewers("acme", fdir, []string{"bob"}, wAlice)
	st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice))
	ref, _ := st.Finding("acme", fdir)
	id, err := st.DB().StartRun("acme", "F-001", ref.Hash, "alice", e.srv.Rules.Version())
	if err != nil {
		t.Fatal(err)
	}
	st.DB().TxFor("acme", func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) })
	draft := func() string { return queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "drafts") }
	if q := draft(); !strings.Contains(q, "Checks pass") || !strings.Contains(q, ">Submit</a>") {
		t.Fatalf("before the rule change:\n%s", q)
	}
	p := filepath.Join(e.dir, ".yars", "rules", "style.yaml")
	os.WriteFile(p, []byte("- id: none\n  target: title\n  regex_forbid: 'qqqq'\n"), 0o644)
	later := time.Now().Add(time.Minute)
	os.Chtimes(p, later, later)
	if q := draft(); !strings.Contains(q, "Rules changed since the check") || strings.Contains(q, "Checks pass") || strings.Contains(q, ">Submit</a>") || !strings.Contains(q, ">Continue</a>") {
		t.Fatalf("after the rule change:\n%s", q)
	}
}

// An archived engagement has nothing to do: none of its findings or notes
// is in any queue.
func TestInboxLeavesArchivedOut(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.lead(t, "alice", "Open redirect", "", "open")
	if b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(queue(b, "report"), "SQL injection") {
		t.Fatal("not in Ready to mark reported before archiving")
	}
	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob", "dora"} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		if strings.Contains(b, "SQL injection") || strings.Contains(b, "Open redirect") {
			t.Errorf("%s: archived work listed", u)
		}
	}
}

// The director's bar is always above the queues (disabled at 0 selected);
// only Ready to approve and Ready to mark reported have checkboxes, each
// with its own select-all.
func TestInboxDirectorBar(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	bar, lists := strings.Index(b, `class="fbulk"`), strings.Index(b, `<section class="q q-`)
	if bar < 0 || lists < bar || !strings.Contains(b, `<form class="fbulkform" hx-post="/inbox/bulk"`) {
		t.Fatalf("no bar above the queues:\n%s", b)
	}
	for _, want := range []string{"0 selected", `data-bulk-menu aria-haspopup="menu" aria-expanded="false" disabled>Set state ▾`, ">Assign reviewers</button>", "data-bulk-clear"} {
		if !strings.Contains(b, want) {
			t.Errorf("bar lacks %q", want)
		}
	}
	if q := queue(b, "approve"); !strings.Contains(q, `<input type="checkbox" name="id" value="acme/`+fdir+`"`) || !strings.Contains(q, "data-pick-all") || !strings.Contains(q, `data-acts="`) {
		t.Errorf("approve queue has no picks:\n%s", q)
	}
	if strings.Contains(queue(b, "board"), "c-pick") {
		t.Error("board queue has picks")
	}
	for _, u := range []string{"alice", "bob"} {
		if b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String(); strings.Contains(b, "fbulk") || strings.Contains(b, "c-pick") {
			t.Errorf("%s has the bulk bar", u)
		}
	}
}

// A run from the inbox answers with the whole form: the summary in the bar,
// the rows where they were, a moved row saying what it is now, a skipped
// row tinted. A pentester's run gets the pentester's layout back.
func TestInboxBulkInPlace(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob)
	hx := map[string]string{"HX-Request": "true"}
	b := e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"approve"}, "id": {"acme/" + fdir, "acme/" + fdir, "../x/F-001", "nope/F-001"}}, hx).Body.String()
	if !strings.HasPrefix(strings.TrimSpace(b), `<form class="fbulkform"`) || !strings.Contains(b, `<span class="mv">1 moved</span> <span class="sk">· 2 skipped</span>`) {
		t.Fatalf("answer:\n%s", b)
	}
	q := queue(b, "approve")
	if !strings.Contains(q, "SQL injection") || !strings.Contains(q, "<strong>dora</strong> · approved") || !strings.Contains(q, ">Mark reported</a>") || !strings.Contains(q, " checked") {
		t.Fatalf("moved row:\n%s", q)
	}
	if e.status(t) != "complete" {
		t.Fatal("not approved")
	}
	// the same row again: skipped, tinted, nothing changes
	b = e.do(t, "dora", "POST", "/inbox/bulk", url.Values{"action": {"approve"}, "id": {"acme/" + fdir}}, hx).Body.String()
	if !strings.Contains(b, `<span class="mv">0 moved</span> <span class="sk">· 1 skipped</span>`) || !strings.Contains(b, `class="skip"`) {
		t.Fatalf("second approve:\n%s", b)
	}
	rec := e.do(t, "alice", "POST", "/inbox/bulk", url.Values{"action": {"take_back"}, "id": {"acme/" + fdir}}, hx)
	if strings.Contains(rec.Body.String(), "c-pick") || strings.Contains(rec.Body.String(), "fbulk") {
		t.Fatalf("pentester got the director layout (%d):\n%s", rec.Code, rec.Body.String())
	}
}
