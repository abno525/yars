package workflow

import (
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// In the simple workflow every account is a director; anna is the admin.
var (
	anna   = config.User{Username: "anna", Role: "director", IsAdmin: true}
	ben    = config.User{Username: "ben", Role: "director"}
	simple = Flow{Simple: true}
)

func simpleCfg() config.Config {
	c := config.Default()
	c.Workflow = config.WorkflowSimple
	return c
}

// smeta is a finding by anna as the simple workflow has it: no reviewers.
func smeta(status string) finding.Meta {
	return finding.Meta{ID: "F-001", Title: "T", Status: status, Severity: "high", Author: "anna"}
}

func TestFlowOf(t *testing.T) {
	if f := FlowOf(config.Default()); f.Simple || f.Name() != "standard" || !f.HasReviewers() {
		t.Errorf("standard: %+v %q", f, f.Name())
	}
	if f := FlowOf(simpleCfg()); !f.Simple || f.Name() != "simple" || f.HasReviewers() {
		t.Errorf("simple: %+v %q", f, f.Name())
	}
	c := config.Default()
	c.Workflow = config.WorkflowStandard
	if FlowOf(c).Simple {
		t.Error("workflow: standard is simple")
	}
}

// The simple workflow's steps and actions; the zero Flow is the standard
// one, as the package-level values are.
func TestSimpleStatuses(t *testing.T) {
	if got := simple.Statuses(); !slices.Equal(got, []string{"draft", "complete", "reported"}) {
		t.Errorf("statuses %v", got)
	}
	if got := simple.AllStatuses(); !slices.Equal(got, []string{"draft", "complete", "reported", "withdrawn"}) {
		t.Errorf("all statuses %v", got)
	}
	if !slices.Equal(simple.ShownSteps(), simple.Statuses()) || !slices.Equal(simple.ShownAll(), simple.AllStatuses()) {
		t.Errorf("shown %v %v", simple.ShownSteps(), simple.ShownAll())
	}
	if got := simple.Actions(); !slices.Equal(got, []Action{Complete, Reopen, Report, Unreport, Withdraw, Revise}) || !slices.Equal(got, SimpleActions) {
		t.Errorf("actions %v", got)
	}
	std := Flow{}
	if !slices.Equal(std.Statuses(), Statuses) || !slices.Equal(std.AllStatuses(), AllStatuses) || !slices.Equal(std.ShownSteps(), ShownSteps) ||
		!slices.Equal(std.ShownAll(), ShownAll) || !slices.Equal(std.Actions(), Actions) {
		t.Error("the standard flow differs from the package-level values")
	}
	for _, a := range append(slices.Clone(Actions), Complete) {
		f1, t1 := std.Target(a)
		f2, t2 := Target(a)
		if !slices.Equal(f1, f2) || t1 != t2 {
			t.Errorf("standard target of %s: %v %q, package %v %q", a, f1, t1, f2, t2)
		}
	}
}

func TestSimpleTargets(t *testing.T) {
	cases := []struct {
		a    Action
		from []string
		to   string
	}{
		{Complete, []string{"draft"}, "complete"},
		{Reopen, []string{"complete"}, "draft"},
		{Report, []string{"complete"}, "reported"},
		{Unreport, []string{"reported"}, "complete"},
		{Withdraw, []string{"draft", "complete", "reported"}, "withdrawn"},
		{Revise, []string{"withdrawn"}, "draft"},
		{Submit, nil, ""},
		{Return, nil, ""},
		{Clear, nil, ""},
		{Approve, nil, ""},
		{TakeBack, nil, ""},
		{"bogus", nil, ""},
	}
	for _, c := range cases {
		from, to := simple.Target(c.a)
		if !slices.Equal(from, c.from) || to != c.to {
			t.Errorf("%s: %v -> %q, want %v -> %q", c.a, from, to, c.from, c.to)
		}
	}
}

// Submit, Return, Sign off, Approve and Take back are not part of the simple
// workflow: refused in every status, saying so.
func TestSimpleCheckRefusesReviewActions(t *testing.T) {
	for _, a := range []Action{Submit, Return, Clear, Approve, TakeBack} {
		for _, st := range []string{"draft", "verification", "complete"} {
			err := simple.Check(anna, smeta(st), a)
			want := Label(a) + " is not part of the simple workflow (draft → complete → reported)"
			if err == nil || err.Error() != want {
				t.Errorf("%s on %s: %v", a, st, err)
			}
			if _, ok := err.(*Denied); !ok {
				t.Errorf("%s on %s: not a *Denied: %T", a, st, err)
			}
		}
	}
	if err := simple.Check(anna, smeta("draft"), "bogus"); err == nil || err.Error() != `unknown action "bogus"` {
		t.Errorf("bogus: %v", err)
	}
}

// Anyone completes a draft: the author, or any other account (every account
// is a director). Complete works on drafts only.
func TestSimpleCompleteAnyUser(t *testing.T) {
	for _, u := range []config.User{anna, ben} {
		if err := simple.Check(u, smeta("draft"), Complete); err != nil {
			t.Errorf("%s: %v", u.Username, err)
		}
	}
	for _, st := range []string{"complete", "reported", "withdrawn"} {
		if err := simple.Check(ben, smeta(st), Complete); err == nil || err.Error() != "Complete is only possible in draft (finding is "+st+")" {
			t.Errorf("complete on %s: %v", st, err)
		}
	}
	// held to the standard rule: the author or a director
	if err := simple.Check(config.User{Username: "anna", Role: "pentester"}, smeta("draft"), Complete); err != nil {
		t.Errorf("author below director: %v", err)
	}
	if err := simple.Check(config.User{Username: "x", Role: "pentester"}, smeta("draft"), Complete); err == nil {
		t.Error("someone else below director completed it")
	}
	// the rest of the simple workflow, as any account
	for _, c := range []struct {
		st string
		a  Action
	}{{"complete", Reopen}, {"complete", Report}, {"reported", Unreport}, {"draft", Withdraw}, {"complete", Withdraw},
		{"reported", Withdraw}, {"withdrawn", Revise}} {
		if err := simple.Check(ben, smeta(c.st), c.a); err != nil {
			t.Errorf("%s on %s: %v", c.a, c.st, err)
		}
	}
}

func TestSimpleRevertNames(t *testing.T) {
	if n := simple.RevertName(Reopen); n != "Revert to draft" {
		t.Errorf("simple reopen %q", n)
	}
	if n := simple.RevertName(Unreport); n != "Revert to complete" {
		t.Errorf("simple unreport %q", n)
	}
	if n := (Flow{}).RevertName(Reopen); n != "Revert to verification" {
		t.Errorf("standard reopen %q", n)
	}
	if n := (Flow{}).RevertName(Unreport); n != "Revert to complete" {
		t.Errorf("standard unreport %q", n)
	}
	if n := simple.RevertName(Report); n != "Mark reported" {
		t.Errorf("another action %q", n)
	}
	if err := simple.Check(anna, smeta("reported"), Reopen); err == nil || err.Error() != "Revert to draft is only possible in complete (finding is reported)" {
		t.Errorf("reopen on reported: %v", err)
	}
	if err := simple.Check(anna, smeta("complete"), Unreport); err == nil || err.Error() != "Revert to complete is only possible in reported (finding is complete)" {
		t.Errorf("unreport on complete: %v", err)
	}
}

// The standard workflow has no Complete action.
func TestStandardCompleteUnknown(t *testing.T) {
	if from, to := Target(Complete); from != nil || to != "" {
		t.Errorf("target %v %q", from, to)
	}
	for _, err := range []error{Check(dora, meta("draft"), Complete), (Flow{}).Check(dora, meta("draft"), Complete),
		CheckWithGate(dora, meta("draft"), Complete, config.Default())} {
		if err == nil || err.Error() != `unknown action "complete"` {
			t.Errorf("complete in standard: %v", err)
		}
	}
	for _, al := range AllowedActions(dora, meta("draft"), config.Default()) {
		if al.Action == string(Complete) {
			t.Error("standard allows complete")
		}
	}
	if slices.Contains(Actions, Complete) {
		t.Error("standard actions have complete")
	}
}

// Complete is gated like Approve, without the reviewer requirement.
func TestSimpleGateNoReviewer(t *testing.T) {
	cfg := simpleCfg()
	m := smeta("draft")
	if p := Gate(m, cfg); len(p) != 0 {
		t.Fatalf("a simple draft without reviewers: %v", p)
	}
	if p := strings.Join(Gate(m, config.Default()), ";"); !strings.Contains(p, "reviewer") {
		t.Errorf("standard without reviewers: %q", p)
	}
	m.Retest = &finding.Retest{Source: "old/F-001-x"}
	if p := strings.Join(Gate(m, cfg), ";"); p != "set the retest result (fixed, not fixed or partially fixed)" {
		t.Errorf("retest without a result: %q", p)
	}
	m = smeta("draft")
	m.Severity = ""
	if err := CheckWithGate(ben, m, Complete, cfg); err == nil || err.Error() != "cannot complete: set a CVSS vector or a severity" {
		t.Errorf("complete without severity: %v", err)
	}
	if err := CheckWithGate(ben, smeta("draft"), Complete, cfg); err != nil {
		t.Errorf("complete: %v", err)
	}
	// the flow comes from the config: the standard actions are refused
	if err := CheckWithGate(ben, smeta("draft"), Submit, cfg); err == nil || !strings.Contains(err.Error(), "not part of the simple workflow") {
		t.Errorf("submit in simple: %v", err)
	}
}

func TestSimpleAllowedActions(t *testing.T) {
	cfg := simpleCfg()
	names := func(as []Allowed) string {
		var out []string
		for _, a := range as {
			s := a.Action
			if !a.Enabled {
				s += "(off)"
			}
			if a.Needs != "" {
				s += "+" + a.Needs
			}
			out = append(out, s)
		}
		return strings.Join(out, ",")
	}
	cases := map[string]string{
		"draft":     "complete,withdraw+reason",
		"complete":  "reopen+reason,report,withdraw+reason",
		"reported":  "unreport+reason,withdraw+reason",
		"withdrawn": "revise",
	}
	for st, want := range cases {
		if got := names(AllowedActions(ben, smeta(st), cfg)); got != want {
			t.Errorf("%s: %s, want %s", st, got, want)
		}
	}
	m := smeta("draft")
	m.Title = ""
	al := AllowedActions(ben, m, cfg)
	if len(al) != 2 || al[0].Action != "complete" || al[0].Enabled || al[0].Reason != "cannot complete: the title is empty" {
		t.Errorf("gated complete: %+v", al)
	}
}

// Notifications, Ready to mark reported, Open threads on my findings, New
// on team board: the same for every account.
func TestSimpleQueues(t *testing.T) {
	want := []Inbox{InboxNotes, InboxReport, InboxThreads, InboxBoard}
	for _, u := range []config.User{anna, ben, {Username: "x", Role: "pentester"}} {
		if got := simple.Queues(u); !slices.Equal(got, want) {
			t.Errorf("%s: %v", u.Username, got)
		}
	}
	last := -1
	for _, q := range simple.Queues(ben) {
		i := slices.Index(QueueOrder, q)
		if i <= last {
			t.Errorf("%s out of order", q)
		}
		last = i
	}
	for _, u := range []config.User{alice, bob, dora} {
		if !slices.Equal((Flow{}).Queues(u), Queues(u)) {
			t.Errorf("standard queues of %s", u.Username)
		}
	}
	// a complete finding waits to be marked reported
	if Pending(ben, smeta("complete")) != InboxReport || Pending(ben, smeta("draft")) != InboxNone {
		t.Error("pending")
	}
}

func TestSimpleBulk(t *testing.T) {
	var acts []Action
	labels := map[string]bool{}
	for _, o := range simple.BulkOptions(ben) {
		acts = append(acts, o.Action)
		if labels[o.Label] {
			t.Errorf("two items labelled %q", o.Label)
		}
		labels[o.Label] = true
		if _, to := simple.Target(o.Action); o.To != to || to == "" {
			t.Errorf("%s leads to %q, target %q", o.Action, o.To, to)
		}
	}
	if !slices.Equal(acts, []Action{Complete, Report, Reopen, Unreport, Withdraw}) {
		t.Errorf("menu %v", acts)
	}
	byAct := map[Action]BulkOption{}
	for _, o := range simple.BulkOptions(anna) {
		byAct[o.Action] = o
	}
	// Complete has no verb: "Complete · complete" said the word twice (the
	// end-to-end check); Withdrawn has none either
	for a, want := range map[Action][2]string{Complete: {"Complete", ""}, Report: {"Reported", "mark reported"},
		Reopen: {"Draft", "revert"}, Unreport: {"Back to complete", "revert"}, Withdraw: {"Withdrawn", ""}} {
		if o := byAct[a]; o.Label != want[0] || o.Verb != want[1] {
			t.Errorf("%s: %+v", a, o)
		}
	}
	if simple.BulkAssign(anna) || simple.BulkAssign(ben) {
		t.Error("simple bulk assigns reviewers")
	}
	if !simple.BulkPick(ben, smeta("draft")) || !simple.BulkPick(anna, smeta("reported")) {
		t.Error("pick")
	}
	if !simple.BulkAllowed(ben, Complete) || simple.BulkAllowed(ben, Approve) || simple.BulkAllowed(ben, Revise) {
		t.Error("allowed")
	}
	for _, c := range []struct {
		m    finding.Meta
		a    Action
		want bool
	}{
		{smeta("draft"), Complete, true},
		{smeta("complete"), Complete, false},
		{smeta("complete"), Report, true},
		{smeta("complete"), Reopen, true},
		{smeta("reported"), Unreport, true},
		{smeta("complete"), Withdraw, true},
		{smeta("reported"), Withdraw, true},
		{smeta("withdrawn"), Revise, false},
	} {
		if err := simple.BulkCheck(ben, c.m, c.a); (err == nil) != c.want {
			t.Errorf("%s on %s: %v", c.a, c.m.Status, err)
		}
	}
	for _, a := range []Action{Submit, Return, Clear, Approve, TakeBack} {
		if err := simple.BulkCheck(ben, smeta("draft"), a); err == nil || !strings.Contains(err.Error(), "not part of the simple workflow") {
			t.Errorf("%s: %v", a, err)
		}
	}
	// the standard flow is the package-level menu
	for _, u := range []config.User{alice, bob, dora} {
		if !slices.Equal((Flow{}).BulkOptions(u), BulkOptions(u)) || (Flow{}).BulkAssign(u) != BulkAssign(u) {
			t.Errorf("standard bulk of %s", u.Username)
		}
	}
	if (Flow{}).BulkCheck(alice, meta("draft"), Submit) != nil || (Flow{}).BulkPick(pen2, meta("draft")) {
		t.Error("standard bulk check")
	}
}

func TestParseActionComplete(t *testing.T) {
	for _, in := range []string{"complete", " Complete "} {
		if a, ok := ParseAction(in); !ok || a != Complete {
			t.Errorf("ParseAction(%q) = %q, %v", in, a, ok)
		}
	}
	if Label(Complete) != "Complete" || NeedsReason(Complete) {
		t.Errorf("label %q, reason %v", Label(Complete), NeedsReason(Complete))
	}
}

func TestGatedComplete(t *testing.T) {
	if !Gated(Complete) || !Gated(Submit) || !Gated(Approve) || Gated(Report) || Gated(Clear) {
		t.Error("gated")
	}
}
