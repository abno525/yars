package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/cvss"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

// checkRow is one violation in the checks panel.
type checkRow struct {
	N                                  int // row number (ids of its reason form)
	Rule, Level, Message, Quote, Where string
	Target                             string // identifies it with Rule and Quote
	CanDismiss                         bool
	By, At, Reason                     string // dismissed rows: who, when and why
}

// stepRow is one rule of the latest run: its kind, how it went and how long
// it took (script and AI rules).
type stepRow struct {
	Rule, Kind, State, Label, Time string
	CanRetry, Fast                 bool // Fast: a pattern or built-in rule
}

type checksView struct {
	Enabled                                 bool
	URL, DismissURL, UndismissURL, RetryURL string
	// State of the latest run: "" (none), running, done, failed, invalid
	// (a script printed no JSON) or stale (the finding changed since).
	State, StateLabel, Error string
	Running                  bool
	ReadOnly                 bool // archived engagement: no Check, no Dismiss
	Done, Total              int  // rules done of the run's rules
	Progress                 string
	Steps, AIFailed          []stepRow // AI rules that failed are grouped
	AIHead                   string    // the AI provider and its time limit
	ConfigErrors             int       // rule files with problems
	Rows, Dismissed          []checkRow
	Errors, Warnings         int // rows not dismissed
	// Gate: the fast rules' errors that are not dismissed; they block
	// submit and approve like the store's gate.
	Gate []string
	OOB  bool // sent along with the workflow bar (out of band)
	// Empty: no result rows, open or dismissed; the panel is as high as
	// what it shows, like every other empty panel.
	Empty bool
	Open  bool // the strip starts open: a check is running, or the author's draft has errors
}

// kindTag is a rule kind's short tag on a step row.
var kindTag = map[string]string{"pattern": "Regex", "builtin": "Built-in", "script": "Script", "ai": "AI"}

// secs shows a duration like "0.8 s" or "12 s".
func secs(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 10*time.Second {
		return fmt.Sprintf("%.1f s", d.Seconds())
	}
	return fmt.Sprintf("%d s", int(d.Round(time.Second).Seconds()))
}

func parseStep(at string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, at)
	return t, err == nil && at != ""
}

// stepView describes a stored step for the panel.
func stepView(x db.CheckStep, level string, canRetry bool, now time.Time) stepRow {
	row := stepRow{Rule: x.Rule, Kind: kindTag[x.Kind], State: x.State, Fast: x.Kind == "pattern" || x.Kind == "builtin"}
	if row.Kind == "" {
		row.Kind = x.Kind
	}
	switch x.State {
	case db.StepQueued:
		row.Label = "Queued"
	case db.StepRunning:
		row.Label = "Running"
	case db.StepPass:
		row.Label = "Pass"
	case db.StepHits:
		if level == "" {
			level = "hit"
		}
		row.Label = plural(x.Hits, level)
	case db.StepFailed:
		row.Label, row.CanRetry = x.Message, canRetry
		if row.Label == "" {
			row.Label = "rule failed"
		}
	}
	if x.Kind == "script" || x.Kind == "ai" {
		st, ok := parseStep(x.Started)
		switch end, done := parseStep(x.Finished); {
		case ok && done:
			row.Time = secs(end.Sub(st))
		case ok && x.State == db.StepRunning:
			row.Time = secs(now.Sub(st))
		}
	}
	return row
}

var checkStateLabel = map[string]string{"running": "Running", "done": "Done", "failed": "Failed",
	"invalid": "Invalid output", "stale": "Stale"}

func (s *Server) routesChecks(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/checks", s.checksGet)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks", s.checksRun)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks/retry", s.checksRetry)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks/dismiss", s.checksDismiss(true))
	mux.HandleFunc("POST /e/{eng}/f/{fid}/checks/undismiss", s.checksDismiss(false))
}

// where names the part of the finding a violation is about.
func where(target string) string {
	if name, ok := strings.CutPrefix(target, "section:"); ok {
		return name
	}
	if name, ok := strings.CutPrefix(target, "details:"); ok {
		return name
	}
	return target
}

// checksFor builds the checks panel: the latest run's results (the fast
// rules' results now while none is finished), split into open and dismissed
// rows, with what the viewer may dismiss.
func (s *Server) checksFor(r *http.Request, ref store.FindingRef) checksView {
	base := findingURL(ref.EngID, ref.Dir) + "/checks"
	v := checksView{URL: base, DismissURL: base + "/dismiss", UndismissURL: base + "/undismiss", RetryURL: base + "/retry"}
	if s.Rules == nil {
		return v
	}
	v.Enabled = true
	set := s.Rules.Rules()
	for _, pr := range set.Problems {
		if pr.Level == "error" {
			v.ConfigErrors++
		}
	}
	u := auth.UserFrom(r.Context())
	items := s.Rules.Lint(r.Context(), ref.F, rules.Fast)
	st, err := s.Store.CheckStatus(ref.EngID, ref.Dir)
	if err != nil && !errors.Is(err, store.ErrNoDB) {
		v.State, v.Error = "failed", err.Error()
	}
	ds := st.Dismissed
	dismissed := func(it rules.Violation) (db.Dismissal, bool) {
		return db.Lookup(ds, it.Rule, it.Target, it.Quote)
	}
	gated := map[string]bool{} // one line per result row, as the panel lists them
	for _, it := range items {
		k := it.Rule + "\x00" + db.ViolationHash(it.Target, it.Quote)
		if _, ok := dismissed(it); !ok && it.Level == "error" && !gated[k] {
			gated[k] = true
			v.Gate = append(v.Gate, it.Message)
		}
	}
	if st.HasRun {
		v.Error = st.Run.Error
		switch {
		case st.Running:
			v.State, v.Running = "running", true
		case st.Stale:
			v.State = "stale"
		case st.Run.State == db.RunFailed && st.Run.Error == rules.InvalidOutput:
			v.State = "invalid"
		default:
			v.State = st.Run.State
		}
	}
	// D3: the rows are what the store's open checks read, so the strip, the
	// bar and the gate count alike: the fast rules now and the results stored
	// for this content (a run in progress, out of date or cut off adds
	// nothing of its own)
	if s.Store.Linter != nil {
		listed, err := s.Store.CheckItems(ref.EngID, ref.Dir)
		switch {
		case err == nil:
			items = listed
		case !errors.Is(err, store.ErrNoDB):
			v.State, v.Error = "failed", err.Error()
		}
	}
	v.StateLabel = checkStateLabel[v.State]
	v.ReadOnly = s.Store.Archived(ref.EngID)
	if st.HasRun {
		v.Done, v.Total = st.Run.Done, st.Run.Total
		now := time.Now()
		if len(st.Steps) > 0 {
			v.Done, v.Total = 0, len(st.Steps)
		}
		for _, x := range st.Steps {
			if x.State != db.StepQueued && x.State != db.StepRunning {
				v.Done++
			}
			level := ""
			if rl, ok := s.Rules.Rule(x.Rule); ok {
				level = rl.Level
			}
			row := stepView(x, level, !v.ReadOnly && !st.Running && !st.Stale, now)
			if x.Kind == "ai" && x.State == db.StepFailed {
				v.AIFailed = append(v.AIFailed, row)
				continue
			}
			v.Steps = append(v.Steps, row)
		}
		v.Progress = fmt.Sprintf("%d of %d · %s", v.Done, v.Total, clock(st.Run.Started))
		if len(v.AIFailed) > 0 {
			v.AIHead = s.aiHead()
		}
	}
	stepped := map[string]bool{}
	for _, x := range st.Steps {
		stepped[x.Rule] = true
	}
	seen := map[string]bool{} // rule, place and quote: one row each (D18)
	for n, it := range items {
		notice := it.Target == "rules" || it.Target == "ai"
		if notice && stepped[it.Rule] {
			continue // its rule's step says it (AI checks failed)
		}
		k := it.Rule + "\x00" + it.Level + "\x00" + db.ViolationHash(it.Target, it.Quote)
		if seen[k] {
			continue
		}
		seen[k] = true
		row := checkRow{N: n, Rule: it.Rule, Level: it.Level, Message: it.Message, Quote: it.Quote, Where: where(it.Target), Target: it.Target}
		if d, ok := dismissed(it); ok && !notice {
			row.By, row.At, row.Reason = d.By, stamp(d.At), d.Reason
			row.CanDismiss = !v.ReadOnly && store.CanDismiss(u, ref.F.Meta, d.Level)
			v.Dismissed = append(v.Dismissed, row)
			continue
		}
		row.CanDismiss = !v.ReadOnly && !notice && store.CanDismiss(u, ref.F.Meta, it.Level)
		switch {
		case notice && it.Level != "error": // listed, not counted: the gate does not count it
		case it.Level == "error": // a broken rule file's too: Submit refuses it
			v.Errors++
		default:
			v.Warnings++
		}
		v.Rows = append(v.Rows, row)
	}
	gate := s.gateRows(ref.F.Meta, set, v.Rows) // first, and counted
	v.Errors += len(gate)
	v.Rows = append(gate, v.Rows...)
	v.Empty = len(v.Rows) == 0 && len(v.Dismissed) == 0
	m := ref.F.Meta
	v.Open = v.Running || (m.Status == "draft" && u.Username == m.Author && v.Errors > 0)
	return v
}

// gateRule names the strip's rows that are the workflow gate's problems
// (their title; they have no Dismiss).
const gateRule = "workflow"

// gateRows are what the workflow gate asks for, as rows of the strip, for a
// draft or a finding in verification (D3). An unexplained CVSS value is left
// to a cvss-explained rule only while that rule's open error names the same
// metric (a warning or a dismissed row does not stand for the gate's error).
func (s *Server) gateRows(m finding.Meta, set *rules.Set, rows []checkRow) []checkRow {
	if m.Status != "draft" && m.Status != "verification" {
		return nil
	}
	cvssRule := map[string]bool{}
	for _, r := range set.Rules {
		if r.On() && r.Check == "cvss-explained" {
			cvssRule[r.ID] = true
		}
	}
	said := map[string]bool{} // metric keys ("AC") an open cvss-explained error names
	for _, r := range rows {
		if key, _, ok := strings.Cut(r.Quote, ":"); ok && cvssRule[r.Rule] && r.Level == "error" {
			said[key] = true
		}
	}
	var out []checkRow
	for _, p := range workflow.Gate(m, s.conf()) {
		if name, ok := strings.CutPrefix(p, "explain the non-standard CVSS value for "); ok {
			if i := slices.IndexFunc(cvss.Metrics, func(mt cvss.Metric) bool { return mt.Name == name }); i >= 0 && said[cvss.Metrics[i].Key] {
				continue
			}
		}
		out = append(out, checkRow{Level: "error", Rule: gateRule, Message: p, Where: "Workflow"})
	}
	return out
}

// stamp shows a stored RFC 3339 time like the chat does.
func stamp(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return t.Local().Format("2006-01-02 15:04")
}

// clock shows a stored RFC 3339 time as HH:MM, local.
func clock(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return ""
	}
	return t.Local().Format("15:04")
}

// aiHead names the AI provider in use and its time limit ("anthropic · 60 s").
func (s *Server) aiHead() string {
	rn, ok := s.Rules.Runner.(*rules.Runner)
	if !ok {
		return ""
	}
	c, _, _ := rn.Effective()
	p := c.Provider
	if p == "" {
		p = "no provider"
	}
	return p + " · " + secs(rn.AITimeout)
}

// checksGet answers the checks panel alone (live refreshes).
func (s *Server) checksGet(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref))
}

// checksRun starts a run of every rule kind (scripts and AI included) in
// the background and answers the panel, running.
func (s *Server) checksRun(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if s.Rules == nil {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Store.StartCheck(ref.EngID, ref.Dir, auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	s.checksStarted(w, r, ref)
}

// checksStarted answers a started run: the workflow bar (its Check button
// shows the progress) with the checks panel out of band.
func (s *Server) checksStarted(w http.ResponseWriter, r *http.Request, ref store.FindingRef) {
	wf, checks := s.wfGated(r, ref)
	// both fetch themselves again once in the page (load): check events
	// sent before this answer was swapped in are not lost
	checks.OOB, wf.Refetch = true, true
	s.exec(w, "finding.html", "check_started", struct {
		WF     wfView
		Checks checksView
	}{wf, checks})
}

// checksRetry runs one rule of the latest run again.
func (s *Server) checksRetry(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if s.Rules == nil {
		http.NotFound(w, r)
		return
	}
	_, err := s.Store.RetryCheck(ref.EngID, ref.Dir, r.FormValue("rule"), auth.UserFrom(r.Context()))
	if errors.Is(err, store.ErrInvalidValue) {
		http.Error(w, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.checksStarted(w, r, ref)
}

// checksDismiss dismisses (on) or restores the violation (rule, quote) and
// answers the panel.
func (s *Server) checksDismiss(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ref, ok := s.cvssRef(w, r)
		if !ok {
			return
		}
		u := auth.UserFrom(r.Context())
		rule, target, quote := r.FormValue("rule"), r.FormValue("target"), r.FormValue("quote")
		var err error
		if on {
			reason := strings.TrimSpace(r.FormValue("reason"))
			if reason == "" {
				http.Error(w, "Reason is required", http.StatusBadRequest)
				return
			}
			err = s.Store.DismissWhy(ref.EngID, ref.Dir, rule, target, quote, reason, u)
		} else {
			err = s.Store.Undismiss(ref.EngID, ref.Dir, rule, target, quote, u)
		}
		if errors.Is(err, store.ErrInvalidValue) {
			http.Error(w, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "), http.StatusBadRequest)
			return
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		s.exec(w, "finding.html", "checks_panel", s.checksFor(r, ref))
	}
}
