package store

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// blocking lists what blocks act on the finding (content hash): Submit and
// Approve run every rule now (scripts and AI too: no check run may have
// covered the content) and are blocked by its undismissed errors; Sign off
// and Approve are blocked by every open check, warnings too (OpenChecks,
// the source the page and Ready to approve show). With Require Check on,
// Sign off and Approve first need a finished run on this content
// (checkGate), and Approve runs nothing inline: the run is the source. The
// rules run for u on the finding (their AI calls are recorded so, D24).
func (s *Store) blocking(act workflow.Action, ref FindingRef, hash string, u config.User) ([]string, error) {
	var out []string
	gate := SignsOff(act) && s.gating()
	if gate {
		// Require Check: the stored run is the source, nothing runs inline
		g, err := s.checkGate(ref.EngID, ref.F.Meta.ID, hash)
		if err != nil {
			return nil, err
		}
		if g != "" {
			out = append(out, g)
		}
	}
	if act == workflow.Submit || (act == workflow.Approve && !gate) {
		ctx := rules.WithCaller(context.Background(), rules.Caller{User: u.Username, Eng: ref.EngID, Fid: ref.F.Meta.ID})
		vs, err := s.undismissed(ref.EngID, ref.F.Meta.ID, s.Linter.Lint(ctx, ref.F, rules.All))
		if err != nil {
			return nil, err
		}
		for _, msg := range rules.Errors(vs) {
			if !slices.Contains(out, msg) { // a rule may find a quote twice
				out = append(out, msg)
			}
		}
	}
	if SignsOff(act) {
		open, err := s.openChecks(ref, hash)
		if err != nil {
			return nil, err
		}
		for _, v := range open {
			msg := v.Message
			if v.Level == "warning" {
				msg += " (warning)"
			}
			if !slices.Contains(out, msg) {
				out = append(out, msg)
			}
		}
	}
	return out, nil
}

// OpenChecks lists the finding's open (undismissed) check errors and
// warnings, notices about the rules left out: the fast rules run now, plus
// the results of the latest check run that finished on the current content
// (a run in progress does not hide it; script and AI rules are never run
// here). It is the one source of
// "open checks" for the Sign off and Approve gate, the finding page and
// Ready to approve.
func (s *Store) OpenChecks(engID, dir string) ([]rules.Violation, error) {
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return nil, err
	}
	return s.openChecks(ref, contentHash(raw))
}

func (s *Store) openChecks(ref FindingRef, hash string) ([]rules.Violation, error) {
	if s.Linter == nil {
		return nil, nil
	}
	fid := ref.F.Meta.ID
	type keyed struct {
		v   rules.Violation
		key string
	}
	var all []keyed
	seen := map[string]bool{}
	add := func(v rules.Violation, qh string) {
		if notice(v) || (v.Level != "error" && v.Level != "warning") {
			return
		}
		k := db.DismissKey(v.Rule, qh)
		if seen[k+"\x00"+v.Target] {
			return
		}
		seen[k+"\x00"+v.Target] = true
		all = append(all, keyed{v, k})
	}
	for _, v := range s.Linter.Lint(context.Background(), ref.F, rules.Fast) {
		add(v, ViolationHash(v.Target, v.Quote))
	}
	ds := map[string]db.Dismissal{}
	if s.db != nil {
		if err := s.storedChecks(ref.EngID, fid, hash, add); err != nil {
			return nil, err
		}
		var err error
		if ds, err = s.db.Dismissals(ref.EngID, fid); err != nil {
			return nil, err
		}
	}
	var out []rules.Violation
	for _, x := range all {
		_, own := ds[x.key]
		if !own && !dismissedRow(ds, x.v) {
			out = append(out, x.v)
		}
	}
	return out, nil
}

// CheckItems lists what the finding page's Checks strip shows for the
// finding as it is now, from the source OpenChecks reads: the fast rules run
// now (their notices too: a broken rule file) and the results stored for the
// current content (storedChecks, which leaves out a rule that failed), with
// dismissed ones kept (the strip lists them apart). A run in progress, out
// of date or cut off adds nothing of its own.
func (s *Store) CheckItems(engID, dir string) ([]rules.Violation, error) {
	if s.Linter == nil {
		return nil, nil
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return nil, err
	}
	var out []rules.Violation
	seen := map[string]bool{}
	add := func(v rules.Violation, qh string) {
		if k := db.DismissKey(v.Rule, qh) + "\x00" + v.Target; !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	for _, v := range s.Linter.Lint(context.Background(), ref.F, rules.Fast) {
		add(v, ViolationHash(v.Target, v.Quote))
	}
	if s.db != nil {
		if err := s.storedChecks(engID, ref.F.Meta.ID, contentHash(raw), add); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// storedChecks hands add the results stored for the finding's content: the
// latest finished run's, and for each rule that failed in it (a step that
// failed, or a notice about the rules: the AI was down, say) the results of
// the newest earlier run on the same content where that rule did run. A
// failed rule says nothing about its earlier violations, as in finishCheck.
func (s *Store) storedChecks(eng, fid, hash string, add func(rules.Violation, string)) error {
	runs, err := s.db.FinishedRuns(eng, fid, hash, 20)
	if err != nil {
		return err
	}
	var wanted map[string]bool // nil: every rule (the latest run)
	for _, run := range runs {
		res, err := s.db.RunResults(run.ID)
		if err != nil {
			return err
		}
		steps, err := s.db.RunSteps(run.ID)
		if err != nil {
			return err
		}
		failed := map[string]bool{}
		for _, x := range steps {
			if x.State == db.StepFailed {
				failed[x.Rule] = true
			}
		}
		for _, r := range res {
			if r.Target == "rules" || r.Target == "ai" {
				failed[r.Rule] = true
			}
		}
		for _, r := range res {
			if failed[r.Rule] || (wanted != nil && !wanted[r.Rule]) {
				continue
			}
			add(rules.Violation{Rule: r.Rule, Level: r.Level, Message: r.Message, Target: r.Target, Quote: r.Quote}, r.QuoteHash)
		}
		if wanted == nil {
			wanted = failed
		} else {
			for rule := range wanted {
				if !failed[rule] {
					delete(wanted, rule)
				}
			}
		}
		if len(wanted) == 0 {
			break
		}
	}
	return nil
}

// Dismissals returns the dismissed violations of finding fid.
func (s *Store) Dismissals(engID, fid string) (map[string]db.Dismissal, error) {
	if s.db == nil {
		return map[string]db.Dismissal{}, nil
	}
	return s.db.Dismissals(engID, fid)
}

// lintFidRe is a finding id (F-001, F-1000).
var lintFidRe = regexp.MustCompile(`^F-[0-9]{3,6}$`)

// LintContent checks raw (a finding.md as it would be committed to
// engagement engID) with every rule, as a check run does, and returns the
// violations that are not dismissed on that finding. Nothing is stored. A
// file that does not parse is ErrInvalidValue with the parser's message; an
// unknown engagement is ErrNotFound. The rules' AI calls are recorded under
// the caller ctx carries and this finding (D24).
func (s *Store) LintContent(ctx context.Context, engID string, raw []byte) ([]rules.Violation, error) {
	f, err := finding.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
	}
	if _, err := s.Engagement(engID); err != nil {
		return nil, err
	}
	if s.Linter == nil {
		return []rules.Violation{}, nil
	}
	// the finding as Check sees it (read): the title cleaned, the server's
	// workflow state applied (the file never holds it)
	f.Meta.Title = CleanTitle(f.Meta.Title)
	st := db.State{Status: "draft"}
	if s.db != nil {
		if st, err = s.db.State(engID, f.Meta.ID); err != nil {
			return nil, err
		}
	}
	applyState(&f.Meta, st, contentHash(raw))
	c := rules.CallerOf(ctx)
	c.Eng, c.Fid = engID, ""
	if lintFidRe.MatchString(f.Meta.ID) {
		c.Fid = f.Meta.ID // only a finding id is recorded (the text is the poster's)
	}
	vs, err := s.undismissed(engID, f.Meta.ID, s.Linter.Lint(rules.WithCaller(ctx, c), f, rules.All))
	if vs == nil {
		vs = []rules.Violation{}
	}
	return vs, err
}

// undismissed drops the violations dismissed on finding fid.
func (s *Store) undismissed(engID, fid string, vs []rules.Violation) ([]rules.Violation, error) {
	ds, err := s.Dismissals(engID, fid)
	if err != nil || len(ds) == 0 {
		return vs, err
	}
	var out []rules.Violation
	for _, v := range vs {
		if _, ok := db.Lookup(ds, v.Rule, v.Target, v.Quote); !ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// CheckStatus returns the finding's latest check run with its results and
// dismissals. A run left "running" by an earlier server is failed here
// ("interrupted").
func (s *Store) CheckStatus(engID, dir string) (CheckStatus, error) {
	if s.db == nil {
		return CheckStatus{}, ErrNoDB
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return CheckStatus{}, err
	}
	fid := ref.F.Meta.ID
	st := CheckStatus{Ref: ref}
	s.checksMu.Lock()
	st.Run, st.HasRun, err = s.db.LatestRun(engID, fid)
	if err == nil && st.HasRun && st.Run.State == db.RunRunning {
		if s.inProgress(checkKey(engID, fid), st.Run.ID) {
			st.Running = true
		} else if err = s.db.FailRun(st.Run.ID, "interrupted"); err == nil {
			st.Run, err = s.db.Run(st.Run.ID)
		}
	}
	s.checksMu.Unlock()
	if err != nil {
		return st, err
	}
	if st.HasRun {
		// stale: the finding, or the rules (Q13), changed since the run
		st.Stale = st.Run.ContentHash != contentHash(raw) || RulesChanged(st.Run.Rules, s.RulesVersion())
		if st.Steps, err = s.db.RunSteps(st.Run.ID); err != nil {
			return st, err
		}
		if !st.Running {
			if st.Results, err = s.db.RunResults(st.Run.ID); err != nil {
				return st, err
			}
		}
	}
	st.Dismissed, err = s.db.Dismissals(engID, fid)
	return st, err
}

// violationLevel finds the level of the finding's violation (rule, quote)
// in its latest run or among the fast rules now ("" = no such violation).
func (s *Store) violationLevel(ref FindingRef, rule, qh string) (string, error) {
	level := ""
	note := func(l string) {
		if level != "error" {
			level = l
		}
	}
	run, ok, err := s.db.LatestRun(ref.EngID, ref.F.Meta.ID)
	if err != nil {
		return "", err
	}
	if ok {
		res, err := s.db.RunResults(run.ID)
		if err != nil {
			return "", err
		}
		for _, r := range res {
			if r.Rule == rule && r.QuoteHash == qh && r.Target != "rules" && r.Target != "ai" {
				note(r.Level)
			}
		}
	}
	if s.Linter != nil {
		for _, v := range s.Linter.Lint(context.Background(), ref.F, rules.Fast) {
			if v.Rule == rule && ViolationHash(v.Target, v.Quote) == qh && !notice(v) {
				note(v.Level)
			}
		}
	}
	return level, nil
}

// placeOf finds where the finding's violation (rule, quote) is when the
// caller did not say: the one target its latest run or the fast rules now
// have it in. In several places the caller must name one (a dismissal
// covers one result row).
func (s *Store) placeOf(ref FindingRef, rule, quote string) (string, error) {
	var places []string
	note := func(target string) {
		if target != "rules" && target != "ai" && !slices.Contains(places, target) {
			places = append(places, target)
		}
	}
	run, ok, err := s.db.LatestRun(ref.EngID, ref.F.Meta.ID)
	if err != nil {
		return "", err
	}
	if ok {
		res, err := s.db.RunResults(run.ID)
		if err != nil {
			return "", err
		}
		for _, r := range res {
			if r.Rule == rule && r.Quote == quote {
				note(r.Target)
			}
		}
	}
	if s.Linter != nil {
		for _, v := range s.Linter.Lint(context.Background(), ref.F, rules.Fast) {
			if v.Rule == rule && v.Quote == quote {
				note(v.Target)
			}
		}
	}
	switch len(places) {
	case 0:
		return "", nil
	case 1:
		return places[0], nil
	}
	return "", fmt.Errorf("%w: %s finds that quote in %s; name the place", ErrInvalidValue, rule, strings.Join(places, ", "))
}
