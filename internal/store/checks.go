package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// CheckUser is the author of the chat threads and events check runs write.
const CheckUser = "yars"

// EventCheckFixed is the chat event earlier versions wrote when a run no
// longer found a violation; runs now resolve its thread silently, and the
// event is kept only to show old chats.
const EventCheckFixed = "check_fixed"

// Checker is a Linter that also reports progress over a full run.
type Checker interface {
	Check(ctx context.Context, f *finding.Finding, progress func(done, total int)) []rules.Violation
}

// StepChecker is a Checker that also runs rule by rule: the rules a run
// has, and a run (or one rule alone) telling hooks about each rule.
type StepChecker interface {
	CheckRules() []rules.Rule
	CheckWith(ctx context.Context, f *finding.Finding, h rules.Hooks) []rules.Violation
}

// CheckStatus is a finding's latest check run as seen now.
type CheckStatus struct {
	Ref       FindingRef
	Run       db.CheckRun
	HasRun    bool
	Running   bool // in progress in this server
	Stale     bool // the finding changed since the run started
	Results   []db.CheckResult
	Steps     []db.CheckStep          // each rule of the run, in order
	Dismissed map[string]db.Dismissal // by db.DismissKey
}

// QuoteHash identifies a violation's quote for dismissals and comments.
func QuoteHash(quote string) string { return BodyHash(quote) }

// ViolationHash identifies a violation of a rule for dismissals and
// comments: its quote, or where it is when it has none (an empty section),
// so that one dismissal covers one place only.
func ViolationHash(target, quote string) string {
	if quote == "" {
		return BodyHash("\x00" + target)
	}
	return QuoteHash(quote)
}

// CanDismiss reports whether u may dismiss (or restore) a violation of the
// given level on a finding: warnings need edit rights, errors also the
// reviewer role or more.
func CanDismiss(u config.User, m finding.Meta, level string) bool {
	if !workflow.CanEdit(u, m) {
		return false
	}
	return level != "error" || workflow.AtLeast(u, "reviewer")
}

func checkKey(eng, fid string) string { return eng + "/" + fid }

// notice reports a violation about the rules themselves (a broken rule
// file, a rule that could not run, AI not configured): stored with the run
// but never posted as a comment.
func notice(v rules.Violation) bool { return v.Target == "rules" || v.Target == "ai" }

// Dismissals returns the dismissed violations of finding fid.
func (s *Store) Dismissals(engID, fid string) (map[string]db.Dismissal, error) {
	if s.db == nil {
		return map[string]db.Dismissal{}, nil
	}
	return s.db.Dismissals(engID, fid)
}

// undismissed drops the violations dismissed on finding fid.
func (s *Store) undismissed(engID, fid string, vs []rules.Violation) ([]rules.Violation, error) {
	ds, err := s.Dismissals(engID, fid)
	if err != nil || len(ds) == 0 {
		return vs, err
	}
	var out []rules.Violation
	for _, v := range vs {
		if _, ok := ds[db.DismissKey(v.Rule, ViolationHash(v.Target, v.Quote))]; !ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// StartCheck starts a run of every rule (fast, script, AI) on the finding in
// the background, as u, and returns it. While a run of the finding is in
// progress, that run is returned instead. Progress is announced as
// ChangeCheck; at the end the results are stored and each new violation is
// posted as a chat thread (see finishCheck).
func (s *Store) StartCheck(engID, dir string, u config.User) (db.CheckRun, error) {
	return s.startCheck(engID, dir, "", u)
}

// RetryCheck runs one rule of the finding's latest run again (a rule that
// failed, say) as a new run: the other rules keep their steps and results.
// When the finding changed since that run, every rule runs.
func (s *Store) RetryCheck(engID, dir, rule string, u config.User) (db.CheckRun, error) {
	if rule == "" {
		return db.CheckRun{}, fmt.Errorf("%w: no rule", ErrInvalidValue)
	}
	return s.startCheck(engID, dir, rule, u)
}

// carried is what a retry keeps from the run before it.
type carried struct {
	results []db.CheckResult
	steps   map[string]db.CheckStep
}

func (s *Store) startCheck(engID, dir, only string, u config.User) (db.CheckRun, error) {
	if s.db == nil {
		return db.CheckRun{}, ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return db.CheckRun{}, err
	}
	if s.Linter == nil {
		return db.CheckRun{}, fmt.Errorf("%w: no rules configured", ErrInvalidValue)
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return db.CheckRun{}, err
	}
	fid := ref.F.Meta.ID
	key := checkKey(engID, fid)
	hash := contentHash(raw)
	sc, stepped := s.Linter.(StepChecker)
	var ruleList []rules.Rule
	if stepped {
		ruleList = sc.CheckRules()
	}
	if only != "" && !slices.ContainsFunc(ruleList, func(r rules.Rule) bool { return r.ID == only }) {
		return db.CheckRun{}, fmt.Errorf("%w: no rule %s to run", ErrInvalidValue, only)
	}
	s.checksMu.Lock()
	if id, ok := s.running[key]; ok {
		s.checksMu.Unlock()
		return s.db.Run(id)
	}
	var keep *carried
	if only != "" {
		prev, ok, err := s.db.LatestRun(engID, fid)
		if err == nil && ok && prev.State != db.RunRunning && prev.ContentHash == hash {
			keep, err = s.carry(prev.ID, only)
		}
		if err != nil {
			s.checksMu.Unlock()
			return db.CheckRun{}, err
		}
		if keep == nil {
			only = "" // nothing to keep: run everything
		}
	}
	id, err := s.db.StartRun(engID, fid, hash, u.Username)
	if err != nil {
		s.checksMu.Unlock()
		return db.CheckRun{}, err
	}
	if stepped {
		var steps []db.CheckStep
		for i, r := range ruleList {
			x := db.CheckStep{RunID: id, Pos: i, Rule: r.ID, Kind: r.KindName(), State: db.StepQueued}
			if old, ok := keep.step(r.ID); ok && r.ID != only {
				x.State, x.Started, x.Finished, x.Hits, x.Message, x.Fail = old.State, old.Started, old.Finished, old.Hits, old.Message, old.Fail
			}
			steps = append(steps, x)
		}
		s.db.AddSteps(steps)
	}
	total := 1
	if only == "" {
		if c, ok := s.Linter.(interface{ RuleCount() int }); ok {
			total = c.RuleCount()
		}
	}
	s.db.RunProgress(id, 0, total) // "0/6" from the start
	if s.running == nil {
		s.running = map[string]int64{}
	}
	s.running[key] = id
	s.checkWG.Add(1)
	s.checksMu.Unlock()
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	go s.runCheck(id, ref, only, keep)
	return s.db.Run(id)
}

// carry reads what a retry of rule keeps from run prev: the other rules'
// results and every step.
func (s *Store) carry(prev int64, rule string) (*carried, error) {
	res, err := s.db.RunResults(prev)
	if err != nil {
		return nil, err
	}
	steps, err := s.db.RunSteps(prev)
	if err != nil {
		return nil, err
	}
	c := &carried{steps: map[string]db.CheckStep{}}
	for _, x := range steps {
		c.steps[x.Rule] = x
	}
	for _, r := range res {
		if r.Rule != rule {
			c.results = append(c.results, r)
		}
	}
	return c, nil
}

func (c *carried) step(rule string) (db.CheckStep, bool) {
	if c == nil {
		return db.CheckStep{}, false
	}
	x, ok := c.steps[rule]
	return x, ok
}

// violations turns the kept results back into what a run found; a rule
// that had failed fails again, so its open threads stay open.
func (c *carried) violations() []rules.Violation {
	if c == nil {
		return nil
	}
	var out []rules.Violation
	for _, r := range c.results {
		v := rules.Violation{Rule: r.Rule, Level: r.Level, Message: r.Message, Target: r.Target, Quote: r.Quote}
		if x := c.steps[r.Rule]; x.State == db.StepFailed && r.Target == "rules" {
			v.Fail = x.Fail
		}
		out = append(out, v)
	}
	return out
}

// stepOutcome is how a rule ended, from what it reported.
func stepOutcome(run int64, r rules.Rule, vs []rules.Violation) db.CheckStep {
	x := db.CheckStep{RunID: run, Rule: r.ID, State: db.StepPass, Finished: db.StepStamp(time.Now())}
	for _, v := range vs {
		switch {
		case v.Fail != "":
			x.State, x.Message, x.Fail = db.StepFailed, v.Message, v.Fail
		case notice(v):
			if x.State != db.StepFailed {
				x.State, x.Message = db.StepFailed, v.Message
			}
		default:
			x.Hits++
		}
	}
	if x.State == db.StepPass && x.Hits > 0 {
		x.State = db.StepHits
	}
	return x
}

// WaitChecks waits until no check run is in progress.
func (s *Store) WaitChecks() { s.checkWG.Wait() }

func (s *Store) runCheck(id int64, ref FindingRef, only string, keep *carried) {
	eng, fid := ref.EngID, ref.F.Meta.ID
	defer s.checkWG.Done()
	defer func() {
		if p := recover(); p != nil {
			s.db.FailRun(id, fmt.Sprint("crashed: ", p))
		}
		s.checksMu.Lock()
		delete(s.running, checkKey(eng, fid))
		s.checksMu.Unlock()
		s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeCheck})
		s.emitCheck(id, ref)
	}()
	progress := func(done, total int) {
		if s.db.RunProgress(id, done, total) == nil {
			s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeCheck})
		}
	}
	var vs []rules.Violation
	if c, ok := s.Linter.(StepChecker); ok {
		vs = c.CheckWith(context.Background(), ref.F, rules.Hooks{
			Only:     only,
			Progress: progress,
			Start: func(r rules.Rule) {
				if s.db.StepStarted(id, r.ID, time.Now()) == nil {
					s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeCheck})
				}
			},
			Done: func(r rules.Rule, got []rules.Violation) { s.db.StepDone(stepOutcome(id, r, got)) },
		})
		vs = append(keep.violations(), vs...)
	} else if c, ok := s.Linter.(Checker); ok {
		vs = c.Check(context.Background(), ref.F, progress)
	} else {
		progress(0, 1)
		vs = s.Linter.Lint(context.Background(), ref.F, rules.All)
		progress(1, 1)
	}
	seq, err := s.db.TxForSeq(eng, func(tx *db.Tx) error { return finishCheck(tx, id, eng, fid, vs) })
	if err != nil {
		s.db.FailRun(id, err.Error())
		return
	}
	s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeChat, Seq: seq})
}

// emitCheck tells the subscribers that run id of ref ended, with its counts.
func (s *Store) emitCheck(id int64, ref FindingRef) {
	run, err := s.db.Run(id)
	if err != nil {
		return
	}
	ev := findingEvent(EventCheck, run.By, ref)
	ev.State = run.State
	dis, _ := s.db.Dismissals(ref.EngID, ref.F.Meta.ID)
	if res, err := s.db.RunResults(id); err == nil {
		for _, r := range res {
			if _, ok := dis[db.DismissKey(r.Rule, r.QuoteHash)]; ok {
				continue
			}
			switch r.Level {
			case "error":
				ev.Errors++
			case "warning":
				ev.Warnings++
			}
		}
	}
	s.Emit(ev)
}

// checkText is the comment for a violation: its message and the quote.
func checkText(v rules.Violation) string {
	q := strings.Join(strings.Fields(v.Quote), " ")
	if q == "" {
		return v.Message
	}
	return v.Message + "\n\n> " + q
}

func sectionOf(target string) string {
	if name, ok := strings.CutPrefix(target, "section:"); ok {
		return name
	}
	return ""
}

// threadKey identifies a violation's thread: rule, quote hash and section.
func threadKey(rule, quoteHash, section string) string {
	return db.DismissKey(rule, quoteHash) + "\x00" + section
}

// knownThreads maps each violation (threadKey) of the finding to the chat
// thread the latest run that had one gave it; threads no longer in the chat
// are left out.
func knownThreads(tx *db.Tx, eng, fid string, threads map[string]*chat.Thread) (map[string]string, error) {
	refs, err := tx.CheckThreadRefs(eng, fid)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range refs {
		if t := threads[r.Thread]; t != nil {
			out[threadKey(r.Rule, r.QuoteHash, t.Root.Section)] = r.Thread
		}
	}
	return out, nil
}

// finishCheck stores the results of run id and keeps the chat in step. Only
// a new violation adds anything visible to the chat:
//   - a violation without a thread of its own (same rule, quote and section)
//     gets a new one (kind check, by CheckUser, on its section);
//   - one whose thread is still open keeps it, and nothing is posted; one
//     whose thread someone resolved although it is still there gets it
//     reopened (a reopen marker, no comment);
//   - a dismissed violation gets no comment;
//   - an open thread whose violation is gone is resolved silently (a resolve
//     marker only; not for a rule that failed to run or only reported a
//     notice).
//
// The run fails when a rule could not run (Fail; "invalid output" for a
// script that printed something other than JSON).
func finishCheck(tx *db.Tx, id int64, eng, fid string, vs []rules.Violation) error {
	state, reason := db.RunDone, ""
	failedRules := map[string]bool{}
	for _, v := range vs {
		// a rule that only reported a notice (AI down, budget spent) says
		// nothing about its earlier violations: keep their threads
		if notice(v) {
			failedRules[v.Rule] = true
		}
		if v.Fail != "" {
			failedRules[v.Rule] = true
			if reason == "" {
				state, reason = db.RunFailed, v.Fail
			}
		}
	}
	msgs, err := tx.Messages(eng, fid)
	if err != nil {
		return err
	}
	threads := map[string]*chat.Thread{}
	for _, it := range chat.Timeline(msgs) {
		if it.Thread != nil {
			threads[it.Thread.Root.ID] = it.Thread
		}
	}
	known, err := knownThreads(tx, eng, fid, threads)
	if err != nil {
		return err
	}
	dismissed, err := tx.Dismissals(eng, fid)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	add := func(m chat.Message) error {
		m.ID, m.TS, m.User = chat.NewID(), now, CheckUser
		return tx.AddMessage(eng, fid, m)
	}
	found := map[string]string{} // threadKey -> thread given in this run
	results := make([]db.CheckResult, 0, len(vs))
	for _, v := range vs {
		r := db.CheckResult{Rule: v.Rule, Level: v.Level, Message: v.Message, Target: v.Target, Quote: v.Quote, QuoteHash: ViolationHash(v.Target, v.Quote)}
		k := threadKey(r.Rule, r.QuoteHash, sectionOf(v.Target))
		switch th, seen := found[k]; {
		case notice(v):
		case seen:
			r.Thread = th
		case dismissed[db.DismissKey(r.Rule, r.QuoteHash)].By != "":
			found[k] = known[k]
			r.Thread = known[k]
		default:
			if t := threads[known[k]]; t != nil {
				if t.Resolved {
					if err := add(chat.Message{Reopens: t.Root.ID}); err != nil {
						return err
					}
				}
				r.Thread = t.Root.ID
			} else {
				m := chat.Message{Kind: chat.KindCheck, Section: sectionOf(v.Target), Text: checkText(v)}
				m.ID, m.TS, m.User = chat.NewID(), now, CheckUser
				if err := tx.AddMessage(eng, fid, m); err != nil {
					return err
				}
				r.Thread = m.ID
			}
			found[k] = r.Thread
		}
		results = append(results, r)
	}
	for k, th := range known {
		rule, _, _ := strings.Cut(k, "\x00")
		t := threads[th]
		if _, still := found[k]; still || failedRules[rule] || t == nil || t.Resolved {
			continue
		}
		if err := add(chat.Message{Resolves: th}); err != nil {
			return err
		}
	}
	return tx.FinishRun(id, state, reason, results)
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
		if s.running[checkKey(engID, fid)] == st.Run.ID {
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
		st.Stale = st.Run.ContentHash != contentHash(raw)
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

// Dismiss marks the finding's violation (rule, quote) as not counting: the
// submit/approve gate ignores it and check runs post no comment for it; its
// open comment is resolved. Warnings need edit rights, errors also the
// reviewer role (CanDismiss). A violation without a quote is dismissed with
// DismissWhy, which takes its target.
func (s *Store) Dismiss(engID, dir, rule, quote string, u config.User) error {
	return s.DismissWhy(engID, dir, rule, "", quote, "", u)
}

// DismissWhy is Dismiss of the violation (rule, target, quote) with the
// reason: it is kept with the dismissal and posted as u's reply in the
// violation's open thread before it is resolved. The target matters only
// when the quote is empty (see ViolationHash).
func (s *Store) DismissWhy(engID, dir, rule, target, quote, reason string, u config.User) error {
	reason = strings.TrimSpace(reason)
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	qh := ViolationHash(target, quote)
	level, err := s.violationLevel(ref, rule, qh)
	if err != nil {
		return err
	}
	if level == "" {
		return fmt.Errorf("%w: no violation %s with that quote", ErrInvalidValue, rule)
	}
	if !CanDismiss(u, ref.F.Meta, level) {
		return &workflow.Denied{Reason: dismissDenied(level)}
	}
	fid := ref.F.Meta.ID
	k := db.DismissKey(rule, qh)
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := tx.Dismiss(db.Dismissal{Eng: engID, Fid: fid, Rule: rule, QuoteHash: qh, Level: level, By: u.Username, Reason: reason}); err != nil {
			return err
		}
		refs, err := tx.CheckThreadRefs(engID, fid)
		if err != nil {
			return err
		}
		mine := map[string]bool{} // the violation's threads (one per section)
		for _, r := range refs {
			if db.DismissKey(r.Rule, r.QuoteHash) == k {
				mine[r.Thread] = true
			}
		}
		if len(mine) == 0 {
			return nil
		}
		msgs, err := tx.Messages(engID, fid)
		if err != nil {
			return err
		}
		for _, it := range chat.Timeline(msgs) {
			if it.Thread != nil && mine[it.Thread.Root.ID] && !it.Thread.Resolved {
				if reason != "" {
					if err := tx.AddMessage(engID, fid, chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second),
						User: u.Username, Reply: it.Thread.Root.ID, Text: reason}); err != nil {
						return err
					}
				}
				if err := tx.AddMessage(engID, fid, chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second),
					User: u.Username, Resolves: it.Thread.Root.ID}); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}

func dismissDenied(level string) string {
	if level == "error" {
		return "only a reviewer or a director can dismiss an error"
	}
	return "only someone who may edit the finding can dismiss a warning"
}

// Undismiss makes a dismissed violation (rule, target, quote) count again;
// the same people who may dismiss it may do this.
func (s *Store) Undismiss(engID, dir, rule, target, quote string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	fid, qh := ref.F.Meta.ID, ViolationHash(target, quote)
	ds, err := s.db.Dismissals(engID, fid)
	if err != nil {
		return err
	}
	d, ok := ds[db.DismissKey(rule, qh)]
	if !ok {
		return nil
	}
	if !CanDismiss(u, ref.F.Meta, d.Level) {
		return &workflow.Denied{Reason: dismissDenied(d.Level)}
	}
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error { return tx.Undismiss(engID, fid, rule, qh) })
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}
