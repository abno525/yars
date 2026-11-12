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
	"yars/internal/rules"
)

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
	// one start at a time; checksMu is held across the writes below, so
	// nothing inside a transaction may take it (the gate reads running
	// under runningMu only)
	s.checksMu.Lock()
	s.runningMu.Lock()
	id, ok := s.running[key]
	s.runningMu.Unlock()
	if ok {
		s.checksMu.Unlock()
		if id == fixRun {
			return db.CheckRun{}, ErrBusy // the AI is fixing it (StartFix)
		}
		return s.db.Run(id)
	}
	var keep *carried
	if only != "" {
		prev, ok, err := s.db.LatestRun(engID, fid)
		// kept only from a run on this content with these rules (Q13)
		if err == nil && ok && prev.State != db.RunRunning && prev.ContentHash == hash && !RulesChanged(prev.Rules, s.RulesVersion()) {
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
	// marked before the run exists: a gate that sees the new run as the
	// latest counts it as running, not as cut off
	s.setRunning(key, pendingRun, false)
	id, err = s.db.StartRun(engID, fid, hash, u.Username, s.RulesVersion())
	if err != nil {
		s.setRunning(key, 0, true)
		s.checksMu.Unlock()
		return db.CheckRun{}, err
	}
	s.setRunning(key, id, false)
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
	s.checkWG.Add(1)
	s.checksMu.Unlock()
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	go s.runCheck(id, ref, only, keep, u.Username)
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
	rows := map[string]bool{} // one hit per result row (finishCheck)
	for _, v := range vs {
		switch {
		case v.Fail != "":
			x.State, x.Message, x.Fail = db.StepFailed, v.Message, v.Fail
		case notice(v):
			if x.State != db.StepFailed {
				x.State, x.Message = db.StepFailed, v.Message
			}
		default:
			if k := v.Level + "\x00" + ViolationHash(v.Target, v.Quote); !rows[k] {
				rows[k] = true
				x.Hits++
			}
		}
	}
	if x.State == db.StepPass && x.Hits > 0 {
		x.State = db.StepHits
	}
	return x
}

// CheckRunning reports whether this server is running a check of the
// finding now (a run a stopped server left "running" is not).
func (s *Store) CheckRunning(engID, fid string) bool {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()
	_, ok := s.running[checkKey(engID, fid)]
	return ok
}

// pendingRun marks a check as starting in running before its run exists.
const pendingRun = 0

// inProgress reports whether run id of key is in progress in this server
// (or a start of key is under way, which makes it the latest run).
func (s *Store) inProgress(key string, id int64) bool {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()
	v, ok := s.running[key]
	return ok && (v == id || v == pendingRun)
}

// setRunning records (or, with forget, removes) key's run in running.
func (s *Store) setRunning(key string, id int64, forget bool) {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()
	if forget {
		delete(s.running, key)
		return
	}
	if s.running == nil {
		s.running = map[string]int64{}
	}
	s.running[key] = id
}

// WaitChecks waits until no check run is in progress.
func (s *Store) WaitChecks() { s.checkWG.Wait() }

// runCheck runs the check id started by user by (the run's By); its AI
// calls are recorded as theirs, on this finding (D24).
func (s *Store) runCheck(id int64, ref FindingRef, only string, keep *carried, by string) {
	eng, fid := ref.EngID, ref.F.Meta.ID
	ctx := rules.WithCaller(context.Background(), rules.Caller{User: by, Eng: eng, Fid: fid})
	defer s.checkWG.Done()
	defer func() {
		if p := recover(); p != nil {
			s.db.FailRun(id, fmt.Sprint("crashed: ", p))
		}
		s.setRunning(checkKey(eng, fid), 0, true)
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
		vs = c.CheckWith(ctx, ref.F, rules.Hooks{
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
		vs = c.Check(ctx, ref.F, progress)
	} else {
		progress(0, 1)
		vs = s.Linter.Lint(ctx, ref.F, rules.All)
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
			if r.Target == "rules" || r.Target == "ai" {
				continue
			}
			if _, ok := db.Lookup(dis, r.Rule, r.Target, r.Quote); ok {
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
	// a dismissal made before they were per row covers the rows of its
	// quote this run finds: each gets its own copy, and the old one ends,
	// so the same wording put in another place later counts (D18)
	ended := map[string]db.Dismissal{}
	for _, v := range vs {
		if notice(v) || v.Quote == "" {
			continue
		}
		lk := db.DismissKey(v.Rule, db.LegacyHash(v.Quote))
		old, ok := dismissed[lk]
		if !ok {
			continue
		}
		ended[lk] = old
		own := db.DismissKey(v.Rule, ViolationHash(v.Target, v.Quote))
		if _, has := dismissed[own]; has {
			continue
		}
		old.QuoteHash = ViolationHash(v.Target, v.Quote)
		if err := tx.Dismiss(old); err != nil {
			return err
		}
		dismissed[own] = old
	}
	for lk, old := range ended {
		if err := tx.Undismiss(eng, fid, old.Rule, old.QuoteHash); err != nil {
			return err
		}
		delete(dismissed, lk)
	}
	now := time.Now().UTC().Truncate(time.Second)
	add := func(m chat.Message) error {
		m.ID, m.TS, m.User = chat.NewID(), now, CheckUser
		return tx.AddMessage(eng, fid, m)
	}
	found := map[string]string{} // threadKey -> thread given in this run
	results := make([]db.CheckResult, 0, len(vs))
	stored := map[string]bool{} // rule, place and quote: one row each (D18)
	for _, v := range vs {
		r := db.CheckResult{Rule: v.Rule, Level: v.Level, Message: v.Message, Target: v.Target, Quote: v.Quote, QuoteHash: ViolationHash(v.Target, v.Quote)}
		row := db.DismissKey(r.Rule, r.QuoteHash) + "\x00" + r.Level
		if !notice(v) && stored[row] {
			continue
		}
		stored[row] = true
		k := threadKey(r.Rule, r.QuoteHash, sectionOf(v.Target))
		switch th, seen := found[k]; {
		case notice(v):
		case seen:
			r.Thread = th
		case dismissedRow(dismissed, v):
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

func dismissedRow(ds map[string]db.Dismissal, v rules.Violation) bool {
	_, ok := db.Lookup(ds, v.Rule, v.Target, v.Quote)
	return ok
}
