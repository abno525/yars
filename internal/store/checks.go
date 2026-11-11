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
	Stale     bool // the finding or the rules changed since the run started
	Results   []db.CheckResult
	Steps     []db.CheckStep          // each rule of the run, in order
	Dismissed map[string]db.Dismissal // by db.DismissKey
}

// QuoteHash identifies a violation's quote for dismissals and comments.
func QuoteHash(quote string) string { return BodyHash(quote) }

// ViolationHash identifies a violation of a rule for dismissals and
// comments: where it is and its quote, so that one dismissal covers one
// result row only (db.ViolationHash).
func ViolationHash(target, quote string) string { return db.ViolationHash(target, quote) }

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

// SignsOff reports whether an action hands a finding on towards a director
// (Sign off, Approve): it needs the finding clean, warnings dismissed too.
func SignsOff(act workflow.Action) bool { return act == workflow.Clear || act == workflow.Approve }

// blocking lists what blocks act on the finding (content hash): Submit and
// Approve run every rule now (scripts and AI too: no check run may have
// covered the content) and are blocked by its undismissed errors; Sign off
// and Approve are blocked by every open check, warnings too (OpenChecks,
// the source the page and Ready to approve show). With Require Check on,
// Sign off and Approve first need a finished run on this content
// (checkGate), and Approve runs nothing inline: the run is the source.
func (s *Store) blocking(act workflow.Action, ref FindingRef, hash string) ([]string, error) {
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
		vs, err := s.undismissed(ref.EngID, ref.F.Meta.ID, s.Linter.Lint(context.Background(), ref.F, rules.All))
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

func (s *Store) runCheck(id int64, ref FindingRef, only string, keep *carried) {
	eng, fid := ref.EngID, ref.F.Meta.ID
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

// Dismiss marks the finding's violation (rule, quote) as not counting: the
// submit/approve gate ignores it and check runs post no comment for it; its
// open comment is resolved. Warnings need edit rights, errors also the
// reviewer role (CanDismiss). The quote must be in one place only (placeOf);
// DismissWhy takes the place.
func (s *Store) Dismiss(engID, dir, rule, quote string, u config.User) error {
	return s.DismissWhy(engID, dir, rule, "", quote, "", u)
}

// DismissWhy is Dismiss of the violation (rule, target, quote) with the
// reason: it is kept with the dismissal and posted as u's reply in the
// violation's open thread before it is resolved. It covers that one result
// row: the same quote in another place still counts. An empty target is
// the quote's one place (placeOf).
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
	if target == "" && quote != "" {
		if target, err = s.placeOf(ref, rule, quote); err != nil {
			return err
		}
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
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
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
	if target == "" && quote != "" {
		if target, err = s.placeOf(ref, rule, quote); err != nil {
			return err
		}
	}
	fid, qh := ref.F.Meta.ID, ViolationHash(target, quote)
	ds, err := s.db.Dismissals(engID, fid)
	if err != nil {
		return err
	}
	// its own dismissal, or one made before they were per row (that one
	// covered the quote everywhere: restoring this row ends it)
	legacy := ""
	d, ok := ds[db.DismissKey(rule, qh)]
	if quote != "" {
		if old, has := ds[db.DismissKey(rule, db.LegacyHash(quote))]; has {
			legacy = db.LegacyHash(quote)
			if !ok {
				d, ok = old, true
			}
		}
	}
	if !ok {
		return nil
	}
	if !CanDismiss(u, ref.F.Meta, d.Level) {
		return &workflow.Denied{Reason: dismissDenied(d.Level)}
	}
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		if legacy != "" {
			if err := tx.Undismiss(engID, fid, rule, legacy); err != nil {
				return err
			}
		}
		return tx.Undismiss(engID, fid, rule, qh)
	})
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}
