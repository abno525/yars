package store

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// Fixer is a Linter that can also fix (rules.Engine).
type Fixer interface {
	Fix(ctx context.Context, v rules.Violation, section, body string) (string, error)
}

// FixRow is the outcome for one check result.
type FixRow struct {
	Rule, Target, Quote, Outcome string
	Fixed                        bool
}

// ErrBusy: the finding has a check or a fix running.
var ErrBusy = errors.New("a check or a fix of this finding is running")

// fixRun marks a fix in the running map (a check holds its run's id there).
const fixRun = -1

// FixRunning reports whether a fix of the finding runs now.
func (s *Store) FixRunning(engID, fid string) bool {
	s.runningMu.Lock()
	defer s.runningMu.Unlock()
	v, ok := s.running[checkKey(engID, fid)]
	return ok && v == fixRun
}

// fixable is a check result the AI can work on: not a notice, not
// dismissed, with its thread, a quote and a section to fix in.
func fixable(r db.CheckResult, dismissed map[string]db.Dismissal) bool {
	v := rules.Violation{Rule: r.Rule, Target: r.Target, Quote: r.Quote}
	_, gone := db.Lookup(dismissed, r.Rule, r.Target, r.Quote)
	return !notice(v) && !gone && r.Thread != "" && r.Quote != "" && sectionOf(r.Target) != ""
}

// Fixable counts the open check results of the finding the AI can work on
// (the latest run, finished on the current content); 0 without such a run.
func (s *Store) Fixable(engID, dir string) (int, error) {
	list, err := s.fixList(engID, dir)
	return len(list), err
}

// fixList is the work list: the fixable results of the latest check run
// that finished on the current content.
func (s *Store) fixList(engID, dir string) ([]db.CheckResult, error) {
	st, err := s.CheckStatus(engID, dir)
	if err != nil {
		return nil, err
	}
	if !st.HasRun || st.Running || st.Stale {
		return nil, nil
	}
	var out []db.CheckResult
	for _, r := range st.Results {
		if fixable(r, st.Dismissed) {
			out = append(out, r)
		}
	}
	return out, nil
}

// AICanFix reports whether a provider is set up for fixing.
func (s *Store) AICanFix() bool {
	_, ok := s.Linter.(Fixer)
	ai, ok2 := s.Linter.(interface{ AIConfigured() bool })
	return ok && ok2 && ai.AIConfigured()
}

// StartFix starts fixing the finding's open check results in the background
// as u (R7). It returns at once; progress is announced as ChangeCheck. While
// a check or a fix of the finding runs, it returns ErrBusy. The AI never
// changes the workflow state and never dismisses anything; each fix is
// committed as "AI for <user>" and answered in its result's thread, and a
// check run follows.
func (s *Store) StartFix(engID, dir string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	ref, _, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	if !workflow.CanEdit(u, ref.F.Meta) {
		return &workflow.Denied{Reason: "this finding is " + ref.F.Meta.Status + "; " + u.Username + " cannot edit it"}
	}
	if !s.AICanFix() {
		return fmt.Errorf("%w: no AI provider configured", ErrInvalidValue)
	}
	if s.CheckRunning(engID, ref.F.Meta.ID) {
		return ErrBusy // checked again under the lock below
	}
	list, err := s.fixList(engID, dir)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return fmt.Errorf("%w: nothing to fix: run Check first", ErrInvalidValue)
	}
	fid := ref.F.Meta.ID
	key := checkKey(engID, fid)
	s.checksMu.Lock()
	s.runningMu.Lock()
	_, busy := s.running[key]
	s.runningMu.Unlock()
	if busy {
		s.checksMu.Unlock()
		return ErrBusy
	}
	s.setRunning(key, fixRun, false)
	s.checkWG.Add(1)
	s.checksMu.Unlock()
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	go s.runFix(engID, dir, fid, list, u)
	return nil
}

// runFix works through list for u, then clears the busy mark, audits the
// outcome and starts a check run (which resolves the fixed threads).
func (s *Store) runFix(engID, dir, fid string, list []db.CheckResult, u config.User) {
	defer s.checkWG.Done()
	key := checkKey(engID, fid)
	cleared := false
	defer func() {
		if p := recover(); p != nil {
			log.Printf("fix %s/%s crashed: %v", engID, fid, p)
		}
		if !cleared {
			s.setRunning(key, 0, true)
			s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
		}
	}()
	ctx := rules.WithCaller(context.Background(), rules.Caller{User: u.Username, Eng: engID, Fid: fid})
	nFixed, nSkipped := 0, 0
	for _, r := range list {
		row := s.fixOne(ctx, engID, dir, r, u)
		text := "Fixed."
		if row.Fixed {
			nFixed++
		} else {
			nSkipped++
			text = "Not fixed: " + strings.TrimPrefix(row.Outcome, "not fixed: ") + "."
		}
		s.replyAI(engID, fid, r.Thread, u, text)
		s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	}
	// cleared before the check starts, which would otherwise be refused
	s.setRunning(key, 0, true)
	cleared = true
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	s.db.Audit(u.Username, "ai.fix", engID+"/"+fid, fmt.Sprintf("%d fixed · %d not fixed", nFixed, nSkipped))
	if _, err := s.StartCheck(engID, dir, u); err != nil && !errors.Is(err, ErrBusy) {
		log.Printf("check after the fix of %s/%s: %v", engID, fid, err)
	}
}

// replyAI answers a check's thread for u, marked as done by AI. No domain
// event is emitted (no notifications).
func (s *Store) replyAI(engID, fid, thread string, u config.User, text string) {
	m := chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Kind: chat.KindAI, Reply: thread, Text: text}
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error { return tx.AddMessage(engID, fid, m) })
	if err != nil {
		log.Printf("AI reply on %s/%s: %v", engID, fid, err)
		return
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeChat, Seq: seq})
}

// fixOne asks for a fix of r and commits it when it passes every check.
func (s *Store) fixOne(ctx context.Context, engID, dir string, r db.CheckResult, u config.User) FixRow {
	row := FixRow{Rule: r.Rule, Target: r.Target, Quote: r.Quote}
	not := func(reason string) FixRow {
		row.Outcome = "not fixed: " + reason
		return row
	}
	fx, ok := s.Linter.(Fixer)
	if !ok {
		return not(rules.ErrNoAI.Error())
	}
	section := sectionOf(r.Target)
	ref, _, err := s.read(engID, dir, nil)
	if err != nil {
		return not(err.Error())
	}
	old, ok := ref.F.Section(section)
	if !ok {
		return not("the section " + section + " is gone")
	}
	v := rules.Violation{Rule: r.Rule, Level: r.Level, Message: r.Message, Target: r.Target, Quote: r.Quote}
	body, err := fx.Fix(ctx, v, section, old)
	if err != nil {
		return not(err.Error())
	}
	// the AI's text keeps the section's own leading and trailing line breaks
	lead := old[:len(old)-len(strings.TrimLeft(old, "\n"))]
	trail := old[len(strings.TrimRight(old, "\n")):]
	body = lead + strings.Trim(body, "\n") + trail
	if reason := s.acceptFix(ctx, ref, section, old, body, v); reason != "" {
		return not(reason)
	}
	err = s.fixSection(engID, dir, section, body, BodyHash(old), u)
	var d *workflow.Denied
	switch {
	case errors.Is(err, ErrConflict):
		return not("the section changed meanwhile")
	case errors.As(err, &d):
		return not(d.Reason)
	case err != nil:
		return not(err.Error())
	}
	row.Fixed, row.Outcome = true, "fixed"
	return row
}

// paragraphs splits a section on blank lines.
var paragraphs = regexp.MustCompile("\n[ \t]*\n+")

// squash collapses white space, so a quote is found across line breaks.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// acceptFix checks the AI's body for the problem v in section of ref (old
// is the section now): it is a valid section; it changed nothing outside the
// paragraph(s) holding the quote (Review focus 1: the text is other people's
// and may hold instructions); the rule no longer finds the problem (focus
// 2); it brings no new error into the section. "" when it passes, else why
// not, in words.
func (s *Store) acceptFix(ctx context.Context, ref FindingRef, section, old, body string, v rules.Violation) string {
	if err := finding.ValidateBody(body); err != nil {
		return "the AI's text is not a valid section (" + err.Error() + ")"
	}
	po, pn := paragraphs.Split(old, -1), paragraphs.Split(body, -1)
	if len(po) != len(pn) {
		return fmt.Sprintf("the AI changed the number of paragraphs (%d to %d)", len(po), len(pn))
	}
	q := squash(v.Quote)
	for i := range po {
		if !strings.Contains(squash(po[i]), q) && po[i] != pn[i] {
			return fmt.Sprintf("the AI changed paragraph %d, which does not hold the quoted text", i+1)
		}
	}
	after, err := finding.Parse(ref.F.Bytes())
	if err != nil {
		return err.Error()
	}
	after.Meta = ref.F.Meta
	after.SetSection(section, body)
	same := func(x rules.Violation) bool {
		return x.Rule == v.Rule && x.Target == v.Target && squash(x.Quote) == q
	}
	fastAfter := s.Linter.Lint(ctx, after, rules.Fast)
	for _, x := range fastAfter {
		if same(x) {
			return "the rule still finds the problem"
		}
	}
	// a script or AI rule runs on its own for the new text
	if sc, ok := s.Linter.(StepChecker); ok {
		for _, rule := range sc.CheckRules() {
			if rule.ID != v.Rule || (rule.KindName() != "script" && rule.KindName() != "ai") {
				continue
			}
			for _, x := range sc.CheckWith(ctx, after, rules.Hooks{Only: rule.ID}) {
				if same(x) {
					return "the rule still finds the problem"
				}
			}
		}
	}
	before := map[string]bool{}
	for _, x := range s.Linter.Lint(ctx, ref.F, rules.Fast) {
		if x.Level == "error" && x.Target == v.Target {
			before[x.Rule+"\x00"+squash(x.Quote)] = true
		}
	}
	for _, x := range fastAfter {
		if x.Level == "error" && x.Target == v.Target && !before[x.Rule+"\x00"+squash(x.Quote)] {
			return "the change brings a new error (" + x.Rule + ": " + x.Message + ")"
		}
	}
	return ""
}

// fixSection writes the AI's section body as "AI for <user>", if the
// section is still at base and u may still edit the finding (both checked
// under the engagement's lock, at the commit).
func (s *Store) fixSection(engID, dir, section, body, base string, u config.User) error {
	author := gitrepo.Author{Name: "AI for " + u.Username, Email: u.GitAuthor().Email}
	return s.mutateContent(engID, dir, author, func(f *finding.Finding) (string, error) {
		if !workflow.CanEdit(u, f.Meta) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + " now; " + u.Username + " cannot edit it"}
		}
		cur, _ := f.Section(section)
		if BodyHash(cur) != base {
			return "", ErrConflict
		}
		f.SetSection(section, body)
		return "edit " + section, nil
	})
}
