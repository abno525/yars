package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/history"
	"github.com/abno525/yars/internal/render"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// Fixer is a Linter that can also fix (rules.Engine): section names the part
// body is the text of (a section's name, "title", or "details: " and a row's
// name).
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

// fixPart is the part of a finding a check result is about, as Fix with AI
// works on it: a section, the title or one row of the details table.
type fixPart struct {
	kind string // section, title or details
	name string // the section's or the row's name ("" for the title)
}

// partOf is the part a result with target is about; ok is false for a target
// that names no one text to rewrite (the finding, the CVSS vector, the
// details table without a row, the row that counts a rule's other results).
func partOf(target string) (p fixPart, ok bool) {
	if name := sectionOf(target); name != "" {
		return fixPart{"section", name}, true
	}
	if target == "title" {
		return fixPart{kind: "title"}, true
	}
	if name, is := strings.CutPrefix(target, "details:"); is && name != "" {
		return fixPart{"details", name}, true
	}
	return fixPart{}, false
}

// words names the part's kind in a reply ("the section changed meanwhile").
func (p fixPart) words() string {
	switch p.kind {
	case "title":
		return "the title"
	case "details":
		return "the details row"
	}
	return "the section"
}

// label names the part for the AI: a section's name, "title", or "details: "
// and the row's name.
func (p fixPart) label() string {
	switch p.kind {
	case "title":
		return "title"
	case "details":
		return "details: " + p.name
	}
	return p.name
}

// text is the part's text in f; ok is false when f has no such section or
// row.
func (p fixPart) text(f *finding.Finding) (string, bool) {
	switch p.kind {
	case "title":
		return f.Meta.Title, true
	case "details":
		v, ok := f.Meta.Details[p.name]
		return v, ok
	}
	return f.Section(p.name)
}

// base identifies text as the part's stored text (what the write compares).
func (p fixPart) base(text string) string {
	if p.kind == "section" {
		return BodyHash(text)
	}
	return RowHash(text)
}

// fixable is a check result the AI can work on: not a notice, not
// dismissed, with its thread, a quote and a part to fix in (a section, the
// title or a details row).
func fixable(r db.CheckResult, dismissed map[string]db.Dismissal) bool {
	v := rules.Violation{Rule: r.Rule, Target: r.Target, Quote: r.Quote}
	_, gone := db.Covering(dismissed, r.Rule, r.Target, r.Quote, r.Matches)
	_, part := partOf(r.Target)
	return !notice(v) && !gone && r.Thread != "" && r.Quote != "" && part
}

// FixCount counts the open check results in st the AI can work on (the
// latest run, finished on the current content); 0 without such a run.
func FixCount(st CheckStatus) int { return len(fixResults(st)) }

// fixResults is the work list: the fixable results of the latest check run
// in st, when it finished on the current content.
func fixResults(st CheckStatus) []db.CheckResult {
	if !st.HasRun || st.Running || st.Stale {
		return nil
	}
	var out []db.CheckResult
	for _, r := range st.Results {
		if fixable(r, st.Dismissed) {
			out = append(out, r)
		}
	}
	return out
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
	if !FixOpen(ref.F.Meta.Status) {
		works := "drafts and findings in verification"
		if s.Flow().Simple {
			works = "drafts" // a stray verification reads as a draft there
		}
		return &workflow.Denied{Reason: "this finding is " + ref.F.Meta.Status + "; Fix with AI works on " + works}
	}
	if !s.AICanFix() {
		return fmt.Errorf("%w: no AI provider configured", ErrInvalidValue)
	}
	// the engagement takes no AI: said at the press, and nothing is sent
	if why := rules.AIOff(ref.F); why != "" {
		return fmt.Errorf("%w: %s", ErrInvalidValue, why)
	}
	// the spend limit is reached: said at the press, not once per item
	if l, ok := s.Linter.(interface{ AIOverLimit() bool }); ok && l.AIOverLimit() {
		return fmt.Errorf("%w: %s", ErrInvalidValue, rules.ErrAILimit)
	}
	if s.CheckRunning(engID, ref.F.Meta.ID) {
		return ErrBusy // checked again under the lock below
	}
	st, err := s.CheckStatus(engID, dir)
	if err != nil {
		return err
	}
	list := fixResults(st)
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
	stop := s.newStop(key, s.fixBase())
	s.checkWG.Add(1)
	s.checksMu.Unlock()
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	go s.runFix(stop.ctx, engID, dir, fid, list, st.Results, u)
	return nil
}

// fixJobLimit bounds a whole Fix with AI run: its items run one after
// another, each up to three times the AI time limit.
const fixJobLimit = 15 * time.Minute

// fixBase is the context every fix runs under; StopFixes cancels it.
func (s *Store) fixBase() context.Context {
	s.fixOnce.Do(func() { s.fixCtx, s.fixStop = context.WithCancel(context.Background()) })
	return s.fixCtx
}

// StopFixes ends the fixes running now (the server is stopping): what is
// left is answered without asking the AI, and no check follows.
func (s *Store) StopFixes() {
	s.fixBase()
	s.fixStop()
}

// FixOpen reports whether a finding in status may be fixed: a draft or one
// in verification. An approved finding may not (its approval would carry
// over to text nobody read), nor a withdrawn one.
func FixOpen(status string) bool { return status == "draft" || status == "verification" }

// runFix works through list for u (all: every result of the run, what the
// rules found before), then clears the busy mark, audits the outcome and
// starts a check run (which resolves the fixed threads).
func (s *Store) runFix(own context.Context, engID, dir, fid string, list, all []db.CheckResult, u config.User) {
	defer s.checkWG.Done()
	key := checkKey(engID, fid)
	cleared := false
	defer func() {
		if p := recover(); p != nil {
			s.Log().Error("fix with AI crashed", "eng", engID, "finding", fid, "err", fmt.Sprint(p))
		}
		if !cleared {
			s.setRunning(key, 0, true)
			s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
		}
	}()
	base := s.fixBase()
	job, cancel := context.WithTimeout(own, fixJobLimit)
	defer cancel()
	ctx := rules.WithCaller(job, rules.Caller{User: u.Username, Eng: engID, Fid: fid})
	start := time.Now()
	nFixed, nSkipped := 0, 0
	// the job's end, in one line (also when it crashed: the counts so far)
	defer func() {
		s.Log().Info("fix with AI finished", "eng", engID, "finding", LogID(fid), "user", u.Username,
			"fixed", nFixed, "not_fixed", nSkipped, "ms", time.Since(start).Milliseconds())
	}()
	for _, r := range list {
		if s.writable(engID) != nil {
			break // archived meanwhile: nothing more is written there
		}
		if userCancelled(own) {
			break // cancelled: the items not reached get no reply
		}
		row := s.fixItem(ctx, engID, dir, r, all, u)
		if !row.Fixed && userCancelled(own) {
			break // nor does the item the cancel cut off
		}
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
	detail := fmt.Sprintf("%d fixed · %d not fixed", nFixed, nSkipped)
	if userCancelled(own) {
		detail += " · cancelled"
	}
	s.db.Audit(u.Username, "ai.fix", engID+"/"+fid, detail)
	if base.Err() != nil || userCancelled(own) || s.writable(engID) != nil {
		// the server is stopping, the fix was cancelled, or the engagement
		// was archived: no check follows
		return
	}
	if _, err := s.StartCheck(engID, dir, u); err != nil && !errors.Is(err, ErrBusy) {
		s.Log().Error("check after a fix with AI not started", "eng", engID, "finding", fid, "err", err)
	}
}

// replyAI answers a check's thread for u, marked as done by AI. No domain
// event is emitted (no notifications).
func (s *Store) replyAI(engID, fid, thread string, u config.User, text string) {
	m := chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Kind: chat.KindAI, Reply: thread, Text: text}
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		return tx.AddMessage(engID, fid, m)
	})
	if errors.Is(err, ErrArchived) {
		return // archived meanwhile, as a chat post would be refused
	}
	if err != nil {
		s.Log().Error("fix with AI: the reply is not written", "eng", engID, "finding", fid, "err", err)
		return
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeChat, Seq: seq})
}

// fixItem is fixOne with a crash turned into its outcome: one item's panic
// does not end the job (the others are answered, the check still follows).
func (s *Store) fixItem(ctx context.Context, engID, dir string, r db.CheckResult, all []db.CheckResult, u config.User) (row FixRow) {
	defer func() {
		if p := recover(); p != nil {
			s.Log().Error("fix with AI: one fix crashed", "eng", engID, "finding", LogID(dir), "rule", r.Rule, "err", fmt.Sprint(p))
			row = FixRow{Rule: r.Rule, Target: r.Target, Quote: r.Quote, Outcome: "not fixed: the fix crashed"}
		}
	}()
	return s.fixOne(ctx, engID, dir, r, all, u)
}

// fixOne asks for a fix of r and commits it when it passes every check. The
// AI is asked only when the quote is in exactly one paragraph of the part
// (a section, the title or a details row) and (a fast rule) the rule still
// finds it.
func (s *Store) fixOne(ctx context.Context, engID, dir string, r db.CheckResult, all []db.CheckResult, u config.User) FixRow {
	row := FixRow{Rule: r.Rule, Target: r.Target, Quote: r.Quote}
	not := func(reason string) FixRow {
		row.Outcome = "not fixed: " + reason
		return row
	}
	switch err := ctx.Err(); {
	case errors.Is(err, context.DeadlineExceeded):
		return not(fmt.Sprintf("the fix took longer than %d minutes", int(fixJobLimit.Minutes())))
	case userCancelled(ctx):
		return not("cancelled")
	case err != nil:
		return not("the server is stopping")
	}
	fx, ok := s.Linter.(Fixer)
	if !ok {
		return not(rules.ErrNoAI.Error())
	}
	kind := s.ruleKind(r.Rule)
	if kind == "" {
		return not("the rule " + r.Rule + " is gone")
	}
	part, ok := partOf(r.Target)
	if !ok {
		return not("the result names no section, title or details row")
	}
	ref, _, err := s.read(engID, dir, nil)
	if err != nil {
		return not(err.Error())
	}
	// switched off since the press: the items left are not sent
	if why := rules.AIOff(ref.F); why != "" {
		return not(why)
	}
	old, ok := part.text(ref.F)
	if !ok {
		return not(part.words() + " " + part.name + " is gone")
	}
	v := rules.Violation{Rule: r.Rule, Level: r.Level, Message: r.Message, Target: r.Target, Quote: r.Quote}
	at, why := quotePara(old, r.Quote)
	if why != "" {
		return not(strings.Replace(why, "the section", part.words(), 1))
	}
	if fastKind(kind) && !slices.ContainsFunc(s.Linter.Lint(ctx, ref.F, rules.Fast), sameAs(v)) {
		return not("the rule no longer finds the problem")
	}
	body, err := fx.Fix(ctx, v, part.label(), old)
	switch {
	case userCancelled(ctx):
		// also when the provider still answered: nothing is committed after
		// a cancel
		return not("cancelled")
	case err != nil && errors.Is(ctx.Err(), context.Canceled):
		return not("the server is stopping") // not the provider's error
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return not(fmt.Sprintf("the fix took longer than %d minutes", int(fixJobLimit.Minutes())))
	case err != nil:
		return not(err.Error())
	}
	// CRLF is a line break for the paragraphs too (the section is saved with
	// LF), and the AI's text keeps the section's own leading and trailing
	// line breaks
	body = strings.ReplaceAll(body, "\r\n", "\n")
	switch part.kind {
	case "title":
		// blanks at its ends are not the title's; anything else it holds is
		// judged as it came (acceptFix): never joined, cut or cleaned
		body = strings.TrimSpace(body)
	case "details":
		body = CleanRow(body) // as the page stores a row
	default:
		lead := old[:len(old)-len(strings.TrimLeft(old, "\n"))]
		trail := old[len(strings.TrimRight(old, "\n")):]
		body = lead + strings.Trim(body, "\n") + trail
	}
	if body == old {
		return not("the AI changed nothing")
	}
	if reason := s.acceptFix(ctx, ref, part, old, body, v, at, kind, all); reason != "" {
		return not(reason)
	}
	err = s.fixWrite(engID, dir, part, body, part.base(old), u)
	var d *workflow.Denied
	switch {
	case errors.Is(err, ErrConflict):
		return not(part.words() + " changed meanwhile")
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

// ruleKind is the kind of the rule id as the checks run it ("pattern",
// "builtin", "script", "ai"); "" when no such rule runs now.
func (s *Store) ruleKind(id string) string {
	sc, ok := s.Linter.(StepChecker)
	if !ok {
		return ""
	}
	for _, r := range sc.CheckRules() {
		if r.ID == id {
			return r.KindName()
		}
	}
	return ""
}

// fastKind: the rule runs with the fast rules (Lint), not on its own.
func fastKind(kind string) bool { return kind == "pattern" || kind == "builtin" }

// sameAs matches a violation of v's rule in v's place with v's quote.
func sameAs(v rules.Violation) func(rules.Violation) bool {
	q := squash(v.Quote)
	return func(x rules.Violation) bool {
		return x.Rule == v.Rule && x.Target == v.Target && squash(x.Quote) == q
	}
}

// quotePara finds the one paragraph of body that holds quote as words ("we"
// is not in "however"; a quote cut short, "…", by what it keeps): its index,
// or why there is none.
func quotePara(body, quote string) (int, string) {
	q := strings.TrimSpace(quote)
	cut := strings.HasSuffix(q, "…")
	q = squash(strings.TrimSuffix(q, "…"))
	if q == "" {
		return -1, "the quoted text is empty"
	}
	word := func(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }
	first, _ := utf8.DecodeRuneInString(q)
	lastR, _ := utf8.DecodeLastRuneInString(q)
	pat := regexp.QuoteMeta(q)
	if word(first) {
		pat = `(?:^|[^\pL\pN_])` + pat
	}
	if word(lastR) && !cut {
		pat += `(?:$|[^\pL\pN_])`
	}
	re := regexp.MustCompile(pat)
	at := -1
	for i, p := range paragraphs.Split(body, -1) {
		if re.MatchString(squash(p)) {
			if at >= 0 {
				return -1, "the quoted text is in more than one paragraph"
			}
			at = i
		}
	}
	if at < 0 {
		return -1, "the quoted text is not in the section"
	}
	return at, ""
}

// paraRange is the byte range of paragraph at of body (split as paragraphs
// splits it), with the line break that ends its last line (an indented code
// or raw HTML block keeps it as its own).
func paraRange(body string, at int) [2]int {
	start := 0
	for i, m := range paragraphs.FindAllStringIndex(body, -1) {
		if i == at {
			return [2]int{start, m[0] + 1}
		}
		start = m[1]
	}
	return [2]int{start, len(body)}
}

// reaching starts a line that opens a block running past its paragraph:
// raw HTML (a comment, <pre>, <script> … run to their end marker, across
// blank lines), a code fence, or a link definition (used by any paragraph).
var reaching = regexp.MustCompile("^ {0,3}(<|```|~~~|\\[[^\\]]*\\]:)")

// addsReaching reports whether the new paragraph has such a line the old
// one did not.
func addsReaching(old, new string) bool {
	had := map[string]int{}
	for _, l := range strings.Split(old, "\n") {
		if reaching.MatchString(l) {
			had[strings.TrimSpace(l)]++
		}
	}
	for _, l := range strings.Split(new, "\n") {
		if !reaching.MatchString(l) {
			continue
		}
		k := strings.TrimSpace(l)
		if had[k] == 0 {
			return true
		}
		had[k]--
	}
	return false
}

// acceptFix checks the AI's body for the problem v in part of ref (old is
// the part's text now; at its paragraph holding the quote; kind the rule's;
// all the run's results). A title must be a title as it came: one line of 1
// to 200 characters without hidden text-direction characters (it goes on
// into notifications, mail, webhooks and exports). Review focus 1 (the text
// is other people's and may hold instructions): only paragraph at changed,
// with no raw HTML, code fence or link definition added that would reach the
// other paragraphs. Focus 2: the rule ran on the new text and finds neither
// the problem nor any new one; no new error from another rule in the part.
// "" when it passes, else why not, in words.
func (s *Store) acceptFix(ctx context.Context, ref FindingRef, part fixPart, old, body string, v rules.Violation, at int, kind string, all []db.CheckResult) string {
	if part.kind == "title" && ValidTitle(body) != nil {
		return "the AI's text is not a valid title (one line of 1 to 200 characters)"
	}
	po, pn := paragraphs.Split(old, -1), paragraphs.Split(body, -1)
	if len(po) != len(pn) {
		return fmt.Sprintf("the AI changed the number of paragraphs (%d to %d)", len(po), len(pn))
	}
	for i := range po {
		if i != at && po[i] != pn[i] {
			return fmt.Sprintf("the AI changed paragraph %d, which does not hold the quoted text", i+1)
		}
	}
	if addsReaching(po[at], pn[at]) {
		return "the AI's text adds raw HTML, a code fence or a link definition"
	}
	// the same inside a list item or a quote, a closer taken away: the rest
	// of the section must render as it did
	if !render.SameOutside(old, body, paraRange(old, at), paraRange(body, at)) {
		return "the AI's text changes how the other paragraphs show"
	}
	if part.kind == "section" {
		if err := finding.ValidateBody(body); err != nil {
			return "the AI's text is not a valid section (" + err.Error() + ")"
		}
	}
	// the finding as it would be after the fix, for the rules
	after, err := finding.Parse(ref.F.Bytes())
	if err != nil {
		return err.Error()
	}
	after.Meta = ref.F.Meta
	switch part.kind {
	case "title":
		after.Meta.Title = body
	case "details":
		// a map of its own: after.Meta shares ref's
		rows := maps.Clone(ref.F.Meta.Details)
		if rows == nil {
			rows = map[string]string{}
		}
		rows[part.name] = body
		after.Meta.Details = rows
	default:
		after.SetSection(part.name, body)
	}
	same := sameAs(v)
	mine := func(x rules.Violation) bool { return x.Rule == v.Rule && x.Target == v.Target }
	fastBefore, fastAfter := s.Linter.Lint(ctx, ref.F, rules.Fast), s.Linter.Lint(ctx, after, rules.Fast)
	// what the rule finds in the section, before and after
	before := map[string]bool{}
	var found []rules.Violation
	if fastKind(kind) {
		for _, x := range fastBefore {
			if mine(x) {
				before[squash(x.Quote)] = true
			}
		}
		found = fastAfter
	} else {
		for _, r := range all {
			if r.Rule == v.Rule && r.Target == v.Target {
				before[squash(r.Quote)] = true
			}
		}
		sc, ok := s.Linter.(StepChecker)
		if !ok {
			return "the rule could not run on the new text"
		}
		found = sc.CheckWith(ctx, after, rules.Hooks{Only: v.Rule})
	}
	for _, x := range found {
		switch {
		case x.Rule != v.Rule:
		case notice(x) || x.Fail != "":
			return "the rule could not run on the new text"
		case same(x):
			return "the rule still finds the problem"
		case x.Target == v.Target && !before[squash(x.Quote)]:
			return "the rule finds a new problem (" + x.Quote + ")"
		}
	}
	errs := map[string]bool{}
	for _, x := range fastBefore {
		if x.Level == "error" && x.Target == v.Target {
			errs[x.Rule+"\x00"+squash(x.Quote)] = true
		}
	}
	for _, x := range fastAfter {
		if x.Level == "error" && x.Target == v.Target && !errs[x.Rule+"\x00"+squash(x.Quote)] {
			return "the change brings a new error (" + x.Rule + ": " + x.Message + ")"
		}
	}
	return ""
}

// fixWrite writes the AI's text of part (a section's body, the title, one
// details row) as "AI for <user>", if the part is still at base, the
// finding still open (not approved meanwhile) and u may still edit it (all
// checked under the engagement's lock, at the commit). The commit reads as
// the page's own edit of that part does.
func (s *Store) fixWrite(engID, dir string, part fixPart, body, base string, u config.User) error {
	author := gitrepo.Author{Name: history.AIFor + u.Username, Email: u.GitAuthor().Email}
	return s.mutateContent(engID, dir, author, func(f *finding.Finding) (string, error) {
		if !workflow.CanEdit(u, f.Meta) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + " now; " + u.Username + " cannot edit it"}
		}
		if !FixOpen(f.Meta.Status) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + " now"}
		}
		// a row that is gone is a row that changed
		if cur, ok := part.text(f); (!ok && part.kind != "section") || part.base(cur) != base {
			return "", ErrConflict
		}
		switch part.kind {
		case "title":
			return "edit title", f.SetMeta("title", body)
		case "details":
			return s.writeDetails(f, map[string]string{part.name: body})
		}
		f.SetSection(part.name, body)
		return "edit " + part.name, nil
	})
}
