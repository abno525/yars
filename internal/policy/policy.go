// Package policy decides whether a git push may update the data repo. A
// push carries content only: workflow state and chat live in the YARS
// database, so the rules here are about paths, authorship and whether the
// finding may still be edited.
package policy

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/export"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

const zero = "0000000000000000000000000000000000000000"

type Update struct{ Old, New, Ref string }

// Checker evaluates pushes against the server's current config, accounts
// and workflow state (never the pushed ones, so a push can't relax its own
// checks).
type Checker struct {
	Repo  *gitrepo.Repo // the repository being pushed to
	Eng   string        // its engagement id; "" = the main repo
	Cfg   config.Config
	Users []config.User
	DB    *db.DB // workflow state (nil: every finding counts as a draft)
	// Token is the pushing token's scopes (nil: a password login, which may
	// do whatever the account may): a new finding needs "create", any other
	// change "edit".
	Token *db.TokenInfo

	// ConfigErr, when set, is why the server's own .yars/config.yaml did not
	// load (Cfg is then the defaults): only a push that changes that file
	// is accepted, so a director can repair it over git.
	ConfigErr error

	// Linter, when set, runs the server's check rules (the Check button's
	// engine) on each finding the push changes, as its last commit has it.
	Linter store.Linter

	// Notes is what the pusher should hear even of an accepted push: rule
	// warnings, and rule errors of drafts.
	Notes []string

	// Carry lists approved findings a director changed in the checked push;
	// once the push is accepted the hook moves their approval to the new
	// content (store.CarryApproval).
	Carry []Carry
}

type Carry struct{ Eng, Fid, OldHash, NewHash string }

// TokenScopesEnv carries a git token's scopes (comma-separated) from the
// server to the pre-receive hook; unset for a password login.
const TokenScopesEnv = "YARS_TOKEN_SCOPES"

// TokenFromEnv turns the TokenScopesEnv value (set reports whether it was
// present) into the Checker's Token.
func TokenFromEnv(v string, set bool) *db.TokenInfo {
	if !set {
		return nil
	}
	var scopes []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	if len(scopes) == 0 {
		scopes = []string{db.ScopeRead} // fail closed
	}
	return &db.TokenInfo{Scopes: scopes}
}

// scopeFor is the token action a change needs: "create" for anything in a
// finding folder whose finding.md did not exist before the push, "edit"
// for everything else (changes and deletions).
func (c *Checker) scopeFor(old string, ch gitrepo.Change) string {
	seg := strings.Split(ch.Path, "/")
	if c.Eng != "" && len(seg) >= 3 && seg[0] == "findings" && ch.Status != 'D' {
		if old == "" {
			return "create"
		}
		if _, err := c.Repo.Show(old, "findings/"+seg[1]+"/finding.md"); err != nil {
			return "create"
		}
	}
	return "edit"
}

func manager(u config.User) bool { return workflow.AtLeast(u, "director") }

func (c *Checker) user(name string) (config.User, bool) {
	for _, x := range c.Users {
		if x.Username == name {
			return x, true
		}
	}
	return config.User{}, false
}

// Check returns the problems with a push by username (empty = accept).
func (c *Checker) Check(username string, ups []Update) []string {
	u, ok := c.user(username)
	if !ok {
		return []string{"unknown user " + username}
	}
	if u.Disabled {
		return []string{"account " + username + " is disabled"}
	}
	// commits are told apart by their author email only: an email two
	// accounts share (set before emails had to be unique) proves nothing
	for _, x := range c.Users {
		if x.Username != u.Username && config.SameEmail(x.GitAuthor().Email, u.GitAuthor().Email) {
			return []string{fmt.Sprintf("the email %s of account %s is also the email of account %s; one of them must change it in Settings › Account before either can push",
				u.GitAuthor().Email, u.Username, x.Username)}
		}
	}
	if c.Eng != "" && c.DB != nil {
		// fail closed: a database error refuses the push
		if m, err := c.DB.EngMeta(c.Eng); err != nil || m.Archived {
			return []string{"engagement " + c.Eng + " is archived (read only)"}
		}
		if !store.SeesAll(u) {
			if member, err := c.DB.IsMember(c.Eng, u.Username); err != nil || !member {
				return []string{"you are not on the team of engagement " + c.Eng}
			}
		}
	}
	branch, err := c.Repo.CurrentBranch()
	if err != nil {
		return []string{"server: " + err.Error()}
	}
	var ps []string
	repairs := false // the push changes .yars/config.yaml (see ConfigErr)
	for _, up := range ups {
		if up.Ref != branch {
			ps = append(ps, up.Ref+": only "+branch+" can be pushed")
			continue
		}
		if up.New == zero {
			ps = append(ps, up.Ref+": deleting the branch is not allowed")
			continue
		}
		old := up.Old
		if old == zero {
			old = ""
		}
		// a commit made on the website between the client's read of the
		// refs and its push: refuse before git checks the pushed tree out
		if c.Repo.Ref(up.Ref) != old {
			ps = append(ps, up.Ref+": the server has newer commits; pull, then push again")
			continue
		}
		// every commit is checked on its own, as if it were made on the
		// website: history keeps each one, not only the last
		commits, err := c.Repo.Commits(old, up.New)
		if err != nil {
			ps = append(ps, "server: "+err.Error())
			continue
		}
		lastMerge := ""
		for _, cm := range commits {
			cps, rep := c.checkCommit(u, cm, old)
			ps = append(ps, cps...)
			repairs = repairs || rep
			if len(cm.Parents) > 1 {
				lastMerge = cm.Hash
			}
		}
		if lastMerge != "" {
			// a merge is checked against a parent the pusher picks: what the
			// push changes up to its last merge is checked against the
			// server's copy too, so no choice of parent hides a deletion or a
			// lock (the commits after it are a line, each checked on its own)
			wps, rep := c.checkWhole(u, old, lastMerge, ps)
			ps = append(ps, wps...)
			repairs = repairs || rep
		}
		if len(ps) == 0 {
			// the slow part last: only a push that passed everything else
			ps = append(ps, c.checkRules(old, up.New)...)
		}
		if len(ps) == 0 {
			c.carry(u, old, up.New)
		}
	}
	if c.ConfigErr != nil && !repairs {
		ps = append(ps, "the server's .yars/config.yaml cannot be loaded ("+c.ConfigErr.Error()+"); only an admin's push to the main repository that repairs it is accepted")
	}
	return capped(ps)
}

// maxProblems is how many problems a refusal lists before it sums up the rest.
const maxProblems = 50

func capped(ps []string) []string {
	if len(ps) <= maxProblems {
		return ps
	}
	return append(ps[:maxProblems:maxProblems], fmt.Sprintf("… and %d more problems", len(ps)-maxProblems))
}

// commitChanges lists what commit cm changed against its first parent
// (the empty tree for a root commit). For a merge that is also what the
// other side brought in: it is checked against the first parent's line,
// whatever the other parent is, except the files the merge leaves as the
// server has them now (base, the branch tip before the push; a pull's
// merge of the website's commits).
func (c *Checker) commitChanges(cm gitrepo.PushedCommit, base string) (string, []gitrepo.Change, error) {
	if len(cm.Parents) == 0 {
		cs, err := c.Repo.ChangedFiles("", cm.Hash)
		return "", cs, err
	}
	cs, err := c.Repo.ChangedFiles(cm.Parents[0], cm.Hash)
	if err != nil || len(cm.Parents) == 1 || base == "" {
		return cm.Parents[0], cs, err
	}
	fromServer, err := c.Repo.ChangedFiles(base, cm.Hash)
	if err != nil {
		return "", nil, err
	}
	differs := map[string]bool{}
	for _, ch := range fromServer {
		differs[ch.Path] = true
	}
	cs = slices.DeleteFunc(cs, func(ch gitrepo.Change) bool { return !differs[ch.Path] })
	return cm.Parents[0], cs, nil
}

// checkCommit checks one pushed commit as u: its author and each file it
// changed, against its parent (base: the branch tip before the push). It
// reports whether it changes the main repo's config.yaml (see ConfigErr).
func (c *Checker) checkCommit(u config.User, cm gitrepo.PushedCommit, base string) ([]string, bool) {
	short := cm.Hash
	if len(short) > 7 {
		short = short[:7]
	}
	var ps []string
	// authored as the pusher (audit trail): by the account's email, which
	// does not change the way names do
	if want := u.GitAuthor(); !config.SameEmail(cm.Author.Email, want.Email) {
		ps = append(ps, fmt.Sprintf("commit %s: authored by %s <%s>, but the account %s has the email %s; run git config user.email %s, then git commit --amend --reset-author (or rebase older commits)",
			short, cm.Author.Name, cm.Author.Email, u.Username, want.Email, want.Email))
	}
	parent, changes, err := c.commitChanges(cm, base)
	if err != nil {
		return append(ps, "server: "+err.Error()), false
	}
	cps, repairs := c.checkChanges(u, short, parent, cm.Hash, changes)
	return append(ps, cps...), repairs
}

// checkWhole checks what old..new changes as a whole against old (the
// server's copy), as one commit named after new (a merge), leaving out the
// problems already reported (seen) for the same file.
func (c *Checker) checkWhole(u config.User, old, new string, seen []string) ([]string, bool) {
	short := new
	if len(short) > 7 {
		short = short[:7]
	}
	changes, err := c.Repo.ChangedFiles(old, new)
	if err != nil {
		return []string{"server: " + err.Error()}, false
	}
	known := map[string]bool{}
	for _, p := range seen {
		if rest, ok := strings.CutPrefix(p, "commit "); ok {
			if _, rest, ok = strings.Cut(rest, " "); ok {
				known[rest] = true
			}
		}
	}
	ps, repairs := c.checkChanges(u, short, old, new, changes)
	ps = slices.DeleteFunc(ps, func(p string) bool {
		return known[strings.TrimPrefix(p, "commit "+short+" ")]
	})
	return ps, repairs
}

// checkChanges checks the files changes lists (parent..rev), naming commit
// short in each problem.
func (c *Checker) checkChanges(u config.User, short, parent, rev string, changes []gitrepo.Change) ([]string, bool) {
	var ps []string
	// sizes first: nothing over the limit is read into memory
	var ids, paths []string
	for _, ch := range changes {
		if ch.Status != 'D' && ch.Mode != "160000" {
			ids, paths = append(ids, ch.Blob), append(paths, ch.Path)
		}
	}
	sizes, err := c.Repo.Sizes(ids)
	if err != nil {
		return append(ps, "server: "+err.Error()), false
	}
	big := map[string]int64{}
	for i, p := range paths {
		if sizes[i] > store.MaxAttachment {
			big[p] = sizes[i]
		}
	}
	repairs := false
	for _, ch := range changes {
		if c.Eng == "" && ch.Path == ".yars/config.yaml" {
			repairs = true
		}
		var probs []string
		switch n, tooBig := big[ch.Path]; {
		case strings.ContainsFunc(ch.Path, unicode.IsControl):
			// shown quoted: the name may hold a line break
			ps = append(ps, fmt.Sprintf("commit %s %q: the file name has control characters (such as a line break); rename it", short, ch.Path))
			continue
		case tooBig:
			probs = []string{fmt.Sprintf("%.1f MB; files over 10 MB are not accepted (remove it from the commit: git rm --cached)", float64(n)/(1<<20))}
		case c.Token != nil && !c.Token.Allows(c.scopeFor(parent, ch)):
			probs = []string{"this token cannot " + c.scopeFor(parent, ch) + " findings"}
		case c.Eng == "":
			probs = c.mainFile(u, parent, rev, ch)
		default:
			// rules are written against data-dir paths
			logical := ch
			logical.Path = "engagements/" + c.Eng + "/" + ch.Path
			probs = c.file(u, parent, rev, logical)
		}
		for _, p := range probs {
			ps = append(ps, "commit "+short+" "+ch.Path+": "+p)
		}
	}
	return ps, repairs
}

// checkRules runs the check rules on each finding old..new changes, as new
// has it, and returns the refusals: errors of a finding in verification or
// later (the website gates Submit and Approve on them, so they can't be
// pushed in past that), not counting the ones dismissed on the finding.
// Warnings, and errors of drafts, go to Notes.
func (c *Checker) checkRules(old, new string) []string {
	if c.Linter == nil || c.Eng == "" {
		return nil
	}
	changes, err := c.Repo.ChangedFiles(old, new)
	if err != nil {
		return []string{"server: " + err.Error()}
	}
	short := new
	if len(short) > 7 {
		short = short[:7]
	}
	var ps []string
	for _, ch := range changes {
		seg := strings.Split(ch.Path, "/")
		if ch.Status == 'D' || len(seg) != 3 || seg[0] != "findings" || seg[2] != "finding.md" {
			continue
		}
		nb, err := c.Repo.Show(new, ch.Path)
		if err != nil {
			continue
		}
		f, err := finding.Parse(nb)
		if err != nil {
			continue // refused as unparseable already
		}
		status := "draft"
		if ob, err := c.Repo.Show(old, ch.Path); err == nil && old != "" {
			status = c.status(c.Eng, f.Meta.ID, ob)
		}
		f.Meta.Status = status
		var dismissed map[string]db.Dismissal
		if c.DB != nil {
			if dismissed, err = c.DB.Dismissals(c.Eng, f.Meta.ID); err != nil {
				return []string{"server: " + err.Error()}
			}
		}
		blocks := status == "verification" || status == "complete" || status == "reported"
		for _, v := range c.Linter.Lint(context.Background(), f, rules.All) {
			// as the website: its own dismissal, or one made before they
			// were per row
			if _, ok := db.Lookup(dismissed, v.Rule, v.Target, v.Quote); ok {
				continue
			}
			level := v.Level
			if v.Target == "rules" || v.Target == "ai" {
				level = "could not run" // a broken rule or a missing AI provider
			} else if level == "error" && !blocks {
				level = "error; blocks Submit"
			}
			line := "commit " + short + " " + ch.Path + ": check " + v.Rule + " (" + level + "): " + v.Message
			if q := strings.Join(strings.Fields(v.Quote), " "); q != "" {
				line += fmt.Sprintf(" (%q)", q)
			}
			switch {
			case level == "error":
				ps = append(ps, line)
			case !slices.Contains(c.Notes, line): // a rule may report per section
				c.Notes = append(c.Notes, line)
			}
		}
	}
	return ps
}

// carry records the approved findings a director's accepted push changes
// (old..new as a whole), so their approval moves to the new content.
func (c *Checker) carry(u config.User, old, new string) {
	if c.Eng == "" || !manager(u) || old == "" {
		return
	}
	changes, err := c.Repo.ChangedFiles(old, new)
	if err != nil {
		return
	}
	for _, ch := range changes {
		seg := strings.Split(ch.Path, "/")
		if ch.Status == 'D' || len(seg) != 3 || seg[0] != "findings" || seg[2] != "finding.md" {
			continue
		}
		ob, err1 := c.Repo.Show(old, ch.Path)
		nb, err2 := c.Repo.Show(new, ch.Path)
		of, err3 := finding.Parse(ob)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		if st := c.status(c.Eng, of.Meta.ID, ob); st == "complete" || st == "reported" {
			c.Carry = append(c.Carry, Carry{c.Eng, of.Meta.ID, store.ContentHash(ob), store.ContentHash(nb)})
		}
	}
}

// mainFile checks a change in the main repo: settings only; engagement
// pointers and .gitmodules belong to the server.
func (c *Checker) mainFile(u config.User, old, new string, ch gitrepo.Change) []string {
	// a removed pointer has no mode left: its path tells
	if seg := strings.Split(ch.Path, "/"); ch.Mode == "160000" || ch.Path == ".gitmodules" || (len(seg) == 2 && seg[0] == "engagements" && seg[1] != ".gitkeep") {
		return []string{"engagement pointers are managed by the server; push to the engagement's own repository (/git/e/<id>)"}
	}
	if strings.HasPrefix(ch.Path, "engagements/") && ch.Path != "engagements/.gitkeep" {
		return []string{"findings live in the engagement's own repository; push there (/git/e/<id>)"}
	}
	return c.file(u, old, new, ch)
}

// real maps a data-dir path to a path in the pushed repository.
func (c *Checker) real(p string) string {
	if c.Eng == "" {
		return p
	}
	return strings.TrimPrefix(p, "engagements/"+c.Eng+"/")
}

func (c *Checker) show(rev, path string) ([]byte, bool) {
	if rev == "" {
		return nil, false
	}
	b, err := c.Repo.Show(rev, c.real(path))
	return b, err == nil
}

func (c *Checker) listTree(rev, dir string) ([]string, error) {
	return c.Repo.ListTree(rev, c.real(dir))
}

// outside is the problem with a path outside the layout, in the pushed
// repository's own terms.
func (c *Checker) outside() string {
	if c.Eng != "" {
		return "not allowed here; findings must live under findings/<finding>/"
	}
	return "not allowed here; this repository holds settings (.yars); findings live in each engagement's repository (/git/e/<id>)"
}

// serverOnly are files that exist only on the server and are never in git.
func serverOnly(p string) bool {
	return p == ".yars/users.yaml" || p == ".yars/tokens.yaml" || p == ".yars/secret.key" || strings.HasPrefix(p, ".yars/yars.db")
}

// file checks one changed path.
func (c *Checker) file(u config.User, old, new string, ch gitrepo.Change) []string {
	p := ch.Path
	seg := strings.Split(p, "/")
	if ch.Status != 'D' && ch.Mode != "100644" && ch.Mode != "100755" {
		return []string{"only regular files are allowed (no symlinks or submodules)"}
	}
	for i, s := range seg {
		if strings.HasPrefix(strings.ToLower(s), ".git") && !(i == 0 && (p == ".gitattributes" || p == ".gitignore")) {
			return []string{"git control files are not allowed here"}
		}
	}
	switch {
	case serverOnly(p):
		return []string{"accounts, tokens, keys and the database stay on the server (yars useradd / yars token), not in git"}
	case seg[0] == ".yars":
		if !manager(u) {
			return []string{"only a director can change .yars (config, rules)"}
		}
		if strings.HasPrefix(p, ".yars/config.yaml/") {
			return []string{".yars/config.yaml must be a file"}
		}
		if p == ".yars/config.yaml" || (len(seg) == 3 && seg[1] == "rules") {
			// on the website: Admin › Structure, AI, Rules
			if !u.IsAdmin {
				return []string{"only an admin can change .yars/config.yaml and .yars/rules (on the website: Admin › Structure, AI and Rules)"}
			}
		}
		if p == ".yars/config.yaml" {
			if ch.Status == 'D' {
				return []string{"cannot be deleted (every setting would fall back to its default); push the settings you want instead"}
			}
			// the server applies it as soon as the push lands
			b, _ := c.show(new, p)
			if _, err := store.CheckConfig(b); err != nil {
				return []string{err.Error()}
			}
		}
		if len(seg) == 3 && seg[1] == "rules" && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			// as Admin › Rules: no load problem the folder did not have
			ps := rules.NewProblems(c.ruleSet(old), c.ruleSet(new))
			var out []string
			for _, pr := range ps {
				if strings.Contains(pr.Message, "("+seg[2]+")") {
					out = append(out, pr.Message)
				}
			}
			return out
		}
		if len(seg) == 3 && seg[1] == "exporters" && strings.HasSuffix(p, ".yaml") && ch.Status != 'D' {
			return c.exporterProblems(u, old, new, p, seg[2])
		}
		if len(seg) == 3 && seg[1] == "templates" && strings.HasSuffix(p, ".md") && ch.Status != 'D' {
			// findings made from a template take its content as it is
			b, _ := c.show(new, p)
			f, err := finding.Parse(b)
			if err != nil {
				return []string{"cannot parse: " + err.Error()}
			}
			var of *finding.Finding
			if ob, ok := c.show(old, p); ok {
				of, _ = finding.Parse(ob)
			}
			return store.FindingProblems(c.Cfg, f, of)
		}
		return nil
	case p == ".gitattributes":
		if !manager(u) {
			return []string{"only a director can change .gitattributes"}
		}
		return nil
	case p == "README.md" || p == "engagements/.gitkeep" || p == ".gitignore":
		if p == ".gitignore" && !manager(u) {
			return []string{"only a director can change .gitignore"}
		}
		return nil
	case len(seg) < 3 || seg[0] != "engagements" || !store.ValidID(seg[1]):
		return []string{c.outside()}
	case len(seg) == 3 && seg[2] == "engagement.yaml":
		if !manager(u) {
			return []string{"only a director can create or change engagements"}
		}
		if ch.Status == 'D' {
			return []string{"engagement.yaml cannot be deleted (a director archives an engagement in YARS)"}
		}
		b, _ := c.show(new, p)
		e, err := store.ParseEngagement(b)
		if err != nil {
			return []string{"cannot parse: " + err.Error()}
		}
		// as the engagement's Settings tab saves it; type and source stay
		var prev *store.Engagement
		if ob, ok := c.show(old, p); ok {
			if pe, err := store.ParseEngagement(ob); err == nil {
				prev = &pe
			}
		}
		if err := store.CheckEngagement(prev, e); err != nil {
			return []string{plain(err)}
		}
		return nil
	}
	// everything else lives inside an existing engagement and finding
	if _, ok := c.show(new, "engagements/"+seg[1]+"/engagement.yaml"); !ok && ch.Status != 'D' {
		return []string{"engagement " + seg[1] + " does not exist (a director creates engagements)"}
	}
	// report-level sections: Markdown bodies the team writes
	if slug, ok := strings.CutSuffix(seg[len(seg)-1], ".md"); len(seg) == 4 && seg[2] == "report" && ok && store.ValidID(slug) {
		if ch.Status == 'D' {
			return nil
		}
		if b, ok := c.show(new, p); ok {
			if err := finding.ValidateBody(string(b)); err != nil {
				return []string{err.Error()}
			}
		}
		return nil
	}
	if len(seg) >= 5 && seg[2] == "findings" && store.ValidID(seg[3]) {
		fp := strings.Join(seg[:4], "/") + "/finding.md"
		switch {
		case len(seg) == 5 && seg[4] == "finding.md":
			return c.findingFile(u, old, new, ch, seg[1], seg[3])
		case len(seg) == 5 && seg[4] == "chat.jsonl":
			if ch.Status == 'D' {
				return nil // removing a leftover from before the database
			}
			return []string{"chat lives in YARS now (web UI or /mcp), not in git"}
		case len(seg) >= 6 && seg[4] == "attachments":
			// locked with the finding's text
			if p := c.attachmentLock(u, old, seg[1], seg[3]); p != "" {
				return []string{p}
			}
			if ch.Status == 'D' {
				return nil
			}
			if _, ok := c.show(new, fp); !ok {
				return []string{"attachment for a finding that does not exist"}
			}
			// as the website accepts uploads
			b, _ := c.show(new, p)
			if err := store.CheckAttachment(strings.Join(seg[5:], "/"), b, ch.Mode == "100755"); err != nil {
				return []string{plain(err)}
			}
			return nil
		}
		// already inside a finding: only its attachments folder is open
		return []string{"not allowed here; a finding's files go in findings/<finding>/attachments/"}
	}
	return []string{c.outside()}
}

// ruleSet loads the main repo's rule files as rev has them (none for "").
func (c *Checker) ruleSet(rev string) *rules.Set {
	files := map[string][]byte{}
	if rev != "" {
		names, _ := c.Repo.ListTree(rev, ".yars/rules")
		for _, n := range names {
			if b, err := c.Repo.Show(rev, ".yars/rules/"+n); err == nil {
				files[n] = b
			}
		}
	}
	return rules.LoadFiles(".yars/rules", files)
}

// exporterProblems checks a pushed exporter file as the export setup
// saves one: its id, its settings, and an admin for a service address.
func (c *Checker) exporterProblems(u config.User, old, new, p, file string) []string {
	if !export.IDRe.MatchString(strings.TrimSuffix(file, ".yaml")) {
		return []string{"exporter ids are lowercase letters, digits, - and _ (the file is <id>.yaml)"}
	}
	b, _ := c.show(new, p)
	ex, err := export.Parse(file, b)
	if err != nil {
		return []string{err.Error()}
	}
	var prev *export.Exporter
	if ob, ok := c.show(old, p); ok {
		if pe, err := export.Parse(file, ob); err == nil {
			prev = &pe
		}
	}
	if export.NeedsAdmin(prev, ex) && !u.IsAdmin {
		// the address gets the server's and the authors' keys
		return []string{"address and key variables: admin only"}
	}
	return nil
}

// plain is a shared rule's error without its "invalid value" prefix.
func plain(err error) string {
	return strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")
}

// status is the finding's workflow status for content raw, from the
// database (a complete finding whose content changed after approval counts
// as in verification, as everywhere else).
func (c *Checker) status(eng, fid string, raw []byte) string {
	if c.DB == nil {
		return "draft"
	}
	st, err := c.DB.State(eng, fid)
	if err != nil {
		return "complete" // fail closed: only a director may edit
	}
	if (st.Status == "complete" || st.Status == "reported") && !store.Approved(st, store.ContentHash(raw)) {
		return "verification"
	}
	return st.Status
}

// lockProblem is why u may not change finding o by push (its status from
// the database), "" when u may: complete, reported and withdrawn findings
// are a director's to change; one in verification its assigned reviewers'
// and directors'.
func (c *Checker) lockProblem(u config.User, eng string, o finding.Meta) string {
	switch o.Status {
	case "complete", "reported", workflow.Withdrawn:
		if !manager(u) {
			return o.ID + " is " + o.Status + "; only a director can change it"
		}
	case "verification":
		if manager(u) {
			return ""
		}
		var revs []string
		if c.DB != nil {
			st, err := c.DB.State(eng, o.ID)
			if err != nil {
				return o.ID + " is in verification; only directors can change it (its reviewers could not be read)"
			}
			for _, r := range st.Reviewers {
				revs = append(revs, r.Name)
			}
		}
		if slices.Contains(revs, u.Username) {
			return ""
		}
		if len(revs) == 0 {
			return o.ID + " is in verification; only its reviewers and directors can change it (it has no reviewers)"
		}
		return o.ID + " is in verification; only its reviewers (" + strings.Join(revs, ", ") + ") and directors can change it"
	}
	return ""
}

// attachmentLock is why u may not change the attachments of finding
// folder dir of eng as they were at old ("" when u may, or when the finding
// is new).
func (c *Checker) attachmentLock(u config.User, old, eng, dir string) string {
	ob, ok := c.show(old, "engagements/"+eng+"/findings/"+dir+"/finding.md")
	if !ok {
		return ""
	}
	of, err := finding.Parse(ob)
	if err != nil {
		if manager(u) {
			return ""
		}
		return "the finding cannot be parsed; only a director can change it"
	}
	o := of.Meta
	o.Status = c.status(eng, o.ID, ob)
	return c.lockProblem(u, eng, o)
}

// reusesDeletedID reports whether a new finding takes the id of a finding
// that no longer exists but still has workflow state or chat. A folder
// renamed within the push (the id still existed before) is fine.
func (c *Checker) reusesDeletedID(old, eng, id string) bool {
	if c.DB == nil || id == "" {
		return false
	}
	if before, err := c.listTree(old, "engagements/"+eng+"/findings"); err == nil && old != "" {
		for _, o := range before {
			if o == id || strings.HasPrefix(o, id+"-") {
				return false
			}
		}
	}
	known, err := c.DB.Known(eng, id)
	return err != nil || known
}

func (c *Checker) findingFile(u config.User, old, new string, ch gitrepo.Change, eng, dir string) []string {
	if ch.Status == 'D' {
		if !manager(u) {
			return []string{"only a director can delete a finding"}
		}
		return nil
	}
	nb, _ := c.show(new, ch.Path)
	nf, err := finding.Parse(nb)
	if err != nil {
		return []string{"cannot parse: " + err.Error()}
	}
	n := nf.Meta
	ob, existed := c.show(old, ch.Path)
	var of *finding.Finding
	if existed {
		of, _ = finding.Parse(ob)
	}
	// the website's rules, for the parts this commit changes
	ps := store.FindingProblems(c.Cfg, nf, of)
	if !existed {
		if n.Author != u.Username {
			if _, ok := c.user(n.Author); !manager(u) || !ok {
				ps = append(ps, "author must be you ("+u.Username+")")
			}
		}
		if n.ID == "" || !(dir == n.ID || strings.HasPrefix(dir, n.ID+"-")) {
			ps = append(ps, fmt.Sprintf("id %s does not match the directory %s", n.ID, dir))
		}
		if others, err := c.listTree(new, "engagements/"+eng+"/findings"); err == nil && n.ID != "" {
			for _, o := range others {
				if o != dir && (o == n.ID || strings.HasPrefix(o, n.ID+"-")) {
					ps = append(ps, "duplicate id "+n.ID+" (also "+o+")")
				}
			}
		}
		if c.reusesDeletedID(old, eng, n.ID) {
			ps = append(ps, "id "+n.ID+" belonged to a deleted finding (its review history is kept); use a new number")
		}
		return ps
	}
	if of == nil {
		if !manager(u) {
			return append(ps, "the previous version cannot be parsed; only a director can repair it")
		}
		return ps
	}
	if bytes.Equal(ob, nb) {
		return ps
	}
	o := of.Meta
	o.Status = c.status(eng, o.ID, ob)
	if p := c.lockProblem(u, eng, o); p != "" {
		return append(ps, p)
	}
	if n.ID != o.ID {
		ps = append(ps, "id cannot change")
	}
	if n.Author != o.Author {
		ps = append(ps, "author cannot change")
	}
	return ps
}
