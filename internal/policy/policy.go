// Package policy decides whether a git push may update the data repo. A
// push carries content only: workflow state and chat live in the YARS
// database, so the rules here are about paths, authorship and whether the
// finding may still be edited.
package policy

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
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
		// every pushed commit must be authored as the pusher (audit trail)
		authors, err := c.Repo.Authors(old, up.New)
		if err != nil {
			ps = append(ps, "server: "+err.Error())
			continue
		}
		want := u.GitAuthor()
		for _, a := range authors {
			if a.Email != want.Email && a.Name != u.Username {
				ps = append(ps, fmt.Sprintf("commit %.8s is authored by %s <%s>; commit as yourself (git config user.email %s)", a.Hash, a.Name, a.Email, want.Email))
			}
		}
		changes, err := c.Repo.ChangedFiles(old, up.New)
		if err != nil {
			ps = append(ps, "server: "+err.Error())
			continue
		}
		for _, ch := range changes {
			if c.Eng == "" && ch.Path == ".yars/config.yaml" {
				repairs = true
			}
			if c.Token != nil {
				if need := c.scopeFor(old, ch); !c.Token.Allows(need) {
					ps = append(ps, ch.Path+": this token cannot "+need+" findings")
					continue
				}
			}
			var probs []string
			if c.Eng == "" {
				probs = c.mainFile(u, old, up.New, ch)
			} else {
				// rules are written against data-dir paths
				logical := ch
				logical.Path = "engagements/" + c.Eng + "/" + ch.Path
				probs = c.file(u, old, up.New, logical)
			}
			for _, p := range probs {
				ps = append(ps, ch.Path+": "+p)
			}
		}
	}
	if c.ConfigErr != nil && !repairs {
		ps = append(ps, "the server's .yars/config.yaml cannot be loaded ("+c.ConfigErr.Error()+"); only a director's push to the main repository that repairs it is accepted")
	}
	return ps
}

// mainFile checks a change in the main repo: settings only; engagement
// pointers and .gitmodules belong to the server.
func (c *Checker) mainFile(u config.User, old, new string, ch gitrepo.Change) []string {
	if ch.Mode == "160000" || ch.Path == ".gitmodules" {
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

const outsideMsg = "not allowed here; findings must live under engagements/<engagement>/findings/<finding>/"

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
		if strings.HasPrefix(strings.ToLower(s), ".git") && !(i == 0 && p == ".gitattributes") {
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
		if p == ".yars/config.yaml" && ch.Status != 'D' {
			// the server loads it on every push and on start
			b, _ := c.show(new, p)
			if _, err := config.Parse(b); err != nil {
				return []string{"cannot load: " + err.Error()}
			}
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
		return []string{outsideMsg}
	case len(seg) == 3 && seg[2] == "engagement.yaml":
		if !manager(u) {
			return []string{"only a director can create or change engagements"}
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
			if _, ok := c.show(new, fp); !ok && ch.Status != 'D' {
				return []string{"attachment for a finding that does not exist"}
			}
			return nil
		}
	}
	return []string{outsideMsg}
}

func parse(b []byte) (*finding.Finding, []string) {
	f, err := finding.Parse(b)
	if err != nil {
		return nil, []string{"cannot parse: " + err.Error()}
	}
	var ps []string
	for _, s := range f.Sections {
		if err := finding.ValidateBody(s.Body); err != nil {
			ps = append(ps, "section "+s.Name+": "+err.Error())
		}
	}
	if l, ok := f.Legacy(); ok {
		ps = append(ps, "workflow state is managed in YARS, not in the file; remove "+strings.Join(l.Keys, ", ")+" from the front matter")
	}
	return f, ps
}

func (c *Checker) severityOK(n finding.Meta) []string {
	if n.Severity != "" && !slices.Contains(c.Cfg.Severities, n.Severity) {
		return []string{"unknown severity " + n.Severity}
	}
	return nil
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
	nf, ps := parse(nb)
	if nf == nil {
		return ps
	}
	n := nf.Meta
	ps = append(ps, c.severityOK(n)...)
	ob, existed := c.show(old, ch.Path)
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
	of, _ := finding.Parse(ob)
	if of == nil {
		if !manager(u) {
			return append(ps, "the server copy cannot be parsed; only a director can repair it")
		}
		return ps
	}
	if bytes.Equal(ob, nb) {
		return ps
	}
	o := of.Meta
	o.Status = c.status(eng, o.ID, ob)
	if !workflow.CanEdit(u, o) {
		return append(ps, "the finding is "+o.Status+"; only a director can change it")
	}
	if n.ID != o.ID {
		ps = append(ps, "id cannot change")
	}
	if n.Author != o.Author {
		ps = append(ps, "author cannot change")
	}
	if o.Status == "complete" || o.Status == "reported" {
		c.Carry = append(c.Carry, Carry{eng, o.ID, store.ContentHash(ob), store.ContentHash(nb)})
	}
	return ps
}
