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
	Repo  *gitrepo.Repo
	Cfg   config.Config
	Users []config.User
	DB    *db.DB // workflow state (nil: every finding counts as a draft)
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
	branch, err := c.Repo.CurrentBranch()
	if err != nil {
		return []string{"server: " + err.Error()}
	}
	var ps []string
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
			for _, p := range c.file(u, old, up.New, ch) {
				ps = append(ps, ch.Path+": "+p)
			}
		}
	}
	return ps
}

func (c *Checker) show(rev, path string) ([]byte, bool) {
	if rev == "" {
		return nil, false
	}
	b, err := c.Repo.Show(rev, path)
	return b, err == nil
}

const outsideMsg = "not allowed here; findings must live under engagements/<engagement>/findings/<finding>/"

// serverOnly are files that exist only on the server and are never in git.
func serverOnly(p string) bool {
	return p == ".yars/users.yaml" || p == ".yars/tokens.yaml" || strings.HasPrefix(p, ".yars/yars.db")
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
		return []string{"accounts, tokens and the database stay on the server (yars useradd / yars token), not in git"}
	case seg[0] == ".yars":
		if !manager(u) {
			return []string{"only a director can change .yars (config, rules)"}
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

// status is the finding's workflow status from the database.
func (c *Checker) status(eng, fid string) string {
	if c.DB == nil {
		return "draft"
	}
	st, err := c.DB.State(eng, fid)
	if err != nil {
		return "complete" // fail closed: only a director may edit
	}
	return st.Status
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
		if others, err := c.Repo.ListTree(new, "engagements/"+eng+"/findings"); err == nil && n.ID != "" {
			for _, o := range others {
				if o != dir && (o == n.ID || strings.HasPrefix(o, n.ID+"-")) {
					ps = append(ps, "duplicate id "+n.ID+" (also "+o+")")
				}
			}
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
	o.Status = c.status(eng, o.ID)
	if !workflow.CanEdit(u, o) {
		return append(ps, "the finding is "+o.Status+"; only a director can change it")
	}
	if n.ID != o.ID {
		ps = append(ps, "id cannot change")
	}
	if n.Author != o.Author {
		ps = append(ps, "author cannot change")
	}
	return ps
}
