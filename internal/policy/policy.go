// Package policy decides whether a git push may update the data repo: the
// same workflow, permission and style rules as the web UI, applied to the
// difference between the old and new trees.
package policy

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

const zero = "0000000000000000000000000000000000000000"

type Update struct{ Old, New, Ref string }

// Checker evaluates pushes against the server's current config, users and
// rules (never the pushed ones, so a push can't relax its own checks).
type Checker struct {
	Repo   *gitrepo.Repo
	Cfg    config.Config
	Users  []config.User
	Linter store.Linter
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
	case p == ".yars/users.yaml" || p == ".yars/tokens.yaml":
		return []string{"accounts and API tokens are managed on the server (yars useradd / yars token), not in git"}
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
			if _, ok := c.show(new, fp); !ok && ch.Status != 'D' {
				return []string{"chat for a finding that does not exist"}
			}
			return c.chatFile(u, old, new, p, fp)
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
	return f, ps
}

// reviewersOK checks that every reviewer not already assigned is a real
// reviewer/director account other than the author, without duplicates.
func (c *Checker) reviewersOK(n finding.Meta, old []string) []string {
	var ps []string
	seen := map[string]bool{}
	for _, r := range n.Reviewers {
		if seen[r] {
			ps = append(ps, "duplicate reviewer "+r)
		}
		seen[r] = true
		if slices.Contains(old, r) {
			continue
		}
		ru, ok := c.user(r)
		if !ok || !workflow.ReviewerCandidate(ru, n) {
			ps = append(ps, "reviewer "+r+" must be an existing reviewer or director account other than the author")
		}
	}
	return ps
}

func (c *Checker) severityOK(n finding.Meta) []string {
	if n.Severity != "" && !slices.Contains(c.Cfg.Severities, n.Severity) {
		return []string{"unknown severity " + n.Severity}
	}
	return nil
}

// retestChange allows only the result of an existing retest link to change.
func retestChange(o, n *finding.Retest) []string {
	switch {
	case o == nil && n == nil:
		return nil
	case o == nil:
		return []string{"a retest block cannot be added to a finding"}
	case n == nil:
		return []string{"the retest block cannot be removed"}
	case n.Source != o.Source:
		return []string{"the retest source cannot change"}
	case n.Result != "" && !slices.Contains(workflow.RetestResults, n.Result):
		return []string{"retest result " + n.Result + " must be fixed, not_fixed or partially_fixed"}
	}
	return nil
}

// sameExceptClearances reports whether two versions differ only in cleared_by.
// A reviewer list that only gained self (a director reviewing unassigned)
// also counts as unchanged.
func sameExceptClearances(o, n *finding.Finding, self string) bool {
	om, nm := o.Meta, n.Meta
	om.ClearedBy, nm.ClearedBy = nil, nil
	if slices.Equal(nm.Reviewers, append(slices.Clone(om.Reviewers), self)) {
		nm.Reviewers = om.Reviewers
	}
	return reflect.DeepEqual(om, nm) && reflect.DeepEqual(o.Sections, n.Sections) && o.Preamble == n.Preamble
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
		// a new finding carries no workflow state
		if n.Status != "draft" {
			ps = append(ps, "a new finding must start as draft")
		}
		if n.Author != u.Username {
			if _, ok := c.user(n.Author); !manager(u) || !ok {
				ps = append(ps, "author must be you ("+u.Username+")")
			}
		}
		if len(n.ClearedBy) > 0 {
			ps = append(ps, "a new finding cannot have cleared_by")
		}
		if n.Returned != nil {
			ps = append(ps, "a new finding cannot have returned")
		}
		if n.Retest != nil && !manager(u) {
			ps = append(ps, "a new finding cannot carry a retest block (directors start retests)")
		}
		ps = append(ps, c.reviewersOK(n, nil)...)
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
	of, _ := parse(ob)
	if of == nil {
		if !manager(u) {
			return append(ps, "the server copy cannot be parsed; only a director can repair it")
		}
		return ps
	}
	o := of.Meta
	if bytes.Equal(ob, nb) {
		return ps
	}
	if !workflow.CanEdit(u, o) {
		return append(ps, "the finding is "+o.Status+"; only a director can change it")
	}
	if n.ID != o.ID {
		ps = append(ps, "id cannot change")
	}
	if n.Author != o.Author {
		ps = append(ps, "author cannot change")
	}
	ps = append(ps, retestChange(o.Retest, n.Retest)...)
	if !slices.Equal(n.Reviewers, o.Reviewers) {
		if !workflow.CanAssign(u, o) {
			ps = append(ps, "only the author or a director can change reviewers")
		}
		ps = append(ps, c.reviewersOK(n, o.Reviewers)...)
	}
	for _, x := range n.ClearedBy {
		if !slices.Contains(n.Reviewers, x) {
			ps = append(ps, "cleared_by lists "+x+", who is not a reviewer")
		}
	}
	var act workflow.Action
	if n.Status != o.Status {
		for _, a := range workflow.Actions {
			if from, to := workflow.Target(a); from == o.Status && to == n.Status && a != workflow.Clear {
				act = a
			}
		}
		if act == "" {
			return append(ps, fmt.Sprintf("status change %s → %s is not allowed", o.Status, n.Status))
		}
		// permissions are judged on the old state, the gate on the new content
		if err := workflow.Check(u, o, act); err != nil {
			return append(ps, err.Error())
		}
		if workflow.Gated(act) {
			if g := workflow.Gate(n, c.Cfg); len(g) > 0 {
				ps = append(ps, "cannot "+strings.ToLower(workflow.Label(act))+": "+strings.Join(g, "; "))
			}
			if c.Linter != nil {
				if errs := rules.Errors(c.Linter.Lint(context.Background(), nf, rules.All)); len(errs) > 0 {
					ps = append(ps, "rules: "+strings.Join(errs, "; "))
				}
			}
		}
		switch act {
		case workflow.Submit, workflow.Reopen, workflow.Return:
			if len(n.ClearedBy) > 0 {
				ps = append(ps, "cleared_by must be emptied when the finding goes back for review")
			}
		}
		if act == workflow.Submit && n.Returned != nil {
			ps = append(ps, "remove returned when resubmitting")
		}
		if act == workflow.Return && (n.Returned == nil || n.Returned.By != u.Username || strings.TrimSpace(n.Returned.Reason) == "") {
			ps = append(ps, "a return needs returned: {by: "+u.Username+", reason: <why>}")
		}
	}
	if n.Returned != nil && !reflect.DeepEqual(n.Returned, o.Returned) && act != workflow.Return {
		ps = append(ps, "returned may only be set when you return the finding to draft with a reason")
	}
	// clearances: only the pusher may add themselves, through a legitimate clear
	var added []string
	for _, x := range n.ClearedBy {
		if !slices.Contains(o.ClearedBy, x) {
			added = append(added, x)
		}
	}
	if len(added) > 0 {
		if len(added) != 1 || added[0] != u.Username || act != "" {
			ps = append(ps, "cleared_by may only gain your own name, through a clear")
		} else if err := workflow.Check(u, o, workflow.Clear); err != nil {
			ps = append(ps, "cleared_by: "+err.Error())
		}
	}
	// any other change during review drops all clearances (as on the web)
	if o.Status == "verification" && n.Status == "verification" && len(n.ClearedBy) > 0 {
		self := ""
		if len(added) == 1 && added[0] == u.Username && !slices.Contains(o.Reviewers, u.Username) {
			self = u.Username
		}
		if !sameExceptClearances(of, nf, self) {
			ps = append(ps, "cleared_by must be emptied when the finding changes during review")
		}
	}
	return ps
}

func (c *Checker) chatFile(u config.User, old, new, path, findingPath string) []string {
	ob, _ := c.show(old, path)
	nb, ok := c.show(new, path)
	if !ok {
		if _, fok := c.show(new, findingPath); !fok && manager(u) {
			return nil // a director deleting the whole finding
		}
		return []string{"chat history cannot be deleted"}
	}
	if len(ob) > 0 && !bytes.HasSuffix(ob, []byte("\n")) {
		return []string{"chat is append-only; the server copy must end with a newline"}
	}
	if !bytes.HasPrefix(nb, ob) {
		return []string{"chat is append-only; existing lines cannot change"}
	}
	var ps []string
	existing := chat.Parse(ob)
	for _, m := range chat.Parse(nb[len(ob):]) {
		if m.User != u.Username {
			ps = append(ps, "message "+m.ID+" is from "+m.User+"; you can only add your own messages")
		}
		if m.Event != "" {
			ps = append(ps, "message "+m.ID+": workflow events can't be pushed")
		}
		if err := chat.Validate(existing, m); err != nil {
			ps = append(ps, "message "+m.ID+": "+err.Error())
		}
		existing = append(existing, m)
	}
	return ps
}
