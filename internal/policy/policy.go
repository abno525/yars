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

func manager(u config.User) bool { return u.Role == "director" || u.Role == "admin" }

// Check returns the problems with a push by username (empty = accept).
func (c *Checker) Check(username string, ups []Update) []string {
	var u config.User
	for _, x := range c.Users {
		if x.Username == username {
			u = x
		}
	}
	if u.Username == "" {
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

// file checks one changed path.
func (c *Checker) file(u config.User, old, new string, ch gitrepo.Change) []string {
	p := ch.Path
	seg := strings.Split(p, "/")
	switch {
	case seg[0] == ".yars":
		if !manager(u) {
			return []string{"only a director or admin can change .yars (config, users, rules)"}
		}
		return nil
	case p == ".gitattributes" || p == "README.md" || p == "engagements/.gitkeep":
		return nil
	case len(seg) < 3 || seg[0] != "engagements" || !store.ValidID(seg[1]):
		return []string{"not allowed here; findings must live under engagements/<engagement>/findings/<finding>/"}
	case len(seg) == 3 && seg[2] == "engagement.yaml":
		if !manager(u) {
			return []string{"only a director or admin can create or change engagements"}
		}
		return nil
	case len(seg) >= 5 && seg[2] == "findings" && store.ValidID(seg[3]):
		switch {
		case len(seg) == 5 && seg[4] == "finding.md":
			return c.findingFile(u, old, new, ch, seg[1], seg[3])
		case len(seg) == 5 && seg[4] == "chat.jsonl":
			return c.chatFile(u, old, new, p)
		case len(seg) >= 6 && seg[4] == "attachments":
			return nil
		}
	}
	return []string{"not allowed here; findings must live under engagements/<engagement>/findings/<finding>/"}
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

func (c *Checker) findingFile(u config.User, old, new string, ch gitrepo.Change, eng, dir string) []string {
	if ch.Status == 'D' {
		if !manager(u) {
			return []string{"only a director or admin can delete a finding"}
		}
		return nil
	}
	nb, _ := c.show(new, ch.Path)
	nf, ps := parse(nb)
	if nf == nil {
		return ps
	}
	n := nf.Meta
	ob, existed := c.show(old, ch.Path)
	if !existed || ch.Status == 'A' {
		if n.Status != "draft" {
			ps = append(ps, "a new finding must start as draft")
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
	of, _ := parse(ob)
	if of == nil {
		return ps // old version was broken; accept a parseable fix
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
	if !slices.Equal(n.Reviewers, o.Reviewers) && !workflow.CanAssign(u, o) {
		ps = append(ps, "only the author or a director can change reviewers")
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
		}
		if workflow.Gated(act) && c.Linter != nil {
			if errs := rules.Errors(c.Linter.Lint(context.Background(), nf, rules.All)); len(errs) > 0 {
				ps = append(ps, "rules: "+strings.Join(errs, "; "))
			}
		}
	}
	// clearances: only the pusher may add themselves, through a legitimate clear
	var added []string
	for _, x := range n.ClearedBy {
		if !slices.Contains(o.ClearedBy, x) {
			added = append(added, x)
		}
	}
	if len(added) > 0 {
		if len(added) != 1 || added[0] != u.Username {
			ps = append(ps, "cleared_by may only gain your own name")
		} else if err := workflow.Check(u, o, workflow.Clear); err != nil {
			ps = append(ps, "cleared_by: "+err.Error())
		}
	}
	if n.Returned != nil && !reflect.DeepEqual(n.Returned, o.Returned) {
		if act != workflow.Return || n.Returned.By != u.Username || strings.TrimSpace(n.Returned.Reason) == "" {
			ps = append(ps, "returned may only be set when you return the finding to draft with a reason")
		}
	}
	return ps
}

func (c *Checker) chatFile(u config.User, old, new, path string) []string {
	ob, _ := c.show(old, path)
	nb, ok := c.show(new, path)
	if !ok {
		return []string{"chat history cannot be deleted"}
	}
	if !bytes.HasPrefix(nb, ob) {
		return []string{"chat is append-only; existing lines cannot change"}
	}
	var ps []string
	for _, m := range chat.Parse(nb[len(ob):]) {
		if m.User != u.Username {
			ps = append(ps, "message "+m.ID+" is from "+m.User+"; you can only add your own messages")
		}
		if m.Event != "" {
			ps = append(ps, "message "+m.ID+": workflow events can't be pushed")
		}
	}
	return ps
}
