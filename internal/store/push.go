package store

import (
	"log"
	"path"
	"reflect"
	"slices"
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

// partAttachments names a change to a finding's files other than
// finding.md in finding.updated.
const partAttachments = "Attachments"

// changedParts lists what differs between two versions of a finding: front
// matter parts first, then sections (in the new file's order, removed ones
// last).
func changedParts(old, cur *finding.Finding) []string {
	var out []string
	om, nm := old.Meta, cur.Meta
	if om.Title != nm.Title {
		out = append(out, "Title")
	}
	if om.Severity != nm.Severity {
		out = append(out, "Severity")
	}
	if om.CVSS != nm.CVSS || !reflect.DeepEqual(om.CVSSReasons, nm.CVSSReasons) {
		out = append(out, "CVSS")
	}
	if !reflect.DeepEqual(om.Details, nm.Details) {
		out = append(out, "Details")
	}
	if !reflect.DeepEqual(om.Assets, nm.Assets) {
		out = append(out, "Assets")
	}
	for _, sec := range cur.Sections {
		if b, ok := old.Section(sec.Name); !ok || b != sec.Body {
			out = append(out, sec.Name)
		}
	}
	for _, sec := range old.Sections {
		if _, ok := cur.Section(sec.Name); !ok {
			out = append(out, sec.Name)
		}
	}
	return out
}

// updatedEvent is the finding.updated event of an edit of ref (as it is
// now) from before (nil: only other files changed).
func updatedEvent(actor string, ref FindingRef, before *finding.Finding, files bool) Event {
	ev := findingEvent(EventUpdated, actor, ref)
	if before != nil {
		ev.Changed = changedParts(before, ref.F)
	}
	if files {
		ev.Changed = append(ev.Changed, partAttachments)
	}
	return ev
}

// filesEvent is the finding.updated event of a commit of files (data-dir
// paths with their previous content) touching ref, whose file is fp.
func filesEvent(actor string, ref FindingRef, fp string, prev, files map[string][]byte) Event {
	var old *finding.Finding
	if b, ok := files[fp]; ok {
		if o, err := finding.Parse(prev[fp]); err == nil {
			old = o
		}
		if cur, err := finding.Parse(b); err == nil {
			cur.Meta.Status, cur.Meta.Reviewers = ref.F.Meta.Status, ref.F.Meta.Reviewers
			ref.F = cur
		}
	}
	other := false
	for p := range files {
		if p != fp && strings.HasPrefix(p, path.Dir(fp)+"/") {
			other = true
		}
	}
	return updatedEvent(actor, ref, old, other)
}

// ReceivePush runs serve (git receiving a push into engagement eng's repo,
// as u) under the engagement's lock, so no commit by YARS lands in
// between. Once the push landed it moves the workflow state as the same
// changes through YARS would (pushState), then emits the events they stand
// for, as if u had made them through YARS: finding.created for each new
// finding and finding.updated for each changed one. A rejected push moves
// nothing and emits nothing.
//
// eng "" is the main repo: the push runs under the main repo's lock and
// emits nothing; the settings it brings apply at once (config.yaml is read
// again; rules, exporters and templates are read from disk on each use).
func (s *Store) ReceivePush(eng string, u config.User, serve func()) {
	if eng == "" {
		s.mainMu.Lock()
		before, _ := s.freshHead("")
		serve()
		s.Invalidate("")
		after, err := s.freshHead("")
		if err == nil && after == before {
			restoreTree("the main repo", s.repo)
		}
		s.mainMu.Unlock()
		if err == nil && after != before {
			s.reloadConfig()
		}
		return
	}
	if !ValidID(eng) {
		serve()
		return
	}
	l := s.engLock(eng)
	l.Lock()
	before, _ := s.freshHead(eng)
	serve()
	s.Invalidate(eng)
	after, err := s.freshHead(eng)
	if err == nil && after == before {
		if r, rerr := s.EngRepo(eng); rerr == nil {
			restoreTree(eng, r)
		}
	}
	var evs []Event
	if err == nil && after != "" && after != before {
		// read under the lock: a purge (D28) waiting on it rewrites the
		// pushed commits
		ps, err := s.pushedFindings(eng, before, after)
		if err != nil {
			log.Printf("push to %s: %v", eng, err)
		} else {
			s.pushState(eng, u, ps)
			if evs, err = s.pushEvents(eng, u.Username, ps); err != nil {
				log.Printf("push to %s: events: %v", eng, err)
			}
		}
	}
	l.Unlock()
	for _, ev := range evs {
		s.notify(Change{Eng: eng, Fid: ev.Fid, Kind: ChangeContent})
		s.Emit(ev)
	}
}

// restoreTree puts r's work tree back to HEAD after a push that did not
// move the branch: git checks a pushed tree out before it updates the ref,
// so a failed ref update must not leave that tree behind.
func restoreTree(name string, r *gitrepo.Repo) {
	if reset, err := r.RestoreHead(); err != nil {
		log.Printf("push to %s: restore work tree: %v", name, err)
	} else if reset {
		log.Printf("push to %s: work tree put back to HEAD after a failed push", name)
	}
}

// renamedFrom is the folder that held finding id at rev, when it is not dir
// ("" when there was none).
func renamedFrom(r *gitrepo.Repo, rev, dir, id string) string {
	if id == "" {
		return ""
	}
	names, err := r.ListTree(rev, "findings")
	if err != nil {
		return ""
	}
	for _, n := range names {
		if n != dir && (n == id || strings.HasPrefix(n, id+"-")) {
			return n
		}
	}
	return ""
}

// pushedFinding is a finding folder a push changed, with a finding.md the
// push left readable.
type pushedFinding struct {
	dir   string
	cur   *finding.Finding // finding.md as the push left it
	raw   []byte           // its bytes
	old   *finding.Finding // before the push, here or in the folder it was renamed from (nil: new)
	prev  []byte           // finding.md before the push in this folder (nil: none)
	md    byte             // A or M of finding.md; 0 when untouched
	files bool             // other files of the folder changed
}

// pushedFindings diffs before..after of eng's repo per finding folder.
func (s *Store) pushedFindings(eng, before, after string) ([]pushedFinding, error) {
	r, err := s.EngRepo(eng)
	if err != nil {
		return nil, err
	}
	changes, err := r.ChangedFiles(before, after)
	if err != nil {
		return nil, err
	}
	type touched struct {
		md    byte // A or M (or D) of finding.md; 0 when untouched
		files bool // other files of the folder changed
	}
	var dirs []string
	byDir := map[string]*touched{}
	for _, c := range changes {
		seg := strings.SplitN(c.Path, "/", 3)
		if len(seg) != 3 || seg[0] != "findings" || !ValidID(seg[1]) {
			continue
		}
		t := byDir[seg[1]]
		if t == nil {
			t = &touched{}
			byDir[seg[1]] = t
			dirs = append(dirs, seg[1])
		}
		if seg[2] == "finding.md" {
			t.md = c.Status
		} else {
			t.files = true
		}
	}
	slices.Sort(dirs)
	var out []pushedFinding
	for _, dir := range dirs {
		t := byDir[dir]
		p := path.Join("findings", dir, "finding.md")
		raw, err := r.Show(after, p)
		if err != nil {
			continue // deleted (no event for that) or not a finding
		}
		cur, err := finding.Parse(raw)
		if err != nil {
			continue
		}
		pf := pushedFinding{dir: dir, cur: cur, raw: raw, md: t.md, files: t.files}
		if before != "" {
			if b, err := r.Show(before, p); err == nil {
				pf.prev = b
				pf.old, _ = finding.Parse(b)
			} else if prev := renamedFrom(r, before, dir, cur.Meta.ID); prev != "" {
				// the folder was renamed: the same finding, not a new one
				if b, err := r.Show(before, path.Join("findings", prev, "finding.md")); err == nil {
					pf.old, _ = finding.Parse(b)
				}
				// its other files moved along: changed only if they differ
				// from the old folder's
				if cs, err := r.ChangedFiles(before+":findings/"+prev, after+":findings/"+dir); err == nil {
					pf.files = slices.ContainsFunc(cs, func(c gitrepo.Change) bool { return c.Path != "finding.md" })
				}
			}
		}
		out = append(out, pf)
	}
	return out, nil
}

// pushState moves the workflow state a landed push by u calls for, as the
// same changes through YARS would: a director's edit of an approved
// finding's finding.md moves its approval to the new content (a renamed
// folder's does not), and a changed attachment drops the sign-offs of a
// finding in verification. It runs under the engagement's lock, before the
// push is announced; a failure is logged (the push stands).
func (s *Store) pushState(eng string, u config.User, ps []pushedFinding) {
	if s.db == nil {
		return
	}
	// unread (nil), every candidate is tried: each step checks the state again
	states, serr := s.db.States(eng)
	may := func(fid string, want func(db.State) bool) bool {
		st, ok := states[fid]
		return serr != nil || ok && want(st)
	}
	director := workflow.AtLeast(u, "director")
	for _, pf := range ps {
		if director && pf.md != 0 && pf.prev != nil {
			if of, err := finding.Parse(pf.prev); err == nil {
				old := contentHash(pf.prev)
				if may(of.Meta.ID, func(st db.State) bool { return Approved(st, old) && st.ApprovedHash != "" }) {
					if err := carryApprovalDB(s.db, eng, of.Meta.ID, old, contentHash(pf.raw)); err != nil {
						log.Printf("push to %s: approval of %s: %v", eng, of.Meta.ID, err)
					}
				}
			}
		}
		if pf.files && may(pf.cur.Meta.ID, signedOff) {
			if err := dropSignOffs(s.db, eng, pf.cur.Meta.ID); err != nil {
				log.Printf("push to %s: sign-offs of %s: %v", eng, pf.cur.Meta.ID, err)
			}
		}
	}
}

// pushEvents is the events of the findings a push by actor changed.
func (s *Store) pushEvents(eng, actor string, ps []pushedFinding) ([]Event, error) {
	var states map[string]db.State
	if s.db != nil {
		var err error
		if states, err = s.db.States(eng); err != nil {
			return nil, err
		}
	}
	var evs []Event
	for _, pf := range ps {
		st := db.State{Status: "draft"}
		if got, ok := states[pf.cur.Meta.ID]; ok {
			st = got
		}
		applyState(&pf.cur.Meta, st, contentHash(pf.raw))
		ref := FindingRef{EngID: eng, Dir: pf.dir, F: pf.cur}
		switch {
		case pf.old == nil && pf.md != 0:
			evs = append(evs, findingEvent(EventCreated, actor, ref))
		case pf.old != nil && pf.md != 0 || pf.files:
			ev := updatedEvent(actor, ref, pf.old, pf.files)
			if len(ev.Changed) > 0 {
				evs = append(evs, ev)
			}
		}
	}
	return evs, nil
}
