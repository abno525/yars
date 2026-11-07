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
// between, then emits the events the pushed changes stand for, as if u had
// made them through YARS: finding.created for each new finding and
// finding.updated for each changed one. A rejected push moves nothing and
// emits nothing.
func (s *Store) ReceivePush(eng string, u config.User, serve func()) {
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
		// a push whose ref update failed after git checked its tree out
		// must not leave that tree behind
		if r, rerr := s.EngRepo(eng); rerr == nil {
			if reset, rerr := r.RestoreHead(); rerr != nil {
				log.Printf("push to %s: restore work tree: %v", eng, rerr)
			} else if reset {
				log.Printf("push to %s: work tree put back to HEAD after a failed push", eng)
			}
		}
	}
	l.Unlock()
	if err != nil || after == "" || after == before {
		return
	}
	evs, err := s.pushEvents(eng, before, after, u.Username)
	if err != nil {
		log.Printf("push to %s: events: %v", eng, err)
	}
	for _, ev := range evs {
		s.notify(Change{Eng: eng, Fid: ev.Fid, Kind: ChangeContent})
		s.Emit(ev)
	}
}

// pushEvents diffs before..after of eng's repo per finding folder.
func (s *Store) pushEvents(eng, before, after, actor string) ([]Event, error) {
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
	var states map[string]db.State
	if s.db != nil {
		if states, err = s.db.States(eng); err != nil {
			return nil, err
		}
	}
	var evs []Event
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
		st := db.State{Status: "draft"}
		if got, ok := states[cur.Meta.ID]; ok {
			st = got
		}
		applyState(&cur.Meta, st, contentHash(raw))
		ref := FindingRef{EngID: eng, Dir: dir, F: cur}
		var old *finding.Finding
		if before != "" {
			if b, err := r.Show(before, p); err == nil {
				old, _ = finding.Parse(b)
			}
		}
		switch {
		case old == nil && t.md != 0:
			evs = append(evs, findingEvent(EventCreated, actor, ref))
		case old != nil && t.md != 0 || t.files:
			ev := updatedEvent(actor, ref, old, t.files)
			if len(ev.Changed) > 0 {
				evs = append(evs, ev)
			}
		}
	}
	return evs, nil
}
