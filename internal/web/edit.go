package web

import (
	"bytes"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/history"
	"yars/internal/store"
)

// routesEdit registers write routes. New findings exist only under /e/{eng}/.
func (s *Server) routesEdit(mux *http.ServeMux) {
	mux.HandleFunc("GET /engagements/new", s.newEngagementForm)
	mux.HandleFunc("POST /engagements/new", s.newEngagement)
	mux.HandleFunc("GET /e/{eng}/findings/new", s.newFindingForm)
	mux.HandleFunc("POST /e/{eng}/findings/new", s.newFinding)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/s/{section}", s.sectionView)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/s/{section}/edit", s.sectionEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/s/{section}", s.sectionSave)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/s/{section}/presence", s.presenceGet)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/s/{section}/presence", s.presenceBeat)
	mux.HandleFunc("POST /e/{eng}/preview", s.preview)
}

// conflictDiff sets the user's text beside the saved one after a conflict.
type conflictDiff struct {
	By, At             string // who last changed the section, and when
	MineBase, TheirsAt string // short hashes: what the user started from, what is saved
	Mine, Theirs       []histLine
}

// lastChange finds who last changed a section (the newest version whose
// text differs from the one before it) — from the cached file history.
func (s *Server) lastChange(ref store.FindingRef, section string) (string, string) {
	vs, err := s.versions(ref)
	if err != nil || len(vs) == 0 {
		return "", ""
	}
	sec := func(raw []byte) string {
		f, err := finding.Parse(raw)
		if err != nil {
			return "\x00"
		}
		b, _ := f.Section(section)
		return strings.Trim(b, "\n")
	}
	cur, j := sec(vs[0].Raw), 0
	for j+1 < len(vs) && sec(vs[j+1].Raw) == cur {
		j++
	}
	return vs[j].Author, vs[j].Time.Local().Format("15:04")
}

func (s *Server) conflictOf(ref store.FindingRef, section, mine, base string) *conflictDiff {
	theirs, _ := ref.F.Section(section)
	d := &conflictDiff{MineBase: short(base), TheirsAt: short(store.BodyHash(theirs))}
	d.By, d.At = s.lastChange(ref, section)
	norm := func(t string) string { return strings.Trim(strings.ReplaceAll(t, "\r\n", "\n"), "\n") }
	if old, ok := s.baseText(ref, section, base); ok {
		// each side against the text both started from: what it removed
		// and what it added
		d.Mine = histLines(history.Diff(norm(old), norm(mine)))
		d.Theirs = histLines(history.Diff(norm(old), norm(theirs)))
		return d
	}
	// the base is not in the history: show the two texts against each other
	for _, l := range history.Diff(norm(theirs), norm(mine)) {
		switch l.Op {
		case '+':
			d.Mine = append(d.Mine, histLine{Class: "add", Op: "+", Text: l.Text, No: l.New})
		case '-':
			d.Theirs = append(d.Theirs, histLine{Class: "add", Op: "+", Text: l.Text, No: l.Old})
		default:
			d.Mine = append(d.Mine, histLine{Text: l.Text, No: l.New})
			d.Theirs = append(d.Theirs, histLine{Text: l.Text, No: l.Old})
		}
	}
	return d
}

// baseText finds the section's text whose hash is base in the finding's
// history (newest first).
func (s *Server) baseText(ref store.FindingRef, section, base string) (string, bool) {
	if base == "" {
		return "", false
	}
	vs, err := s.versions(ref)
	if err != nil {
		return "", false
	}
	for _, v := range vs {
		f, err := finding.Parse(v.Raw)
		if err != nil {
			continue
		}
		if b, ok := f.Section(section); ok && store.BodyHash(b) == base {
			return b, true
		}
	}
	return "", false
}

func short(h string) string {
	if len(h) > 7 {
		return h[:7]
	}
	return h
}

// editorPanel is a section's editor: the panel plus who else is editing it
// and the finding's attachments.
func (s *Server) editorPanel(w http.ResponseWriter, r *http.Request, ref store.FindingRef, name string) (panel, bool) {
	p := s.panelFor(ref, name)
	p.Presence = s.presenceFor(r, ref, name)
	a, err := s.attachFor(ref)
	if err != nil {
		s.fail(w, err)
		return p, false
	}
	p.Attach = a
	return p, true
}

func (s *Server) newEngagementForm(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	if !p.CanEngs {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.Users = s.teamCandidates(p.User)
	s.render(w, "new_engagement.html", p)
}

// isDate: "" or a real YYYY-MM-DD date (what a date input sends).
func isDate(d string) bool {
	if d == "" {
		return true
	}
	t, err := time.Parse("2006-01-02", d)
	return err == nil && t.Format("2006-01-02") == d
}

// teamCandidates are the people a new engagement's creator can put on the
// team: every enabled account but the creator, who is always on it.
func (s *Server) teamCandidates(creator config.User) []config.User {
	var out []config.User
	for _, u := range s.Auth.Users() {
		if !u.Disabled && u.Username != creator.Username {
			out = append(out, u)
		}
	}
	return out
}

func (s *Server) newEngagement(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	if !p.CanEngs {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	p.Users = s.teamCandidates(p.User)
	e := store.Engagement{
		ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Client: strings.TrimSpace(r.FormValue("client")), Type: "pentest",
		Start: r.FormValue("start"), End: r.FormValue("end"),
	}
	p.FieldErrs = map[string]string{}
	if !store.ValidID(e.ID) {
		p.FieldErrs["id"] = "Letters, digits, dot, dash, underscore"
	} else if _, err := s.Store.Engagement(e.ID); err == nil {
		p.FieldErrs["id"] = "ID already used"
	}
	if e.Name == "" {
		p.FieldErrs["name"] = "Required"
	}
	if !isDate(e.Start) {
		p.FieldErrs["start"] = "YYYY-MM-DD"
	}
	if !isDate(e.End) {
		p.FieldErrs["end"] = "YYYY-MM-DD"
	} else if e.Start != "" && e.End != "" && e.End < e.Start {
		p.FieldErrs["end"] = "Before the start"
	}
	if len(p.FieldErrs) == 0 {
		if err := s.Store.CreateEngagement(e, author(p.User)); err != nil {
			if _, gerr := s.Store.Engagement(e.ID); gerr != nil {
				// not about a field: the detail (paths, git output) goes to the log
				s.fail(w, err)
				return
			}
			p.FieldErrs["id"] = "ID already used" // created meanwhile
		} else {
			// the creator and the ticked people form the team
			team := []string{p.User.Username}
			for _, u := range p.Users {
				if slices.Contains(r.PostForm["member"], u.Username) {
					team = append(team, u.Username)
				}
			}
			if err := s.Store.AddMembers(e.ID, team, p.User); err != nil {
				s.fail(w, err)
				return
			}
			s.Store.DB().Audit(p.User.Username, "eng.create", e.ID, strings.Join(team, ","))
			http.Redirect(w, r, "/e/"+e.ID, http.StatusSeeOther)
			return
		}
	}
	s.renderStatus(w, http.StatusBadRequest, "new_engagement.html", p)
}

func (s *Server) newFindingForm(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	if p.Tpl, err = s.pickerView(p.Eng.ID, q.Get("q"), q.Get("t"), q.Get("mode")); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "new_finding.html", p)
}

// newFinding creates a blank finding, or one from the picked template.
func (s *Server) newFinding(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	p, err := s.base(r, eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	title := store.CleanTitle(r.FormValue("title"))
	mode, tpl := r.FormValue("mode"), r.FormValue("template")
	bad := func(msg string) {
		p.Error = msg
		if p.Tpl, err = s.pickerView(eng, r.FormValue("q"), tpl, mode); err != nil {
			s.fail(w, err)
			return
		}
		s.renderStatus(w, http.StatusBadRequest, "new_finding.html", p)
	}
	if title == "" {
		bad("Title is required.")
		return
	}
	if store.CheckTitle(title) != nil {
		bad("The title must be one line of 1–200 characters.")
		return
	}
	if mode == "template" && tpl == "" {
		bad("Pick a template.")
		return
	}
	var ref store.FindingRef
	if mode == "template" && tpl != "" {
		ref, err = s.Store.CreateFindingFrom(eng, title, tpl, author(p.User))
		if errors.Is(err, store.ErrNotFound) {
			if _, eerr := s.Store.Engagement(eng); eerr == nil {
				bad("Template " + tpl + " not found.")
				return
			}
		}
	} else {
		ref, err = s.Store.CreateFinding(eng, title, author(p.User))
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, findingURL(eng, ref.Dir), http.StatusSeeOther)
}

// sectionRef loads the finding and validates that the section is either
// configured or already present in the file.
func (s *Server) sectionRef(w http.ResponseWriter, r *http.Request) (store.FindingRef, string, bool) {
	ref, err := s.Store.Finding(r.PathValue("eng"), r.PathValue("fid"))
	if err != nil {
		s.fail(w, err)
		return ref, "", false
	}
	name := r.PathValue("section")
	for _, n := range s.sectionNames(ref) {
		if n == name {
			return ref, name, true
		}
	}
	http.NotFound(w, r)
	return ref, "", false
}

func (s *Server) sectionView(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("live") != "" {
		// a live refresh: 204 while current, a reload once the finding is gone
		if _, ok := s.liveRef(w, r); !ok {
			return
		}
	}
	if ref, name, ok := s.sectionRef(w, r); ok {
		// Cancel comes here: the editor is closed (a live refresh is not
		// Cancel: the user may be editing it in another tab)
		if r.URL.Query().Get("live") == "" {
			s.presence.leave(presKey{ref.EngID, ref.F.Meta.ID, name}, auth.UserFrom(r.Context()).Username)
		}
		p := s.panelFor(ref, name)
		p.ReadOnly = s.Store.Archived(ref.EngID)
		if msgs, err := s.Store.Chat(ref.EngID, ref.Dir); err == nil {
			_, by := chat.OpenCount(msgs)
			p.Open = by[name]
		}
		p.Presence = s.presenceFor(r, ref, name)
		if s.locked(r, ref) {
			p.EditURL = ""
		}
		s.exec(w, "finding.html", "panel", p)
	}
}

func (s *Server) sectionEdit(w http.ResponseWriter, r *http.Request) {
	if ref, name, ok := s.sectionRef(w, r); ok && s.allowEdit(w, r, ref) {
		s.presence.touch(presKey{ref.EngID, ref.F.Meta.ID, name}, auth.UserFrom(r.Context()).Username)
		if p, ok := s.editorPanel(w, r, ref, name); ok {
			s.exec(w, "finding.html", "editor", p)
		}
	}
}

func (s *Server) sectionSave(w http.ResponseWriter, r *http.Request) {
	ref, name, ok := s.sectionRef(w, r)
	if !ok || !s.allowEdit(w, r, ref) {
		return
	}
	u := auth.UserFrom(r.Context())
	body := r.FormValue("body")
	err := s.Store.UpdateSection(ref.EngID, ref.Dir, name, body, r.FormValue("base"), u)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalidBody) {
		// Re-show the editor with the user's text so nothing typed is lost.
		if cur, ferr := s.Store.Finding(ref.EngID, ref.Dir); ferr == nil {
			ref = cur
		}
		p, ok := s.editorPanel(w, r, ref, name)
		if !ok {
			return
		}
		p.Raw, p.Error = body, err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrConflict) {
			status = http.StatusConflict
			p.Current, p.Conflict = p.HTML, true
			p.Diff = s.conflictOf(ref, name, body, r.FormValue("base"))
			p.Error = conflictText
			if p.Diff.By != "" && p.Diff.By != auth.UserFrom(r.Context()).Username {
				p.Error = "Changed by " + p.Diff.By
			}
		}
		s.execStatus(w, status, "finding.html", "editor", p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.presence.leave(presKey{ref.EngID, ref.F.Meta.ID, name}, u.Username)
	ref, err = s.Store.Finding(ref.EngID, ref.Dir)
	if err != nil {
		s.fail(w, err)
		return
	}
	p := s.panelFor(ref, name)
	p.Presence = s.presenceFor(r, ref, name)
	s.exec(w, "finding.html", "panel", p)
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Store.Engagement(r.PathValue("eng")); err != nil {
		s.fail(w, err)
		return
	}
	body := r.FormValue("body")
	var buf strings.Builder
	h := s.renderMD(body)
	if fid := r.URL.Query().Get("f"); fid != "" {
		h = s.linkAttachments(h, store.FindingRef{EngID: r.PathValue("eng"), Dir: fid})
	}
	buf.WriteString(string(h))
	// Live style hints for the section being edited (fast rules only).
	if fid, sec := r.URL.Query().Get("f"), r.URL.Query().Get("s"); s.Rules != nil && fid != "" && sec != "" {
		if ref, err := s.Store.Finding(r.PathValue("eng"), fid); err == nil {
			if vs := s.Rules.LintSection(ref.F, sec, body); len(vs) > 0 {
				var hb bytes.Buffer
				if err := s.pages["finding.html"].ExecuteTemplate(&hb, "hints", vs); err == nil {
					buf.WriteString(hb.String())
				}
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(buf.String()))
}
