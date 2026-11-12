package web

import (
	"errors"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/history"
	"yars/internal/store"
	"yars/internal/workflow"
)

// histEvent is one row of a finding's history: a commit that changed its
// file, or a workflow event from the chat.
type histEvent struct {
	Key, Kind     string // Kind: content | status
	Class         string // the marker colour
	Who, Act      string // "alice", "edited Impact"
	AI            bool   // the AI made the commit for Who (Fix with AI)
	Text, Short   string // a reason; the short commit hash
	Time, URL     string
	On            bool
	at            time.Time
	before, after []byte // file versions (content)
}

// histDiff is one changed part of the file in the selected commit.
type histDiff struct {
	Name, Section  string // Section: "" for the front matter (no Restore)
	Added, Removed int
	Lines          []histLine
	Base           string // current body hash of the section (Restore)
}

// histLine is one shown line: Class "" (kept), "del" or "add".
type histLine struct {
	Class, Op, Text string
	No              int
}

func histLines(ls []history.Line) []histLine {
	out := make([]histLine, 0, len(ls))
	for _, l := range ls {
		h := histLine{Text: l.Text, No: l.New}
		switch l.Op {
		case '-':
			h.Class, h.Op, h.No = "del", "−", l.Old
		case '+':
			h.Class, h.Op = "add", "+"
		}
		out = append(out, h)
	}
	return out
}

type historyView struct {
	Back, URL       string
	Filters         []link
	Events          []histEvent
	Sel             *histEvent
	Full            bool
	DiffURL         string
	FullURL         string
	Diffs           []histDiff
	CanRestore      bool
	RestoreURL      string
	Error           string
	Added, Removed  int
	Content, Status int // counts for the filters
}

func (s *Server) routesHistory(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/history", s.historyPage)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/history/restore", s.historyRestore)
}

// eventLabels says what a workflow event did, in the past tense.
var eventLabels = map[string]string{
	"submit": "submitted", "return": "returned", "clear": "signed off", "approve": "approved", "reopen": "reverted to verification",
	"report": "marked reported", "unreport": "reverted to complete", "withdraw": "withdrew", "revise": "revised", "take_back": "took back", "retest": "set the result", store.EventMerge: "merged in",
}

func eventLabel(ev string) string {
	if l, ok := eventLabels[ev]; ok {
		return l
	}
	return ev
}

// versions reads the finding's file history (git, cached per engagement
// HEAD: the only page that starts git).
func (s *Server) versions(ref store.FindingRef) ([]history.Version, error) {
	repo, err := s.Store.EngRepo(ref.EngID)
	if err != nil {
		return nil, err
	}
	head, err := s.Store.EngHead(ref.EngID)
	if err != nil {
		return nil, err
	}
	return s.history.Versions(repo, ref.EngID+"/"+ref.Dir, head, path.Join("findings", ref.Dir, "finding.md"))
}

// canRestore: the author and directors put an old text back, while the
// finding may be edited.
func (s *Server) canRestore(u config.User, ref store.FindingRef) bool {
	return (u.Username == ref.F.Meta.Author || canManage(u)) && workflow.CanEdit(u, ref.F.Meta) && !s.Store.Archived(ref.EngID)
}

// changedNames names what a version changed (history.Parts).
func changedNames(before, after []byte) string {
	return strings.Join(history.Parts(before, after), ", ")
}

// historyOf builds the event list (filtered by show) and the selected
// event's changes.
func (s *Server) historyOf(r *http.Request, ref store.FindingRef) (historyView, error) {
	u := auth.UserFrom(r.Context())
	q := r.URL.Query()
	show := q.Get("show")
	if show != "content" && show != "status" {
		show = ""
	}
	base := findingURL(ref.EngID, ref.Dir)
	v := historyView{Back: base, URL: base + "/history", RestoreURL: base + "/history/restore", Full: q.Get("view") == "full",
		CanRestore: s.canRestore(u, ref)}
	vs, err := s.versions(ref)
	if err != nil {
		return v, err
	}
	msgs, err := s.Store.ChatOf(ref)
	if err != nil {
		return v, err
	}
	var all []histEvent
	for i, ver := range vs {
		var before []byte
		if i+1 < len(vs) {
			before = vs[i+1].Raw
		}
		act := "created"
		if i+1 < len(vs) {
			if names := changedNames(before, ver.Raw); names != "" {
				act = "edited " + names
			} else {
				act = ver.Subject
			}
		}
		cls := "ev-edit"
		if act == "created" {
			cls = "ev-create"
		}
		who, ai := history.Who(ver.Author)
		all = append(all, histEvent{Key: ver.Hash, Kind: "content", Class: cls, Who: who, AI: ai, Act: act, Short: ver.Hash[:7],
			at: ver.Time, before: before, after: ver.Raw})
	}
	for _, m := range msgs {
		if m.Event == "" {
			continue
		}
		all = append(all, histEvent{Key: "m-" + m.ID, Kind: "status", Class: "ev-" + m.Event, Who: m.User, Act: eventLabel(m.Event),
			Text: m.Text, at: m.TS})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].at.After(all[j].at) })
	sel := q.Get("ev")
	if sel == "" {
		for _, e := range all {
			if e.Kind == "content" {
				sel = e.Key
				break
			}
		}
	}
	for _, e := range all {
		if e.Kind == "content" {
			v.Content++
		} else {
			v.Status++
		}
	}
	for _, e := range all {
		e.Time = e.at.Local().Format("2006-01-02 15:04")
		uv := url.Values{"ev": {e.Key}}
		if show != "" {
			uv.Set("show", show)
		}
		e.URL = v.URL + "?" + uv.Encode()
		e.On = e.Key == sel
		if e.On {
			cp := e
			v.Sel = &cp
		}
		if show == "" || e.Kind == show {
			v.Events = append(v.Events, e)
		}
	}
	for _, f := range []struct{ key, label string }{{"", "All"}, {"content", "Content"}, {"status", "Status"}} {
		uv := url.Values{}
		if f.key != "" {
			uv.Set("show", f.key)
		}
		if sel != "" {
			uv.Set("ev", sel)
		}
		u := v.URL
		if len(uv) > 0 {
			u += "?" + uv.Encode()
		}
		n := len(all)
		switch f.key {
		case "content":
			n = v.Content
		case "status":
			n = v.Status
		}
		v.Filters = append(v.Filters, link{Label: f.label, URL: u, Active: f.key == show, Count: n})
	}
	if v.Sel != nil && v.Sel.Kind == "content" {
		mk := func(view string) string {
			uv := url.Values{"ev": {v.Sel.Key}}
			if show != "" {
				uv.Set("show", show)
			}
			if view != "" {
				uv.Set("view", view)
			}
			return v.URL + "?" + uv.Encode()
		}
		v.DiffURL, v.FullURL = mk(""), mk("full")
		for _, c := range history.Changes(v.Sel.before, v.Sel.after) {
			lines := c.Lines
			if v.Full {
				lines = nil
				for i, l := range strings.Split(c.After, "\n") {
					if c.After != "" {
						lines = append(lines, history.Line{Op: ' ', New: i + 1, Text: l})
					}
				}
			}
			d := histDiff{Name: c.Name, Added: c.Added, Removed: c.Removed, Lines: histLines(lines)}
			if c.Name != history.FrontMatter {
				d.Section = c.Name
				cur, _ := ref.F.Section(c.Name)
				d.Base = store.BodyHash(cur)
			}
			v.Added += c.Added
			v.Removed += c.Removed
			v.Diffs = append(v.Diffs, d)
		}
	}
	return v, nil
}

func (s *Server) renderHistory(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Finding, err = s.Store.Finding(p.Eng.ID, r.PathValue("fid")); err != nil {
		s.fail(w, err)
		return
	}
	if p.History, err = s.historyOf(r, p.Finding); err != nil {
		s.fail(w, err)
		return
	}
	p.History.Error = errMsg
	p.TabTitle = p.Finding.F.Meta.ID + " history"
	s.renderStatus(w, status, "history.html", p)
}

func (s *Server) historyPage(w http.ResponseWriter, r *http.Request) {
	s.renderHistory(w, r, http.StatusOK, "")
}

// historyRestore puts a section back as the chosen commit left it: a
// normal section edit, refused when the section changed since the page
// showed it (base).
func (s *Server) historyRestore(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	ref, err := s.Store.Finding(r.PathValue("eng"), r.PathValue("fid"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if !s.canRestore(u, ref) {
		s.fail(w, &workflow.Denied{Reason: "only the author or a director can restore while the finding may be edited"})
		return
	}
	ev, section := r.FormValue("ev"), r.FormValue("section")
	vs, err := s.versions(ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	i := slices.IndexFunc(vs, func(v history.Version) bool { return v.Hash == ev })
	if i < 0 || vs[i].Raw == nil {
		http.NotFound(w, r)
		return
	}
	old, err := finding.Parse(vs[i].Raw)
	if err != nil {
		http.Error(w, "that version can't be read", http.StatusBadRequest)
		return
	}
	body, _ := old.Section(section)
	err = s.Store.UpdateSection(ref.EngID, ref.Dir, section, body, r.FormValue("base"), u)
	if errors.Is(err, store.ErrConflict) {
		r.URL.RawQuery = url.Values{"ev": {ev}}.Encode()
		s.renderHistory(w, r, http.StatusConflict, section+" changed since; reload")
		return
	}
	if errors.Is(err, store.ErrInvalidBody) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, findingURL(ref.EngID, ref.Dir)+"/history", http.StatusSeeOther)
}
