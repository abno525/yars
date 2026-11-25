package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/store"
	"yars/internal/workflow"
)

// tplRow is one template in a list.
type tplRow struct {
	Slug, Title, Severity, Score string
	Used                         int
	On                           bool // picked on the new finding page
	tplOwner
}

// tplOwner is what git says about a template: its version (number of
// saves), who made it and the last edit ("2026-11-04 · rev1").
type tplOwner struct {
	Version            int
	Owner, Edited      string
	EditedBy, EditedOn string
	History            []tplVersion // newest first (the history page)
}

// tplVersion is one saved version of a template.
type tplVersion struct {
	N                     int
	Date, Author, Subject string
	Hash                  string
}

// ownerOf describes a template's versions.
func ownerOf(vs []store.TemplateVersion, all bool) tplOwner {
	o := tplOwner{Version: len(vs), Owner: "—", Edited: "—"}
	if len(vs) == 0 {
		return o
	}
	last := vs[0]
	o.Owner = vs[len(vs)-1].Author
	o.EditedBy, o.EditedOn = last.Author, last.Time.Local().Format("2006-01-02")
	o.Edited = o.EditedOn + " · " + o.EditedBy
	if all {
		for _, v := range vs {
			o.History = append(o.History, tplVersion{N: v.N, Date: v.Time.Local().Format("2006-01-02 15:04"), Author: v.Author, Subject: v.Subject, Hash: v.Hash[:min(8, len(v.Hash))]})
		}
	}
	return o
}

// tplSection is one section of a template preview.
type tplSection struct {
	Name string
	HTML template.HTML
}

// tplPreview is the read-only preview of one template.
type tplPreview struct {
	Title, Vector string
	Sections      []tplSection
	OOB           bool // sent along with a search result (hx-swap-oob)
}

// tplStrip is one part of a finding that "Save as template" may leave out.
type tplStrip struct {
	Key, Label, Value string
	On                bool
}

// tplView feeds the template pages and the template picker of a new
// finding.
type tplView struct {
	CanEdit bool
	Rows    []tplRow
	Total   int // templates before the search
	Q       string
	// the picker
	Eng, Mode string
	Preview   tplPreview
	// one template (edit page)
	Slug, Title, Severity, CVSS, Score, Error string
	Used                                      int
	Own                                       tplOwner
	Severities                                []string
	Panels                                    []panel
	// Save as template
	Strip []tplStrip
	Back  string
}

// canEditTemplates: reviewers and directors write templates; everyone reads.
func canEditTemplates(u config.User) bool { return workflow.AtLeast(u, "reviewer") }

func (s *Server) routesTemplates(mux *http.ServeMux) {
	mux.HandleFunc("GET /templates", s.templatesPage)
	mux.HandleFunc("POST /templates/new", s.templateCreate)
	mux.HandleFunc("GET /templates/{slug}", s.templatePage)
	mux.HandleFunc("GET /templates/{slug}/history", s.templateHistory)
	mux.HandleFunc("POST /templates/{slug}", s.templateSaveMeta)
	mux.HandleFunc("POST /templates/{slug}/delete", s.templateDelete)
	mux.HandleFunc("GET /templates/{slug}/s/{section}", s.templateSection)
	mux.HandleFunc("GET /templates/{slug}/s/{section}/edit", s.templateSectionEdit)
	mux.HandleFunc("POST /templates/{slug}/s/{section}", s.templateSectionSave)
	mux.HandleFunc("POST /preview", s.previewPlain)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/template", s.saveAsTemplateForm)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/template", s.saveAsTemplate)
	mux.HandleFunc("GET /e/{eng}/findings/new/templates", s.newFindingList)
	mux.HandleFunc("GET /e/{eng}/findings/new/preview", s.newFindingPreview)
}

// denyTemplates answers 403 unless u may write templates.
func (s *Server) denyTemplates(w http.ResponseWriter, u config.User) bool {
	if canEditTemplates(u) {
		return false
	}
	s.fail(w, &workflow.Denied{Reason: "only reviewers and directors change templates"})
	return true
}

// tplRows lists the templates whose title contains q (any case), with
// their use counts; total counts them all.
func (s *Server) tplRows(q string) (rows []tplRow, total int, err error) {
	ts, err := s.Store.Templates()
	if err != nil {
		return nil, 0, err
	}
	use, err := s.Index.TemplateUse()
	if err != nil {
		return nil, 0, err
	}
	hist, err := s.Store.TemplateHistories()
	if err != nil {
		return nil, 0, err
	}
	q = strings.ToLower(strings.TrimSpace(q))
	for _, t := range ts {
		if q != "" && !strings.Contains(strings.ToLower(t.F.Meta.Title), q) && !strings.Contains(t.Slug, q) {
			continue
		}
		m := t.F.Meta
		sc := ""
		if v, err := cvss.Parse(m.CVSS); err == nil {
			n, _ := cvss.Score(v)
			sc = cvss.FormatScore(n)
		}
		rows = append(rows, tplRow{Slug: t.Slug, Title: m.Title, Severity: cvss.Derive(m.CVSS, m.Severity), Score: sc, Used: use[t.Slug],
			tplOwner: ownerOf(hist[t.Slug], false)})
	}
	return rows, len(ts), nil
}

func (s *Server) templatesPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	v := tplView{CanEdit: canEditTemplates(p.User), Q: r.URL.Query().Get("q")}
	if v.Rows, v.Total, err = s.tplRows(v.Q); err != nil {
		s.fail(w, err)
		return
	}
	p.Tpl = v
	s.render(w, "templates.html", p)
}

// freeSlug is a template name from title that no template has yet.
func (s *Server) freeSlug(title string) string {
	base := store.Slug(title)
	slug := base
	for i := 2; ; i++ {
		if _, err := s.Store.Template(slug); errors.Is(err, store.ErrNotFound) && slug != "new" {
			return slug
		}
		slug = fmt.Sprintf("%s-%d", base, i)
	}
}

func (s *Server) templateCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if s.denyTemplates(w, u) {
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" || strings.ContainsAny(title, "\r\n") {
		http.Error(w, "a template needs a one-line title", http.StatusBadRequest)
		return
	}
	slug := s.freeSlug(title)
	err := s.Store.SaveTemplate(slug, author(u), func(*finding.Finding) (*finding.Finding, error) {
		return s.Store.NewTemplate(title), nil
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/templates/"+slug, http.StatusSeeOther)
}

// tplPanel is one section of a template as a page panel (no Comment).
func (s *Server) tplPanel(t store.Template, name string, edit bool) panel {
	body, _ := t.F.Section(name)
	p := panel{Name: name, Anchor: anchor(name), Raw: strings.Trim(body, "\n"), Base: store.BodyHash(body), ReadOnly: true}
	if strings.TrimSpace(body) != "" {
		p.HTML = s.renderMD(body)
	}
	base := "/templates/" + t.Slug + "/s/" + url.PathEscape(name)
	p.SaveURL, p.PreviewURL = base, "/preview"
	if edit {
		p.EditURL = base + "/edit"
	}
	return p
}

// tplSectionNames are the template's sections, then configured ones it
// lacks.
func (s *Server) tplSectionNames(f *finding.Finding) []string {
	var names []string
	for _, x := range f.Sections {
		names = append(names, x.Name)
	}
	for _, n := range s.conf().Sections {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

func (s *Server) templateView(t store.Template, u config.User) (tplView, error) {
	m := t.F.Meta
	v := tplView{CanEdit: canEditTemplates(u), Slug: t.Slug, Title: m.Title, Severity: cvss.Derive(m.CVSS, m.Severity), CVSS: m.CVSS,
		Severities: s.conf().Severities}
	if vec, err := cvss.Parse(m.CVSS); err == nil {
		n, _ := cvss.Score(vec)
		v.Score = cvss.FormatScore(n)
	}
	use, err := s.Index.TemplateUse()
	if err != nil {
		return v, err
	}
	v.Used = use[t.Slug]
	hist, err := s.Store.TemplateHistories()
	if err != nil {
		return v, err
	}
	v.Own = ownerOf(hist[t.Slug], true)
	for _, n := range s.tplSectionNames(t.F) {
		v.Panels = append(v.Panels, s.tplPanel(t, n, v.CanEdit))
	}
	return v, nil
}

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, status int, slug string, fill func(*tplView)) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	t, err := s.Store.Template(slug)
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Tpl, err = s.templateView(t, p.User); err != nil {
		s.fail(w, err)
		return
	}
	if fill != nil {
		fill(&p.Tpl)
	}
	s.renderStatus(w, status, "template.html", p)
}

func (s *Server) templatePage(w http.ResponseWriter, r *http.Request) {
	s.renderTemplate(w, r, http.StatusOK, r.PathValue("slug"), nil)
}

// templateHistory lists a template's versions from git, newest first.
func (s *Server) templateHistory(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	t, err := s.Store.Template(r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Tpl, err = s.templateView(t, p.User); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "template_history.html", p)
}

// templateSaveMeta saves the title, severity and CVSS vector. A valid
// vector sets the severity to its rating.
func (s *Server) templateSaveMeta(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if s.denyTemplates(w, u) {
		return
	}
	slug := r.PathValue("slug")
	title := strings.TrimSpace(r.FormValue("title"))
	sev, vec := r.FormValue("severity"), strings.TrimSpace(r.FormValue("cvss"))
	var bad string
	var parsed cvss.Vector
	switch {
	case title == "" || strings.ContainsAny(title, "\r\n"):
		bad = "Title: one line"
	case sev != "" && !slices.Contains(s.conf().Severities, sev):
		bad = "Severity: unknown " + sev
	case vec != "":
		var err error
		if parsed, err = cvss.Parse(vec); err != nil {
			bad = "CVSS: " + err.Error()
		}
	}
	if bad == "" {
		err := s.Store.SaveTemplate(slug, author(u), func(cur *finding.Finding) (*finding.Finding, error) {
			if cur == nil {
				return nil, store.ErrNotFound
			}
			var vv any
			if parsed != nil {
				vv = parsed.String()
				n, _ := cvss.Score(parsed)
				sev = cvss.Rating(n)
			}
			for _, kv := range []struct {
				k string
				v any
			}{{"title", title}, {"severity", sev}, {"cvss", vv}} {
				if err := cur.SetMeta(kv.k, kv.v); err != nil {
					return nil, err
				}
			}
			return cur, nil
		})
		if err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/templates/"+slug, http.StatusSeeOther)
		return
	}
	s.renderTemplate(w, r, http.StatusBadRequest, slug, func(v *tplView) {
		v.Title, v.Severity, v.CVSS, v.Error = title, sev, vec, bad
	})
}

func (s *Server) templateDelete(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if s.denyTemplates(w, u) {
		return
	}
	if err := s.Store.DeleteTemplate(r.PathValue("slug"), author(u)); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/templates", http.StatusSeeOther)
}

// tplSectionRef loads the template and checks the section is one it shows.
func (s *Server) tplSectionRef(w http.ResponseWriter, r *http.Request) (store.Template, string, bool) {
	t, err := s.Store.Template(r.PathValue("slug"))
	if err != nil {
		s.fail(w, err)
		return t, "", false
	}
	name := r.PathValue("section")
	if !slices.Contains(s.tplSectionNames(t.F), name) {
		http.NotFound(w, r)
		return t, "", false
	}
	return t, name, true
}

func (s *Server) templateSection(w http.ResponseWriter, r *http.Request) {
	if t, name, ok := s.tplSectionRef(w, r); ok {
		s.exec(w, "template.html", "panel", s.tplPanel(t, name, canEditTemplates(auth.UserFrom(r.Context()))))
	}
}

func (s *Server) templateSectionEdit(w http.ResponseWriter, r *http.Request) {
	if s.denyTemplates(w, auth.UserFrom(r.Context())) {
		return
	}
	if t, name, ok := s.tplSectionRef(w, r); ok {
		s.exec(w, "template.html", "editor", s.tplPanel(t, name, true))
	}
}

func (s *Server) templateSectionSave(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if s.denyTemplates(w, u) {
		return
	}
	t, name, ok := s.tplSectionRef(w, r)
	if !ok {
		return
	}
	body := r.FormValue("body")
	err := s.Store.UpdateTemplateSection(t.Slug, name, body, r.FormValue("base"), author(u))
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalidBody) {
		p := s.tplPanel(t, name, true)
		p.Raw, p.Error = body, err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrConflict) {
			status, p.Error = http.StatusConflict, "The template changed since you read it"
			p.Current, p.Conflict = p.HTML, true
		}
		s.execStatus(w, status, "template.html", "editor", p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if t, err = s.Store.Template(t.Slug); err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "template.html", "panel", s.tplPanel(t, name, true))
}

// previewPlain renders Markdown for editors outside an engagement.
func (s *Server) previewPlain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s.renderMD(r.FormValue("body"))))
}

// stripOf lists what Save as template can leave out of ref, picked as on.
func stripOf(ref store.FindingRef, on map[string]bool) []tplStrip {
	m := ref.F.Meta
	var out []tplStrip
	if len(m.Details) > 0 {
		val := fmt.Sprintf("%d rows", len(m.Details))
		for _, k := range []string{"Location"} {
			if x := m.Details[k]; x != "" {
				val = x
			}
		}
		out = append(out, tplStrip{Key: "details", Label: "Details", Value: val, On: on["details"]})
	}
	if m.CVSS != "" {
		out = append(out, tplStrip{Key: "cvss", Label: "CVSS vector", Value: m.CVSS, On: on["cvss"]})
	}
	return out
}

func (s *Server) saveAsTemplatePage(w http.ResponseWriter, r *http.Request, status int, ref store.FindingRef, title string, on map[string]bool, errMsg string) {
	p, err := s.base(r, ref.EngID)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Finding = ref
	p.Tpl = tplView{CanEdit: true, Title: title, Strip: stripOf(ref, on), Error: errMsg, Back: findingURL(ref.EngID, ref.Dir)}
	s.renderStatus(w, status, "template_save.html", p)
}

func (s *Server) saveAsTemplateForm(w http.ResponseWriter, r *http.Request) {
	if s.denyTemplates(w, auth.UserFrom(r.Context())) {
		return
	}
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	s.saveAsTemplatePage(w, r, http.StatusOK, ref, ref.F.Meta.Title, map[string]bool{"details": true}, "")
}

// saveAsTemplate makes a new template from a finding: its sections,
// severity and (unless left out) details and CVSS; never its id, author
// or template link.
func (s *Server) saveAsTemplate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if s.denyTemplates(w, u) {
		return
	}
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	title := strings.TrimSpace(r.FormValue("title"))
	on := map[string]bool{}
	for _, k := range r.PostForm["strip"] {
		on[k] = true
	}
	if title == "" || strings.ContainsAny(title, "\r\n") {
		s.saveAsTemplatePage(w, r, http.StatusBadRequest, ref, title, on, "Title: one line")
		return
	}
	all, err := s.Store.Templates()
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, t := range all {
		if strings.EqualFold(strings.TrimSpace(t.F.Meta.Title), title) {
			s.saveAsTemplatePage(w, r, http.StatusBadRequest, ref, title, on, "Template "+t.Slug+" exists")
			return
		}
	}
	slug := s.freeSlug(title)
	raw := ref.F.Bytes()
	errExists := errors.New("exists")
	err = s.Store.SaveTemplate(slug, author(u), func(cur *finding.Finding) (*finding.Finding, error) {
		if cur != nil {
			return nil, errExists
		}
		f, err := finding.Parse(raw)
		if err != nil {
			return nil, err
		}
		drop := []string{"id", "author", store.TemplateKey, "assets"}
		if on["details"] {
			drop = append(drop, "details")
		}
		if on["cvss"] {
			drop = append(drop, "cvss", "cvss_reasons")
		}
		for _, k := range drop {
			if err := f.SetMeta(k, nil); err != nil {
				return nil, err
			}
		}
		return f, f.SetMeta("title", title)
	})
	if errors.Is(err, errExists) {
		s.saveAsTemplatePage(w, r, http.StatusBadRequest, ref, title, on, "Template "+slug+" exists")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/templates/"+slug, http.StatusSeeOther)
}

// pickerView is the template picker of the new finding page: the rows
// matching q, with pick chosen and previewed while it is among them, else
// the first row (none when nothing matches). Without a mode the page starts
// Blank, or from Template when a template is named (pick).
func (s *Server) pickerView(eng, q, pick, mode string) (tplView, error) {
	v := tplView{Eng: eng, Q: q, Mode: mode}
	var err error
	if v.Rows, v.Total, err = s.tplRows(q); err != nil {
		return v, err
	}
	if v.Mode != "blank" && v.Mode != "template" {
		v.Mode = "blank"
		if pick != "" && v.Total > 0 {
			v.Mode = "template"
		}
	}
	if !slices.ContainsFunc(v.Rows, func(r tplRow) bool { return r.Slug == pick }) {
		pick = ""
		if len(v.Rows) > 0 {
			pick = v.Rows[0].Slug
		}
	}
	for i := range v.Rows {
		v.Rows[i].On = v.Rows[i].Slug == pick
	}
	v.Preview = s.previewOf(pick)
	return v, nil
}

// previewOf renders a template's sections for the picker (empty when
// there is no such template).
func (s *Server) previewOf(slug string) tplPreview {
	t, err := s.Store.Template(slug)
	if err != nil {
		return tplPreview{}
	}
	pv := tplPreview{Title: t.F.Meta.Title, Vector: t.F.Meta.CVSS}
	for _, n := range s.tplSectionNames(t.F) {
		body, _ := t.F.Section(n)
		sec := tplSection{Name: n}
		if strings.TrimSpace(body) != "" {
			sec.HTML = s.renderMD(body)
		}
		pv.Sections = append(pv.Sections, sec)
	}
	return pv
}

func (s *Server) newFindingList(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if _, err := s.Store.Engagement(eng); err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	t := q.Get("t")
	if t == "" {
		t = q.Get("template") // the picked radio, sent along with the search
	}
	v, err := s.pickerView(eng, q.Get("q"), t, "template")
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Preview.OOB = true // the preview follows the pick
	s.exec(w, "new_finding.html", "tpl_search", v)
}

func (s *Server) newFindingPreview(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Store.Engagement(r.PathValue("eng")); err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	t := q.Get("t")
	if t == "" {
		t = q.Get("template")
	}
	s.exec(w, "new_finding.html", "tpl_preview", s.previewOf(t))
}
