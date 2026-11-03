package web

import (
	"errors"
	"net/http"
	"strings"

	"yars/internal/auth"
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
	mux.HandleFunc("POST /e/{eng}/preview", s.preview)
}

func (s *Server) newEngagementForm(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	if !p.CanManage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, "new_engagement.html", p)
}

func (s *Server) newEngagement(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	if !p.CanManage {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	e := store.Engagement{
		ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Client: strings.TrimSpace(r.FormValue("client")), Type: "pentest",
		Start: r.FormValue("start"), End: r.FormValue("end"),
	}
	switch {
	case !store.ValidID(e.ID):
		p.Error = "ID may contain only letters, digits, dot, dash and underscore."
	case e.Name == "":
		p.Error = "Name is required."
	}
	if p.Error == "" {
		if err := s.Store.CreateEngagement(e, author(p.User)); err != nil {
			p.Error = err.Error()
		} else {
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
	s.render(w, "new_finding.html", p)
}

func (s *Server) newFinding(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	p, err := s.base(r, eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		p.Error = "Title is required."
		s.renderStatus(w, http.StatusBadRequest, "new_finding.html", p)
		return
	}
	ref, err := s.Store.CreateFinding(eng, title, author(p.User))
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+eng+"/f/"+ref.Dir, http.StatusSeeOther)
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
	if ref, name, ok := s.sectionRef(w, r); ok {
		s.exec(w, "finding.html", "panel", s.panelFor(ref, name))
	}
}

func (s *Server) sectionEdit(w http.ResponseWriter, r *http.Request) {
	if ref, name, ok := s.sectionRef(w, r); ok {
		s.exec(w, "finding.html", "editor", s.panelFor(ref, name))
	}
}

func (s *Server) sectionSave(w http.ResponseWriter, r *http.Request) {
	ref, name, ok := s.sectionRef(w, r)
	if !ok {
		return
	}
	u := auth.UserFrom(r.Context())
	body := r.FormValue("body")
	err := s.Store.UpdateSection(ref.EngID, ref.Dir, name, body, r.FormValue("base"), author(u))
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalidBody) {
		// Re-show the editor with the user's text so nothing typed is lost.
		p := s.panelFor(ref, name)
		p.Raw, p.Error = body, err.Error()
		status := http.StatusBadRequest
		if errors.Is(err, store.ErrConflict) {
			status = http.StatusConflict
			p.Error = "This section was changed by someone else while you were editing. Your text is kept below; the current saved version is shown above it. Saving again will replace it."
			p.Current = p.HTML
		}
		s.execStatus(w, status, "finding.html", "editor", p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	ref, err = s.Store.Finding(ref.EngID, ref.Dir)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "panel", s.panelFor(ref, name))
}

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	if _, err := s.Store.Engagement(r.PathValue("eng")); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(s.renderMD(r.FormValue("body"))))
}
