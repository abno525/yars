package web

import (
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"yars/internal/export"
	"yars/internal/finding"
	"yars/internal/index"
	"yars/internal/workflow"
)

type exportView struct {
	Exporters  []export.Exporter
	LoadErrors []string
	Selected   string
	CanMark    bool
	Enabled    bool
	Done       string // Confluence push: the created page URL
	Marked     []string
}

func (s *Server) routesExport(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/export", s.exportForm)
	mux.HandleFunc("POST /e/{eng}/export", s.exportRun)
}

func (s *Server) exportPage(r *http.Request) (*page, error) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		return nil, err
	}
	if p.Rows, err = s.Index.Rows(index.Query{EngID: p.Eng.ID, Sort: "severity"}); err != nil {
		return nil, err
	}
	v := exportView{Enabled: s.Export != nil, CanMark: p.CanManage}
	if s.Export != nil {
		var errs []error
		v.Exporters, errs = export.Load(s.Export.Dir)
		for _, e := range errs {
			v.LoadErrors = append(v.LoadErrors, e.Error())
		}
	}
	p.ExportV = v
	return p, nil
}

func (s *Server) exportForm(w http.ResponseWriter, r *http.Request) {
	p, err := s.exportPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(p.ExportV.Exporters) > 0 {
		ex := p.ExportV.Exporters[0]
		if q := r.URL.Query().Get("exporter"); q != "" {
			for _, e := range p.ExportV.Exporters {
				if e.ID == q {
					ex = e
				}
			}
		}
		p.ExportV.Selected = ex.ID
		p.Form = map[string][]string{}
		for _, row := range p.Rows {
			if slices.Contains(ex.Statuses, row.Status) {
				p.Form["finding"] = append(p.Form["finding"], row.Dir)
			}
		}
	}
	s.render(w, "export.html", p)
}

func (s *Server) exportRun(w http.ResponseWriter, r *http.Request) {
	p, err := s.exportPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	p.ExportV.Selected = r.FormValue("exporter")
	fail := func(status int, msg string) {
		p.Error = msg
		s.renderStatus(w, status, "export.html", p)
	}
	var ex *export.Exporter
	for i := range p.ExportV.Exporters {
		if p.ExportV.Exporters[i].ID == p.ExportV.Selected {
			ex = &p.ExportV.Exporters[i]
		}
	}
	if s.Export == nil || ex == nil {
		fail(http.StatusBadRequest, "choose an exporter")
		return
	}
	var fs []*finding.Finding
	var dirs []string
	for _, d := range r.PostForm["finding"] {
		ref, err := s.Store.Finding(p.Eng.ID, d)
		if err != nil {
			fail(http.StatusBadRequest, "unknown finding "+d)
			return
		}
		fs, dirs = append(fs, ref.F), append(dirs, d)
	}
	if len(fs) == 0 {
		fail(http.StatusBadRequest, "select at least one finding")
		return
	}
	res, err := s.Export.Run(r.Context(), *ex, export.Input{Engagement: p.Eng, Findings: fs, Cfg: s.Cfg})
	if err != nil {
		fail(http.StatusInternalServerError, "export failed: "+err.Error())
		return
	}
	// a successful export by a director marks complete findings reported
	var marked []string
	if ex.Marks() && p.CanManage {
		for i, f := range fs {
			if f.Meta.Status != "complete" {
				continue
			}
			if err := s.Store.Transition(p.Eng.ID, dirs[i], workflow.Report, "", p.User); err != nil {
				log.Printf("export: mark %s reported: %v", f.Meta.ID, err)
				continue
			}
			marked = append(marked, f.Meta.ID)
		}
	}
	if res.URL != "" {
		p.ExportV.Done, p.ExportV.Marked = res.URL, marked
		s.render(w, "export.html", p)
		return
	}
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(res.Filename, `"`, "")))
	if len(marked) > 0 {
		w.Header().Set("X-Yars-Marked-Reported", strings.Join(marked, ","))
	}
	w.Write(res.Data)
}
