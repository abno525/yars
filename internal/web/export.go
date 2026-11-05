package web

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"yars/internal/auth"
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
	Done       string // Confluence push: the created/updated page URL
	Pushed     bool
	Download   string // link to the finished file
	Filename   string
	Marked     []string
	Failed     []string
}

// exportCache keeps finished files for 10 minutes so the result page can
// show what was marked and offer the download; only the exporting user may
// fetch it.
type exportCache struct {
	mu    sync.Mutex
	items map[string]cachedExport
}

type cachedExport struct {
	user string
	res  export.Result
	exp  time.Time
}

func (c *exportCache) put(user string, res export.Result) string {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]cachedExport{}
	}
	for k, v := range c.items {
		if time.Now().After(v.exp) {
			delete(c.items, k)
		}
	}
	c.items[tok] = cachedExport{user, res, time.Now().Add(10 * time.Minute)}
	return tok
}

func (c *exportCache) get(user, tok string) (export.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[tok]
	if !ok || it.user != user || time.Now().After(it.exp) {
		return export.Result{}, false
	}
	return it.res, true
}

func (s *Server) routesExport(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/export", s.exportForm)
	mux.HandleFunc("POST /e/{eng}/export", s.exportRun)
	mux.HandleFunc("GET /e/{eng}/export/download/{tok}", s.exportDownload)
}

func (s *Server) exportDownload(w http.ResponseWriter, r *http.Request) {
	res, ok := s.exports.get(auth.UserFrom(r.Context()).Username, r.PathValue("tok"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(res.Filename, `"`, "")))
	w.Write(res.Data)
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
	// the exporter may run longer than the server's write timeout
	limit := 120 * time.Second // export.Runner's default
	if s.Export != nil && s.Export.Timeout > 0 {
		limit = s.Export.Timeout
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(limit + 30*time.Second))
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
	dirOf := map[*finding.Finding]string{}
	for i, f := range fs {
		dirOf[f] = dirs[i]
	}
	in := export.Input{Engagement: p.Eng, Findings: fs, Cfg: s.Cfg,
		Attachment: func(f *finding.Finding, rel string) ([]byte, bool) {
			b, err := s.Store.ReadAttachment(p.Eng.ID, dirOf[f], rel)
			return b, err == nil
		}}
	res, err := s.Export.Run(r.Context(), *ex, in)
	if err != nil {
		fail(http.StatusInternalServerError, "export failed: "+err.Error())
		return
	}
	// a successful export by a director marks complete findings reported
	v := &p.ExportV
	if ex.Marks() && p.CanManage {
		for i, f := range fs {
			if f.Meta.Status != "complete" {
				continue
			}
			if err := s.Store.Transition(p.Eng.ID, dirs[i], workflow.Report, "", p.User); err != nil {
				log.Printf("export: mark %s reported: %v", f.Meta.ID, err)
				v.Failed = append(v.Failed, f.Meta.ID+" ("+err.Error()+")")
				continue
			}
			v.Marked = append(v.Marked, f.Meta.ID)
		}
	}
	if res.Pushed {
		v.Pushed, v.Done = true, res.URL
	} else {
		v.Download = "/e/" + p.Eng.ID + "/export/download/" + s.exports.put(p.User.Username, res)
		v.Filename = res.Filename
	}
	if p.Rows, err = s.Index.Rows(index.Query{EngID: p.Eng.ID, Sort: "severity"}); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "export.html", p)
}
