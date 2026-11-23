package web

import (
	"errors"
	"io/fs"
	"net/http"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"yars/internal/auth"
	"yars/internal/export"
	"yars/internal/store"
)

// destRow is a destination in the editor's table.
type destRow struct {
	ID, Name, Sub, Kind, Key string
	Service, Marks, Editing  bool
}

// destForm is the destination editor.
type destForm struct {
	New                                                        bool
	ID, Name, Type, Format, Template, BaseURL, Space, ParentID string
	Project, IssueType, UserEnv, TokenEnv, Script, Extension   string
	Complete, Reported, Marks                                  bool
	Error                                                      string
}

type destSetup struct {
	Rows    []destRow
	Form    destForm
	Types   []option
	Formats []string
}

var destTypes = []option{{Value: "pandoc", Label: "pandoc"}, {Value: "confluence", Label: "confluence"}, {Value: "jira", Label: "jira"}, {Value: "script", Label: "script"}}

var pandocFormats = []string{"pdf", "docx", "odt", "html", "markdown"}

var destID = export.IDRe

const exportersRel = ".yars/exporters/"

// prevOf is the saved destination being replaced (nil: a new one).
func prevOf(cur export.Exporter, found bool) *export.Exporter {
	if !found {
		return nil
	}
	return &cur
}

func (s *Server) routesExportSetup(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/export/setup", s.destPage)
	mux.HandleFunc("POST /e/{eng}/export/setup", s.destSave)
	mux.HandleFunc("POST /e/{eng}/export/setup/delete", s.destDelete)
}

// setupBase is the editor's page for a director; ok false: answered.
func (s *Server) setupBase(w http.ResponseWriter, r *http.Request) (*page, bool) {
	if s.Export == nil {
		http.NotFound(w, r)
		return nil, false
	}
	p, err := s.exportPage(r, nil)
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	if !p.CanManage {
		http.Error(w, "only a director can edit destinations", http.StatusForbidden)
		return nil, false
	}
	p.ExportV.Setup.Types, p.ExportV.Setup.Formats = destTypes, pandocFormats
	return p, true
}

// formOfExporter fills the editor from a destination.
func formOfExporter(ex export.Exporter) destForm {
	f := destForm{ID: ex.ID, Name: ex.Name, Type: ex.Type, Format: ex.Format, Template: ex.Template, Script: ex.Script, Extension: ex.Extension,
		Complete: slices.Contains(ex.Statuses, "complete"), Reported: slices.Contains(ex.Statuses, "reported"), Marks: ex.Marks()}
	if c := ex.Confluence; c != nil {
		f.BaseURL, f.Space, f.ParentID, f.UserEnv, f.TokenEnv = c.BaseURL, c.Space, c.ParentID, c.UserEnv, c.TokenEnv
	}
	if j := ex.Jira; j != nil {
		f.BaseURL, f.Project, f.IssueType, f.UserEnv, f.TokenEnv = j.BaseURL, j.Project, j.IssueType, j.UserEnv, j.TokenEnv
	}
	return f
}

func newDestForm() destForm {
	return destForm{New: true, Type: "pandoc", Format: "pdf", Complete: true, Marks: true}
}

// fillSetup lists the destinations; editing is the open one.
func (s *Server) fillSetup(p *page, editing string) {
	v := &p.ExportV
	if f := v.Setup.Form.Format; f != "" && !slices.Contains(v.Setup.Formats, f) {
		v.Setup.Formats = append(slices.Clone(v.Setup.Formats), f) // written by hand: kept
	}
	for _, ex := range v.exporters {
		row := destRow{ID: ex.ID, Name: ex.Name, Sub: destSub(ex), Kind: "file", Key: "—", Service: ex.Service(), Marks: ex.Marks(), Editing: ex.ID == editing}
		if row.Service {
			row.Kind = "service"
			if k := s.Export.Getenv(ex.TokenEnv()); k != "" {
				row.Key = ending(k)
			}
		}
		v.Setup.Rows = append(v.Setup.Rows, row)
	}
}

func (s *Server) destPage(w http.ResponseWriter, r *http.Request) {
	p, ok := s.setupBase(w, r)
	if !ok {
		return
	}
	edit := r.URL.Query().Get("edit")
	p.ExportV.Setup.Form = newDestForm()
	if ex, found := findExporter(p.ExportV.exporters, edit); found {
		p.ExportV.Setup.Form = formOfExporter(ex)
	} else {
		edit = ""
	}
	s.fillSetup(p, edit)
	s.render(w, "export_setup.html", p)
}

// destFromForm reads the editor; cur is the saved destination being
// edited (its other settings, such as pandoc args, are kept).
func destFromForm(r *http.Request, cur export.Exporter) (destForm, export.Exporter) {
	r.ParseForm()
	v := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	f := destForm{New: v("new") == "1", ID: v("id"), Name: v("name"), Type: v("type"), Format: v("format"), Template: v("template"),
		BaseURL: v("base_url"), Space: v("space"), ParentID: v("parent_id"), Project: v("project"), IssueType: v("issue_type"),
		UserEnv: v("user_env"), TokenEnv: v("token_env"), Script: v("script"), Extension: v("extension"),
		Complete: checkedIn(r.PostForm, "status", "complete"), Reported: checkedIn(r.PostForm, "status", "reported"), Marks: v("mark_reported") == "1"}
	ex := cur
	ex.ID, ex.Name, ex.Type = f.ID, f.Name, f.Type
	ex.Format, ex.Template, ex.Script, ex.Extension, ex.Confluence, ex.Jira = "", "", "", "", nil, nil
	if f.Type != "pandoc" {
		ex.Args = nil
	}
	env := func(val, def string) string {
		if val == "" {
			return def
		}
		return val
	}
	switch f.Type {
	case "pandoc":
		ex.Format, ex.Template = f.Format, f.Template
	case "script":
		ex.Script, ex.Extension = f.Script, f.Extension
	case "confluence":
		if f.BaseURL != "" {
			ex.Confluence = &export.ConfluenceConf{BaseURL: f.BaseURL, Space: f.Space, ParentID: f.ParentID,
				UserEnv: env(f.UserEnv, "CONFLUENCE_USER"), TokenEnv: env(f.TokenEnv, "CONFLUENCE_TOKEN")}
		}
	case "jira":
		ex.Jira = &export.JiraConf{BaseURL: f.BaseURL, Project: f.Project, IssueType: f.IssueType,
			UserEnv: env(f.UserEnv, "JIRA_USER"), TokenEnv: env(f.TokenEnv, "JIRA_TOKEN")}
	}
	ex.Statuses = nil
	if f.Complete {
		ex.Statuses = append(ex.Statuses, "complete")
	}
	if f.Reported {
		ex.Statuses = append(ex.Statuses, "reported")
	}
	marks := f.Marks
	ex.MarkReported = &marks
	return f, ex
}

type destErr struct{ msg string }

func (e *destErr) Error() string { return e.msg }

func (s *Server) destSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.setupBase(w, r)
	if !ok {
		return
	}
	cur, found := findExporter(p.ExportV.exporters, r.FormValue("id"))
	f, ex := destFromForm(r, cur)
	if f.New {
		cur, found = export.Exporter{}, false
		f, ex = destFromForm(r, cur)
	}
	msg := ""
	switch {
	case !destID.MatchString(f.ID):
		msg = "id: lowercase letters, digits, - and _"
	case f.Name == "":
		msg = "name is required"
	case !f.New && !found:
		msg = "destination " + f.ID + " not found"
	case export.NeedsAdmin(prevOf(cur, found), ex) && !p.CanAdmin:
		// the address gets the server's and the authors' keys
		msg = "address and key variables: admin only"
	}
	if msg == "" {
		data, err := yaml.Marshal(ex)
		if err != nil {
			s.fail(w, err)
			return
		}
		file := exportersRel + f.ID + ".yaml"
		err = s.Store.EditSettings("exporters: save "+f.ID, author(p.User), func(read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
			if _, err := read(file); f.New && err == nil {
				return nil, &destErr{"id already used"}
			} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			return []store.SettingsFile{{Path: file, Data: data}}, nil
		}, func() error {
			_, errs := export.Load(s.Export.Dir)
			for _, e := range errs {
				if strings.HasPrefix(e.Error(), f.ID+".yaml:") {
					return &destErr{e.Error()}
				}
			}
			return nil
		})
		var de *destErr
		switch {
		case err == nil:
			http.Redirect(w, r, "/e/"+p.Eng.ID+"/export/setup?edit="+f.ID, http.StatusSeeOther)
			return
		case errors.As(err, &de):
			msg = de.msg
		default:
			s.fail(w, err)
			return
		}
	}
	f.Error = msg
	p.ExportV.Setup.Form = f
	edit := ""
	if !f.New {
		edit = f.ID
	}
	s.fillSetup(p, edit)
	s.renderStatus(w, http.StatusBadRequest, "export_setup.html", p)
}

func (s *Server) destDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.setupBase(w, r)
	if !ok {
		return
	}
	id := r.FormValue("id")
	if _, found := findExporter(p.ExportV.exporters, id); !found || !destID.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	err := s.Store.EditSettings("exporters: delete "+id, author(auth.UserFrom(r.Context())), func(func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		return []store.SettingsFile{{Path: exportersRel + id + ".yaml"}}, nil
	}, nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+p.Eng.ID+"/export/setup", http.StatusSeeOther)
}
