// Package web serves the YARS UI: html/template pages with htmx partials.
package web

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	Store *store.Store
	Index *index.Index
	Auth  *auth.Auth
	Cfg   config.Config

	pages map[string]*template.Template
	md    goldmark.Markdown
}

type link struct {
	Label, URL   string
	Active, Desc bool
}

type panel struct {
	Name, Anchor, EditURL, SaveURL, PreviewURL, Raw string
	Base, Error                                     string
	HTML, Current                                   template.HTML
}

type page struct {
	User          config.User
	Engagements   []store.Engagement
	Eng           store.Engagement
	CanManage     bool
	Error         string
	Rows          []index.Row
	StatusFilters []link
	Columns       []link
	Finding       store.FindingRef
	Panels        []panel
	Form          url.Values
}

var funcs = template.FuncMap{"join": strings.Join}

func (s *Server) init() {
	s.md = goldmark.New(goldmark.WithExtensions(extension.GFM))
	s.pages = map[string]*template.Template{}
	names, _ := fs.Glob(templateFS, "templates/*.html")
	for _, n := range names {
		base := strings.TrimPrefix(n, "templates/")
		if base == "layout.html" || base == "partials.html" {
			continue
		}
		s.pages[base] = template.Must(template.New(base).Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/partials.html", n))
	}
}

func (s *Server) Handler() http.Handler {
	s.init()
	static, _ := fs.Sub(staticFS, "static")

	private := http.NewServeMux()
	private.HandleFunc("GET /{$}", s.home)
	private.HandleFunc("GET /go", s.goEngagement)
	private.HandleFunc("POST /logout", s.logout)
	private.HandleFunc("GET /e/{eng}", s.engagement)
	private.HandleFunc("GET /e/{eng}/f/{fid}", s.finding)
	s.routesEdit(private)

	root := http.NewServeMux()
	root.HandleFunc("GET /login", s.loginPage)
	root.HandleFunc("POST /login", s.login)
	root.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	root.Handle("/", s.Auth.Require(private))
	// Reject cross-origin state-changing requests (CSRF, incl. login CSRF).
	return http.NewCrossOriginProtection().Handler(root)
}

func (s *Server) render(w http.ResponseWriter, name string, p *page) {
	s.execStatus(w, http.StatusOK, name, "layout", p)
}

func (s *Server) renderStatus(w http.ResponseWriter, status int, name string, p *page) {
	s.execStatus(w, status, name, "layout", p)
}

func (s *Server) exec(w http.ResponseWriter, name, tmpl string, data any) {
	s.execStatus(w, http.StatusOK, name, tmpl, data)
}

// execStatus renders into a buffer first so headers and status are only
// written once the template succeeded.
func (s *Server) execStatus(w http.ResponseWriter, status int, name, tmpl string, data any) {
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, tmpl, data); err != nil {
		log.Printf("template %s/%s: %v", name, tmpl, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, nil)
		return
	}
	log.Printf("error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func canManage(u config.User) bool { return u.Role == "admin" || u.Role == "director" }

func author(u config.User) gitrepo.Author {
	email := u.Email
	if email == "" {
		email = u.Username + "@yars.local"
	}
	return gitrepo.Author{Name: u.Username, Email: email}
}

// base builds the common page data; eng may be "" for pages outside an engagement.
func (s *Server) base(r *http.Request, eng string) (*page, error) {
	u := auth.UserFrom(r.Context())
	engs, err := s.Store.ListEngagements()
	if err != nil {
		return nil, err
	}
	p := &page{User: u, Engagements: engs, CanManage: canManage(u)}
	if eng != "" {
		if p.Eng, err = s.Store.Engagement(eng); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", &page{})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	tok, ok := s.Auth.Login(r.FormValue("username"), r.FormValue("password"))
	if !ok {
		s.renderStatus(w, http.StatusUnauthorized, "login.html", &page{Error: "Wrong username or password."})
		return
	}
	auth.SetCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		s.Auth.Logout(c.Value)
	}
	auth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "engagements.html", p)
}

func (s *Server) goEngagement(w http.ResponseWriter, r *http.Request) {
	eng := r.URL.Query().Get("eng")
	if !store.ValidID(eng) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/e/"+eng, http.StatusSeeOther)
}

var columns = []struct{ Key, Label string }{
	{"id", "ID"}, {"title", "Title"}, {"severity", "Severity"}, {"status", "Status"}, {"author", "Author"}, {"reviewers", "Reviewers"},
}

func (s *Server) engagement(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	p, err := s.base(r, eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	query := index.Query{EngID: eng, Status: q.Get("status"), Severity: q.Get("severity"),
		Author: q.Get("author"), Sort: q.Get("sort"), Desc: q.Get("desc") == "1"}
	if p.Rows, err = s.Index.Rows(query); err != nil {
		s.fail(w, err)
		return
	}
	mk := func(mod func(url.Values)) string {
		v := url.Values{}
		for k, x := range q {
			v[k] = x
		}
		mod(v)
		if e := v.Encode(); e != "" {
			return "/e/" + eng + "?" + e
		}
		return "/e/" + eng
	}
	for _, st := range append([]string{""}, index.StatusOrder...) {
		label := st
		if st == "" {
			label = "all"
		}
		p.StatusFilters = append(p.StatusFilters, link{Label: label, Active: st == query.Status,
			URL: mk(func(v url.Values) { setOrDel(v, "status", st) })})
	}
	for _, c := range columns {
		c := c
		active := c.Key == query.Sort || (query.Sort == "" && c.Key == "id")
		desc := active && !query.Desc
		p.Columns = append(p.Columns, link{Label: c.Label, Active: active, Desc: query.Desc,
			URL: mk(func(v url.Values) {
				v.Set("sort", c.Key)
				setOrDel(v, "desc", map[bool]string{true: "1"}[desc])
			})})
	}
	if r.Header.Get("HX-Request") == "true" {
		s.exec(w, "engagement.html", "findings", p)
		return
	}
	s.render(w, "engagement.html", p)
}

func setOrDel(v url.Values, k, val string) {
	if val == "" {
		v.Del(k)
	} else {
		v.Set(k, val)
	}
}

func anchor(name string) string { return store.Slug(name) }

func (s *Server) renderMD(src string) template.HTML {
	var buf bytes.Buffer
	if err := s.md.Convert([]byte(src), &buf); err != nil {
		return template.HTML(template.HTMLEscapeString(src))
	}
	return template.HTML(buf.String())
}

// sectionNames lists the finding's sections in file order, followed by
// configured sections the file lacks.
func (s *Server) sectionNames(ref store.FindingRef) []string {
	var names []string
	seen := map[string]bool{}
	for _, sec := range ref.F.Sections {
		names = append(names, sec.Name)
		seen[sec.Name] = true
	}
	for _, n := range s.Cfg.Sections {
		if !seen[n] {
			names = append(names, n)
		}
	}
	return names
}

func (s *Server) panelFor(ref store.FindingRef, name string) panel {
	body, _ := ref.F.Section(name)
	p := panel{Name: name, Anchor: anchor(name), Raw: strings.Trim(body, "\n"), Base: store.BodyHash(body)}
	if strings.TrimSpace(body) != "" {
		p.HTML = s.renderMD(body)
	}
	base := "/e/" + ref.EngID + "/f/" + ref.Dir + "/s/" + url.PathEscape(name)
	p.EditURL, p.SaveURL, p.PreviewURL = base+"/edit", base, "/e/"+ref.EngID+"/preview"
	return p
}

func (s *Server) finding(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	p, err := s.base(r, eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Finding, err = s.Store.Finding(eng, r.PathValue("fid")); err != nil {
		s.fail(w, err)
		return
	}
	for _, n := range s.sectionNames(p.Finding) {
		p.Panels = append(p.Panels, s.panelFor(p.Finding, n))
	}
	s.render(w, "finding.html", p)
}
