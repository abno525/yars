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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/events"
	"yars/internal/export"
	"yars/internal/gitrepo"
	"yars/internal/history"
	"yars/internal/index"
	"yars/internal/notify"
	"yars/internal/render"
	"yars/internal/rules"
	"yars/internal/secret"
	"yars/internal/store"
	"yars/internal/webhook"
	"yars/internal/workflow"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	Store  *store.Store
	Index  *index.Index
	Auth   *auth.Auth
	Cfg    config.Config
	Rules  *rules.Engine  // optional style rules
	Git    http.Handler   // optional git smart HTTP endpoint, mounted at /git/
	Export *export.Runner // optional exporters
	MCP    http.Handler   // optional MCP endpoint, mounted at /mcp
	// Events carries live changes to open pages (GET /events); created by
	// Handler when nil. Whoever else changes data (the git server after a
	// push) publishes to the same hub.
	Events *events.Hub
	// Tokens manages API tokens (settings, admin); made from the database
	// when nil.
	Tokens *auth.Tokens
	// Secret encrypts personal keys and the AI key; opened from the data
	// directory's key file on first use when nil.
	Secret *secret.Box
	// MigrateStatus lists what in the data directory still needs `yars
	// migrate` (the admin's Migrate status button); nil = nothing known.
	MigrateStatus func() []string
	// Webhooks queues and sends events to outside services; Notifier makes
	// the in-app notifications and email. Both are made from the database
	// when nil and subscribed to the store's events.
	Webhooks *webhook.Service
	Notifier *notify.Notifier

	stop      chan struct{} // closes the background workers (Close)
	stopOnce  sync.Once
	hooksOnce sync.Once // the webhook worker is started
	pages     map[string]*template.Template
	cfgMu     sync.RWMutex // guards Cfg once Admin › Structure saves it
	history   *history.Cache
	started   time.Time
	secretMu  sync.Mutex
	aiTest    atomic.Pointer[aiTestResult] // the last Test on the AI page
	hasUsers  atomic.Bool                  // an account exists (first run is over)
	exports   exportCache
	inboxes   inboxCache
	md        *render.Markdown
	presence  *presence // who has which section open in an editor
	hookOnce  sync.Once
	heartbeat time.Duration // event stream keep-alive (0 = defaultHeartbeat)
	pageSize  int           // board rows per page (0 = boardPage)
	chatLoads atomic.Int64  // full chat reads, for tests of the poll shortcut
}

// boardPage is how many findings the board shows before "Load more".
const boardPage = 200

type link struct {
	Key          string // columns: the sort key (sets the column width)
	Label, URL   string
	Active, Desc bool
	Count        int // status filters: findings with that status
}

type panel struct {
	Name, Anchor, EditURL, SaveURL, PreviewURL, Raw string
	Base, Error                                     string
	Open                                            int // open chat threads anchored here
	HTML, Current                                   template.HTML
	Conflict                                        bool // saved meanwhile by someone else: Current is theirs
	ReadOnly                                        bool // archived engagement: no Comment either
	Presence                                        presView
	Attach                                          *attachView
	Diff                                            *conflictDiff
}

type page struct {
	User          config.User
	Engagements   []store.Engagement
	Eng           store.Engagement
	CanManage     bool
	CanAdmin      bool   // the Admin nav item
	Nav           string // active top-bar item: "" (findings), "inbox", "admin" or "settings" (the user name)
	Bare          bool   // no top bar: login and first run
	Admin         adminView
	Settings      settingsView
	Archive       archiveView // the engagement is archived: read-only bar
	Error         string
	Rows          []index.Row
	Offset        int    // first row shown (board pages after the first)
	PageSize      int    // rows per board page
	MoreURL       string // the next board page ("" = no more)
	StatusFilters []link
	Summary       index.Summary // the board: counts by status and severity, progress
	Bars          boardBars     // the board: progress and severity bars
	EngRows       []engRow      // the home table
	Columns       []link
	Finding       store.FindingRef
	Panels        []panel
	CVSS          cvssView
	Details       detailsView
	WF            wfView
	Inbox         inboxView
	InboxLists    inboxLists // the inbox page: one page of each list
	Chat          chatView
	Checks        checksView
	CloneURL      string
	Retest        *retestView
	IsRetest      bool
	Users         []config.User
	ExportV       exportView
	Source        store.Engagement
	Form          url.Values
	Tpl           tplView     // templates, the template picker
	History       historyView // a finding's history
	ETab          engTabs     // the engagement tabs (Findings, Overview, Report, Settings)
	Overview      overviewView
	Report        reportView
	EngSettings   engSettingsView
	Assets        assetsView // a finding's affected assets
	Dups          dupView    // possible duplicates of a finding
	Merge         mergeView  // the Merge confirm page
	CanMerge      bool       // the finding page: Merge into
	Unread        int        // the bell: unread notifications
	Notes         notesView  // the notifications page
	Docs          docsView   // the developer docs
}

var funcs = template.FuncMap{"join": strings.Join, "checkedIn": checkedIn, "retestLabel": workflow.RetestLabel, "fpath": findingURL,
	"static": staticPrefix, "score0": score0, "cleared": cleared, "age": age, "day": day, "when": when, "ending": ending,
	"actionTag": actionTag, "actionName": actionName}

// findingURL is a finding's page: /e/<eng>/f/<number>.
func findingURL(eng, dir string) string { return "/e/" + eng + "/f/" + store.ShortID(dir) }

func (s *Server) init() {
	s.hookOnce.Do(func() {
		s.started = time.Now()
		s.md = render.New(render.Size)
		s.history = history.NewCache(256)
		if s.Tokens == nil && s.Store != nil && s.Store.DB() != nil {
			s.Tokens = auth.NewTokens(s.Store.DB())
		}
		s.wireAI()
		if s.Events == nil {
			s.Events = events.New()
		}
		s.presence = newPresence(func() *events.Hub { return s.Events })
		s.stop = make(chan struct{})
		if s.Store != nil {
			s.Store.OnChange(s.publishChange)
			s.wireNotifications()
		}
	})
	if s.pageSize <= 0 {
		s.pageSize = boardPage
	}
	s.pages = map[string]*template.Template{}
	// Shared templates are parsed into every page so partial handlers can
	// execute their blocks via any page set.
	shared := []string{"templates/layout.html", "templates/partials.html", "templates/cvss.html", "templates/details.html", "templates/workflow.html", "templates/chat.html", "templates/checks.html", "templates/retest.html", "templates/board.html", "templates/assets.html"}
	names, _ := fs.Glob(templateFS, "templates/*.html")
	for _, n := range names {
		if slices.Contains(shared, n) {
			continue
		}
		base := strings.TrimPrefix(n, "templates/")
		s.pages[base] = template.Must(template.New(base).Funcs(funcs).ParseFS(templateFS, append(slices.Clone(shared), n)...))
	}
}

func (s *Server) Handler() http.Handler {
	s.init()

	private := http.NewServeMux()
	private.HandleFunc("GET /{$}", s.home)
	private.HandleFunc("GET /events", s.events)
	private.HandleFunc("GET /go", s.goEngagement)
	private.HandleFunc("GET /inbox", s.inbox)
	private.HandleFunc("POST /logout", s.logout)
	private.HandleFunc("GET /e/{eng}", s.engagement)
	private.HandleFunc("GET /e/{eng}/f/{fid}", s.finding)
	s.routesEdit(private)
	s.routesCVSS(private)
	s.routesDetails(private)
	s.routesWorkflow(private)
	s.routesChat(private)
	s.routesChecks(private)
	s.routesRetest(private)
	s.routesExport(private)
	s.routesBulk(private)
	s.routesAdmin(private)
	s.routesSettings(private)
	s.routesTemplates(private)
	s.routesHistory(private)
	s.routesEngTabs(private)
	s.routesAssets(private)
	s.routesAttach(private)
	s.routesMerge(private)
	s.routesNotifications(private)
	s.routesDocs(private)
	private.HandleFunc("POST /e/{eng}/reopen", s.engReopen)

	root := http.NewServeMux()
	root.HandleFunc("GET /login", s.loginPage)
	root.HandleFunc("POST /login", s.login)
	root.HandleFunc("GET /setup", s.setupPage)
	root.HandleFunc("POST /setup", s.setup)
	root.Handle("GET /static/", staticHandler())
	root.Handle("/", s.Auth.Require(s.teamGate(private)))
	if s.Git != nil {
		root.Handle("/git/", longLived(s.Git)) // HTTP Basic auth, no cookies; big pushes and clones take time
	}
	if s.MCP != nil {
		root.Handle("/mcp", s.MCP) // Bearer tokens, no cookies
	}
	// Reject cross-origin state-changing requests (CSRF, incl. login CSRF).
	return gzipHandler(http.NewCrossOriginProtection().Handler(s.firstRun(root)))
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
	var d *workflow.Denied
	if errors.As(err, &d) {
		http.Error(w, d.Reason, http.StatusForbidden)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, nil)
		return
	}
	if errors.Is(err, store.ErrArchived) {
		http.Error(w, store.ErrArchived.Error(), http.StatusForbidden)
		return
	}
	log.Printf("error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func canManage(u config.User) bool { return workflow.AtLeast(u, "director") }

// conf is the current configuration.
func (s *Server) conf() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.Cfg
}

// setConfig applies a saved configuration to the pages and the store.
func (s *Server) setConfig(c config.Config) {
	s.cfgMu.Lock()
	s.Cfg = c
	s.cfgMu.Unlock()
	s.Store.SetConfig(c)
}

func author(u config.User) gitrepo.Author { return store.AuthorOf(u) }

// base builds the common page data; eng may be "" for pages outside an engagement.
func (s *Server) base(r *http.Request, eng string) (*page, error) {
	u := auth.UserFrom(r.Context())
	vis, err := s.Store.Visible(u)
	if err != nil {
		return nil, err
	}
	engs, err := s.Index.EngagementsFor(vis) // cached with the index
	if err != nil {
		return nil, err
	}
	p := &page{User: u, Engagements: engs, CanManage: canManage(u), CanAdmin: canAdmin(u)}
	if p.Inbox, err = s.inboxFor(u, engs); err != nil {
		return nil, err
	}
	if p.Unread, err = s.Store.UnreadCount(u); err != nil {
		return nil, err
	}
	if eng != "" {
		i := slices.IndexFunc(engs, func(e store.Engagement) bool { return e.ID == eng })
		if i >= 0 {
			p.Eng = engs[i]
		} else if p.Eng, err = s.Store.Engagement(eng); err != nil {
			return nil, err
		}
		if p.Eng.Archived {
			p.Archive = s.archiveOf(p.Eng.ID, p.CanManage)
		}
	}
	return p, nil
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", &page{Bare: true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	// a disabled account gets the same answer as a wrong password
	tok, ok := s.Auth.Login(r.FormValue("username"), r.FormValue("password"))
	if !ok {
		s.renderStatus(w, http.StatusUnauthorized, "login.html", &page{Bare: true, Error: "Wrong username or password"})
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
	if s.Git != nil {
		p.CloneURL = gitBase(r) + "/git/yars"
	}
	if p.EngRows, err = s.engRows(p.Engagements); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "engagements.html", p)
}

// gitBase is the server's base URL as the browser sees it.
func gitBase(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
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
	{"id", "ID"}, {"title", "Title"}, {"severity", "Severity"}, {"cvss", "CVSS"}, {"status", "Status"}, {"chat", "Chat"}, {"author", "Author"}, {"reviewers", "Reviewers"},
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
	rows, err := s.Index.Rows(query)
	if err != nil {
		s.fail(w, err)
		return
	}
	mk := func(mod func(url.Values)) string {
		v := url.Values{}
		for k, x := range q {
			v[k] = x
		}
		v.Del("offset")
		mod(v)
		if e := v.Encode(); e != "" {
			return "/e/" + eng + "?" + e
		}
		return "/e/" + eng
	}
	// one page of the filtered, sorted rows; "Load more" appends the next
	off, _ := strconv.Atoi(q.Get("offset"))
	off = min(max(off, 0), len(rows))
	end := min(off+s.pageSize, len(rows))
	p.Rows, p.Offset, p.PageSize = rows[off:end], off, s.pageSize
	if end < len(rows) {
		p.MoreURL = mk(func(v url.Values) { v.Set("offset", strconv.Itoa(end)) })
	}
	if p.Summary, err = s.Index.Summary(eng); err != nil {
		s.fail(w, err)
		return
	}
	p.Bars = barsOf(p.Summary)
	for _, st := range append([]string{""}, index.StatusOrder...) {
		label, n := st, p.Summary.ByStatus[st]
		if st == "" {
			label, n = "all", p.Summary.Total
		}
		p.StatusFilters = append(p.StatusFilters, link{Label: label, Active: st == query.Status, Count: n,
			URL: mk(func(v url.Values) { setOrDel(v, "status", st) })})
	}
	cols := columns
	if p.Eng.Type == "retest" {
		p.IsRetest = true
		cols = append(append(slices.Clone(columns[:5]), struct{ Key, Label string }{"result", "Result"}), columns[5:]...)
		p.Source, _ = s.Store.Engagement(p.Eng.Source)
	}
	for _, c := range cols {
		c := c
		active := c.Key == query.Sort || (query.Sort == "" && c.Key == "id")
		desc := active && !query.Desc
		p.Columns = append(p.Columns, link{Key: c.Key, Label: c.Label, Active: active, Desc: query.Desc,
			URL: mk(func(v url.Values) {
				v.Set("sort", c.Key)
				setOrDel(v, "desc", map[bool]string{true: "1"}[desc])
			})})
	}
	if r.Header.Get("HX-Request") == "true" {
		if q.Has("offset") {
			s.exec(w, "engagement.html", "finding_rows", p)
			return
		}
		s.exec(w, "engagement.html", "findings", p)
		return
	}
	if s.Git != nil {
		p.CloneURL = gitBase(r) + "/git/e/" + p.Eng.ID
	}
	if err := s.tabsFor(p, "findings"); err != nil {
		s.fail(w, err)
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

// renderMD renders Markdown through the shared cache (sections, chat and
// preview).
func (s *Server) renderMD(src string) template.HTML { return s.md.HTML(src) }

// sectionNames lists the finding's sections in file order, followed by
// configured sections the file lacks.
func (s *Server) sectionNames(ref store.FindingRef) []string {
	var names []string
	seen := map[string]bool{}
	for _, sec := range ref.F.Sections {
		names = append(names, sec.Name)
		seen[sec.Name] = true
	}
	for _, n := range s.conf().Sections {
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
		p.HTML = linkAttachments(s.renderMD(body), ref)
	}
	p.Presence = presView{URL: presURL(ref, name)}
	base := findingURL(ref.EngID, ref.Dir) + "/s/" + url.PathEscape(name)
	p.EditURL, p.SaveURL = base+"/edit", base
	p.PreviewURL = "/e/" + ref.EngID + "/preview?" + url.Values{"f": {ref.Dir}, "s": {name}}.Encode()
	return p
}

func (s *Server) finding(w http.ResponseWriter, r *http.Request) {
	s.renderFinding(w, r, http.StatusOK, "")
}

// renderFinding renders the full finding page, optionally with an error
// banner (used when a workflow action is denied).
func (s *Server) renderFinding(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
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
	p.Error = errMsg
	p.Tpl.CanEdit = canEditTemplates(p.User)
	stamp := s.chatStamp(p.Finding)
	msgs, err := s.loadChat(p.Finding)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Chat = s.chatFor(p.Finding, msgs, stamp, false, s.hiddenFor(r, p.Finding))
	locked := s.locked(r, p.Finding)
	for _, n := range s.sectionNames(p.Finding) {
		pn := s.panelFor(p.Finding, n)
		pn.Presence = s.presenceFor(r, p.Finding, n)
		pn.Open = p.Chat.BySection[n]
		pn.ReadOnly = p.Archive.On
		if locked {
			pn.EditURL = ""
		}
		p.Panels = append(p.Panels, pn)
	}
	p.CVSS = s.cvssPanel(p.Finding)
	p.CVSS.Locked = locked
	p.Details = s.detailsFor(p.Finding, nil)
	p.Details.Locked = locked
	p.Assets = s.assetsFor(p.Finding, nil)
	p.Assets.Locked = locked
	p.CanMerge = s.canMerge(r, p.Finding)
	if p.Dups, err = s.dupsFor(r, p.Finding); err != nil {
		s.fail(w, err)
		return
	}
	p.Retest = s.retestFor(r, p.Finding)
	// fast rule errors also block submit/approve; show them in the bar
	p.WF, p.Checks = s.wfGated(r, p.Finding)
	s.renderStatus(w, status, "finding.html", p)
}
