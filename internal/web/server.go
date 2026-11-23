// Package web serves the YARS UI: html/template pages with htmx partials.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/events"
	"yars/internal/export"
	"yars/internal/finding"
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
	// HTTPS: the site is served over HTTPS (TLS here or at a proxy), so
	// responses carry Strict-Transport-Security.
	HTTPS bool
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
	// Version is the running build's version (Admin › System); "" shows —.
	Version string
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
	hooksOnce sync.Once  // the webhook worker is started
	pruneOnce sync.Once  // the retention worker is started (D24)
	dailyMu   sync.Mutex // one daily run at a time (the worker's, a test's)
	restoreMu sync.Mutex // one restore of an uploaded backup at a time (D24)
	pages     map[string]*template.Template
	cfgMu     sync.RWMutex // guards Cfg once Admin › Structure saves it
	history   *history.Cache
	started   time.Time
	secretMu  sync.Mutex
	aiTest    atomic.Pointer[aiTestResult] // the last Test on the AI page
	hasUsers  atomic.Bool                  // an account exists (first run is over)
	exports   exportCache
	inboxes   inboxCache
	openCache openCache // Ready to approve and the bulk bar: which findings have open checks
	md        *render.Markdown
	presence  *presence // who has which section open in an editor
	hookOnce  sync.Once
	heartbeat time.Duration // event stream keep-alive (0 = defaultHeartbeat)
	pageSize  int           // board rows per page (0 = boardPage)
	chatLoads atomic.Int64  // full chat reads, for tests of the poll shortcut
	flash     flashes       // one-time secrets for the page after a create
	// lastHealth is the last run of Admin › System's checks; healthRuns
	// counts runs (tests)
	lastHealth atomic.Pointer[healthAdmin]
	healthRuns atomic.Int64
	// bulkBudget is how long a bulk run starts new rows (0 = bulkTime)
	bulkBudget time.Duration
	// boardRead runs once the team board's content is read (tests)
	boardRead func()
}

// boardPage is how many findings the board shows before "Load more".
const boardPage = 200

type link struct {
	Key          string // columns: the sort key (sets the column width)
	Label, URL   string
	Active, Desc bool
	Count        int    // status filters: findings with that status
	Keys         string // aria-keyshortcuts: a status filter's digit (its place, 1–9), a tab's letters
}

// filterKey is the digit of the filter at place i (0-based): 1 to 9, then none.
func filterKey(i int) string {
	if i < 9 {
		return strconv.Itoa(i + 1)
	}
	return ""
}

type panel struct {
	Name, Anchor, EditURL, SaveURL, PreviewURL, Raw string
	LiveURL                                         string // the read panel alone (live refresh; "" = none)
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
	CanEngs       bool   // creates engagements and changes teams (directors and admins)
	CanAdmin      bool   // the Admin nav item
	Nav           string // active top-bar item: "" (findings), "inbox" (the inbox and the notifications page), "admin" or "settings" (the user name: Settings and Developers)
	Bare          bool   // no top bar: login and first run
	Admin         adminView
	Settings      settingsView
	Archive       archiveView // the engagement is archived: read-only bar
	Error         string
	Unreadable    string // a finding file that does not parse: its path in the engagement
	engsErr       error  // the index did not give Engagements: a page that lists them fails with it
	inboxErr      error  // Inbox could not be read: a page made of it fails with it
	Rows          []index.Row
	Offset        int    // first row shown (board pages after the first)
	PageSize      int    // rows per board page
	MoreURL       string // the next board page ("" = no more)
	TabTitle      string // the browser tab's title before " · YARS" ("" = the engagement's name)
	ListURL       string // the board as filtered and sorted now (live refresh)
	LiveURL       string // the board's event stream ("" = no live refresh)
	Q             string // the board's search (D23)
	SearchURL     string // the board as filtered and sorted now, without q (the box supplies it)
	StatusFilters []link
	Bulk          bulkBar           // the board: bulk state change
	Summary       index.Summary     // the board: counts by status and severity, progress
	Bars          boardBars         // the board: progress and severity bars
	BarsOOB       bool              // the bars are sent out of band (after a bulk run)
	EngRows       []engRow          // the home table
	EngShow       string            // … its filter: "", "active" or "archived"
	FieldErrs     map[string]string // a form's errors by field name
	Columns       []link
	Finding       store.FindingRef
	Panels        []panel
	CVSS          cvssView
	Head          headView // the finding's title, status and severity
	Details       detailsView
	WF            wfView
	Inbox         inboxView
	InboxLists    inboxLists // the inbox page: one page of each list
	Chat          chatView
	Checks        checksView
	CloneURL      string
	CloneCmd      string // the engagements list: the main clone's command for this account (mainClone)
	Retest        *retestView
	IsRetest      bool
	Attach        *attachView // the finding page: its attachments (D4)
	Users         []config.User
	ExportV       exportView
	Source        store.Engagement
	Form          url.Values
	// the login lockout (D27): the time left as m:ss ("" = none) and in
	// seconds (the countdown runs from these, not the browser's clock)
	LockLeft    string
	LockSecs    int
	Tpl         tplView     // templates, the template picker
	History     historyView // a finding's history
	ETab        engTabs     // the engagement tabs (Findings, Overview, Report, Settings)
	Overview    overviewView
	Report      reportView
	EngSettings engSettingsView
	Assets      assetsView // a finding's affected assets
	Dups        dupView    // possible duplicates of a finding
	Merge       mergeView  // the Merge confirm page
	Purge       purgeView  // the Purge from history confirm page (D28)
	CanMerge    bool       // the finding page: Merge into
	Unread      int        // the notifications page: unread notifications
	LastEng     string     // a page outside an engagement: the engagement opened last in this browser ("" = none)
	Notes       notesView  // the notifications page
	Docs        docsView   // the developer docs
	TeamBoard   teamBoardView
}

var funcs = template.FuncMap{"join": strings.Join, "checkedIn": checkedIn, "retestLabel": workflow.RetestLabel, "fpath": findingURL,
	"static": staticPrefix, "score": scoreText, "cleared": cleared, "age": age, "day": day, "when": when, "ending": ending,
	"actionTag": actionTag, "actionName": actionName, "statusLabel": workflow.StatusLabel, "statusTitle": workflow.StatusTitle, "shown": workflow.Shown, "dateRange": dateRange, "colspan": colspan,
	// a read panel refetches itself when the finding changed (MCP, a push,
	// another tab); an open editor has no trigger, so it is never replaced
	"liveTrigger": func() string { return "sse:content, sse:resync, sse:poll" },
	// a new password's minlength, as the server checks it
	"minPassword": func() int { return auth.MinPassword },
	// simple reports whether the data folder runs the simple workflow; each
	// server sets its own (init), so any template asks {{if simple}}
	"simple": func() bool { return false },
	"stepArgs": func(s stepRow, retryURL string) any {
		return struct {
			Step     stepRow
			RetryURL string
		}{s, retryURL}
	}}

// colspan is how many columns the findings table has (its pick column too).
func colspan(p *page) int {
	n := len(p.Columns)
	if n == 0 {
		n = len(columns)
	}
	if p.Bulk.On {
		n++
	}
	return n
}

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
			s.Store.OnConfig(s.applyConfig)
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
	own := template.FuncMap{"simple": func() bool { return s.flow().Simple }}
	for _, n := range names {
		if slices.Contains(shared, n) {
			continue
		}
		base := strings.TrimPrefix(n, "templates/")
		s.pages[base] = template.Must(template.New(base).Funcs(funcs).Funcs(own).ParseFS(templateFS, append(slices.Clone(shared), n)...))
	}
}

func (s *Server) Handler() http.Handler {
	s.init()

	private := http.NewServeMux()
	private.HandleFunc("GET /{$}", s.home)
	private.HandleFunc("GET /engagements", s.home)
	private.HandleFunc("GET /events", s.events)
	private.HandleFunc("GET /go", s.goEngagement)
	private.HandleFunc("GET /inbox", s.inbox)
	private.HandleFunc("POST /inbox/board/read", s.boardInboxRead)
	private.HandleFunc("POST /logout", s.logout)
	private.HandleFunc("GET /e/{eng}", s.engagement)
	private.HandleFunc("GET /e/{eng}/f/{fid}", s.finding)
	private.HandleFunc("GET /e/{eng}/f/{fid}/head", s.findingHead)
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
	s.routesTeamBoard(private)
	s.routesPassword(private)
	private.HandleFunc("POST /e/{eng}/archive", s.engArchive(true))
	private.HandleFunc("POST /e/{eng}/reopen", s.engArchive(false))

	root := http.NewServeMux()
	root.HandleFunc("GET /login", s.loginPage)
	root.HandleFunc("POST /login", s.login)
	root.HandleFunc("GET /setup", s.setupPage)
	root.HandleFunc("POST /setup", s.setup)
	root.Handle("GET /static/", staticHandler())
	root.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, staticPrefix()+"/favicon.svg", http.StatusMovedPermanently)
	})
	root.Handle("/", s.Auth.Require(s.mustChangeGate(s.teamGate(private))))
	if s.Git != nil {
		root.Handle("/git/", longLived(s.Git)) // HTTP Basic auth, no cookies; big pushes and clones take time
	}
	if s.MCP != nil {
		root.Handle("/mcp", s.lintLived(s.MCP)) // Bearer tokens, no cookies; lint and transition run every rule
	}
	// Reject cross-origin state-changing requests (CSRF, incl. login CSRF).
	return gzipHandler(secureHeaders(s.HTTPS, http.NewCrossOriginProtection().Handler(limitBody(s.firstRun(root)))))
}

// formMax caps a request body on the website, as MCP caps its requests (a
// section's text comes either way).
const formMax = 2 << 20

// limitBody refuses a body over formMax with 413 before any handler reads
// it. A body sent without a length is read up to the cap first, so a handler
// never parses half a form. Git, MCP and the uploads (attachments, a
// redacted image, a backup to restore, a rule's script) set their own caps:
// an outer cap could not be raised inside them.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ownBodyLimit(r) || r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		tooLarge := func() { http.Error(w, "the request is larger than 2 MiB", http.StatusRequestEntityTooLarge) }
		if r.ContentLength > formMax {
			tooLarge()
			return
		}
		if r.ContentLength < 0 {
			b, err := io.ReadAll(io.LimitReader(r.Body, formMax+1))
			if err != nil {
				http.Error(w, "the request could not be read", http.StatusBadRequest)
				return
			}
			if len(b) > formMax {
				tooLarge()
				return
			}
			r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(b)), int64(len(b))
		}
		next.ServeHTTP(w, r)
	})
}

// ownBodyLimit: the request goes to a handler that caps its body itself.
// The two upload routes are matched by their exact shape (a section or an
// action may be named like their last segment).
func ownBodyLimit(r *http.Request) bool {
	p := r.URL.Path
	if strings.HasPrefix(p, "/git/") || p == "/mcp" {
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	if p == "/admin/system/restore" || p == "/admin/rules/save" {
		return true
	}
	seg := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/"), "/")
	upload := len(seg) == 5 && seg[0] == "e" && seg[2] == "f" && seg[4] == "attachments" // POST /e/{eng}/f/{fid}/attachments
	redact := len(seg) == 7 && seg[0] == "e" && seg[2] == "f" && seg[4] == "attachments" && seg[6] == "redact"
	return upload || redact
}

func (s *Server) render(w http.ResponseWriter, name string, p *page) {
	s.renderStatus(w, http.StatusOK, name, p)
}

func (s *Server) renderStatus(w http.ResponseWriter, status int, name string, p *page) {
	s.keepEng(w, p, status)
	s.execStatus(w, status, name, "layout", p)
}

// lastEngCookie keeps, in the browser, the engagement whose page was shown
// last: a page outside any engagement shows it in the picker and sends
// Findings (f) to its list (base reads it back as page.LastEng).
const lastEngCookie = "yars_eng"

// keepEng remembers p's engagement when p is a signed-in engagement page
// that opened (not an error page).
func (s *Server) keepEng(w http.ResponseWriter, p *page, status int) {
	if p.Eng.ID == "" || p.User.Username == "" || status >= 400 || !store.ValidID(p.Eng.ID) {
		return
	}
	secure := s.Auth != nil && s.Auth.Secure
	http.SetCookie(w, &http.Cookie{Name: lastEngCookie, Value: p.Eng.ID, Path: "/", MaxAge: 365 * 24 * 3600, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: secure})
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
	if errors.Is(err, store.ErrBusy) {
		http.Error(w, store.ErrBusy.Error(), http.StatusConflict)
		return
	}
	log.Printf("error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func canManage(u config.User) bool { return workflow.AtLeast(u, "director") }

// canEngs: directors and admins create engagements and change their teams,
// as the store allows (Admin › Engagements did this before the list).
// Archive, reopen and an engagement's details stay with directors.
func canEngs(u config.User) bool { return store.SeesAll(u) }

// conf is the current configuration.
func (s *Server) conf() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.Cfg
}

// flow is the data folder's workflow: the store's (fixed when it was
// created), or the configuration's on a server without one.
func (s *Server) flow() workflow.Flow {
	if s.Store != nil {
		return s.Store.Flow()
	}
	return workflow.FlowOf(s.conf())
}

// setConfig applies a configuration to the store (which the MCP server
// reads), which hands it to the pages and the style rules (applyConfig) in
// order with every other one.
func (s *Server) setConfig(c config.Config) {
	s.Store.SetConfig(c)
}

// applyConfig is a configuration the store took (Admin › Structure, or a
// git push to the main repo) on the pages and the style rules.
func (s *Server) applyConfig(c config.Config) {
	s.cfgMu.Lock()
	s.Cfg = c
	s.cfgMu.Unlock()
	if s.Rules != nil {
		s.Rules.SetConfig(c)
	}
}

func author(u config.User) gitrepo.Author { return store.AuthorOf(u) }

// base builds the common page data; eng may be "" for pages outside an engagement.
func (s *Server) base(r *http.Request, eng string) (*page, error) {
	u := auth.UserFrom(r.Context())
	vis, err := s.Store.Visible(u)
	if err != nil {
		return nil, err
	}
	// The engagement menu and the badges come from the index and the
	// database: when they cannot be read the page still opens without them
	// (the error is logged); a page that needs the index fails on its own.
	engs, err := s.Index.EngagementsFor(vis) // cached with the index
	if err != nil {
		log.Printf("index: %v", err)
	}
	p := &page{User: u, Engagements: engs, CanManage: canManage(u), CanEngs: canEngs(u), CanAdmin: canAdmin(u), engsErr: err, inboxErr: err}
	if err == nil {
		if err := s.badges(p, u, engs); err != nil {
			log.Printf("inbox badges: %v", err)
			p.Inbox, p.inboxErr = inboxView{}, err
		}
	}
	// outside an engagement: the one last opened here, if the user still sees it
	if c, err := r.Cookie(lastEngCookie); eng == "" && err == nil && slices.ContainsFunc(engs, func(e store.Engagement) bool { return e.ID == c.Value }) {
		p.LastEng = c.Value
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

// badges reads the inbox the top bar counts: the queues, less findings
// waiting on open checks, the team board and the notices.
func (s *Server) badges(p *page, u config.User, engs []store.Engagement) error {
	var err error
	if p.Inbox, err = s.inboxFor(u, engs); err != nil {
		return err
	}
	if p.Inbox, err = s.withoutOpenChecks(p.Inbox); err != nil {
		return err
	}
	// a copy of the cached view: the board and the notices are read now
	if p.Inbox.Board, p.Inbox.BoardTotal, err = s.boardInbox(u, engs); err != nil {
		return err
	}
	p.Inbox.Notes, p.Inbox.NotesTotal, err = s.notesInbox(u, engs)
	return err
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", &page{Bare: true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	// a disabled account gets the same answer as a wrong password
	tok, ok := s.Auth.Login(r.FormValue("username"), r.FormValue("password"))
	if !ok {
		// the username stays filled in (never the password)
		form := url.Values{"username": {r.FormValue("username")}}
		p := &page{Bare: true, Error: "Wrong username or password", Form: form}
		if until, locked := s.Auth.LockedUntil(r.FormValue("username")); locked {
			left := time.Until(until)
			p.LockLeft, p.LockSecs = lockLeft(left), max(int(left.Round(time.Second).Seconds()), 0)
		}
		s.renderStatus(w, http.StatusUnauthorized, "login.html", p)
		return
	}
	s.Auth.SetCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// lockLeft shows the rest of a lockout as m:ss.
func lockLeft(d time.Duration) string {
	sec := max(int(d.Round(time.Second).Seconds()), 0)
	ss := strconv.Itoa(sec % 60)
	if len(ss) < 2 {
		ss = "0" + ss
	}
	return strconv.Itoa(sec/60) + ":" + ss
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.CookieName); err == nil {
		s.Auth.Logout(c.Value)
	}
	s.Auth.ClearCookie(w)
	http.SetCookie(w, &http.Cookie{Name: lastEngCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.Auth.Secure})
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
		p.CloneCmd = mainClone(p.CloneURL, store.SeesAll(p.User), p.Engagements)
	}
	if err = s.engList(p, r.URL.Query().Get("show")); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "engagements.html", p)
}

// mainClone is the command that clones the main repository at url with the
// engagements engs (those the account sees), each on main. The main
// repository names every engagement as a submodule, and git stops a
// recursive clone at the first one the account may not fetch (403), so only
// an account that sees all of them clones recursively; the others check out
// their own by path.
func mainClone(url string, all bool, engs []store.Engagement) string {
	const onMain = "\ngit submodule foreach -q git switch -q main"
	switch {
	case all:
		return "git clone --recurse-submodules " + url + " && cd yars" + onMain
	case len(engs) == 0:
		return "git clone " + url
	}
	return "git clone " + url + " && cd yars\ngit submodule update --init " + engPaths(engs) + onMain
}

// mainCloneLine is mainClone on one line, into findings/, for Developers ›
// Git (which puts the engagements on main on a line of its own).
func mainCloneLine(url string, all bool, engs []store.Engagement) string {
	switch {
	case all:
		return "git clone --recurse-submodules " + url + " findings"
	case len(engs) == 0:
		return "git clone " + url + " findings"
	}
	return "git clone " + url + " findings && git -C findings submodule update --init " + engPaths(engs)
}

// engPaths are the engagements' folders in the main repository.
func engPaths(engs []store.Engagement) string {
	paths := make([]string, len(engs))
	for i, e := range engs {
		paths[i] = "engagements/" + e.ID
	}
	return strings.Join(paths, " ")
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
	p, err := s.engPage(r, eng, nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		if r.URL.Query().Has("offset") {
			s.exec(w, "engagement.html", "finding_rows", p)
			return
		}
		if r.Header.Get("HX-Trigger") == "findings" {
			// the list refreshing itself (live): the progress panel too
			p.BarsOOB = true
			s.exec(w, "engagement.html", "findings_ran", p)
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

// engPage is an engagement's findings list as the URL's query filters and
// sorts it, with the bulk bar of an open engagement. The keep rows (those a
// bulk run just changed) stay in the list whatever their status now, and the
// first page runs long enough to show them.
func (s *Server) engPage(r *http.Request, eng string, keep map[string]bool) (*page, error) {
	p, err := s.base(r, eng)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	if keep == nil {
		// a Load more after a run: the same list as the run's page
		for _, d := range q["keep"] {
			if store.ValidID(d) && len(keep) < maxBulkIDs {
				if keep == nil {
					keep = map[string]bool{}
				}
				keep[d] = true
			}
		}
	}
	q.Del("keep") // filter, sort and bar links start a fresh list
	// the search (D23), trimmed and cut, travels in every link as it is used
	text := strings.TrimSpace(q.Get("q"))
	if r := []rune(text); len(r) > maxSearch {
		text = strings.TrimSpace(string(r[:maxSearch]))
	}
	setOrDel(q, "q", text)
	// the status filter is the shown state: signed off apart from verification
	query := index.Query{EngID: eng, Shown: q.Get("status"), Severity: q.Get("severity"),
		Author: q.Get("author"), Sort: q.Get("sort"), Desc: q.Get("desc") == "1", Keep: keep, Text: text}
	rows, err := s.Index.Rows(query)
	if err != nil {
		return nil, err
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
	for i := end; i < len(rows); i++ {
		if keep[rows[i].Dir] {
			end = i + 1
		}
	}
	p.Rows, p.Offset, p.PageSize = rows[off:end], off, s.pageSize
	p.ListURL = mk(func(url.Values) {})
	p.Q, p.SearchURL = text, mk(func(v url.Values) { v.Del("q") })
	p.LiveURL = "/events?" + url.Values{"eng": {eng}}.Encode()
	if end < len(rows) {
		p.MoreURL = mk(func(v url.Values) {
			v.Set("offset", strconv.Itoa(end))
			for _, d := range slices.Sorted(maps.Keys(keep)) {
				v.Add("keep", d)
			}
		})
	}
	if p.Summary, err = s.Index.Summary(eng); err != nil {
		return nil, err
	}
	p.Bars = barsOf(p.Summary)
	f := s.flow()
	// the workflow's own states, in its order (the simple one: no
	// verification, no signed off), so the digits follow them
	for _, st := range append([]string{""}, f.ShownAll()...) {
		label, n, key := workflow.StatusTitle(st), p.Summary.ByShown[st], st
		if st == "" {
			label, n, key = "All", p.Summary.Total, "all"
		}
		// the key names the link's id (flt-…), so focus stays on it after the swap
		p.StatusFilters = append(p.StatusFilters, link{Key: key, Label: label, Active: st == query.Shown, Count: n,
			URL: mk(func(v url.Values) { setOrDel(v, "status", st) }), Keys: filterKey(len(p.StatusFilters))})
	}
	cols := columns
	if p.Eng.Type == "retest" {
		p.IsRetest = true
		cols = append(append(slices.Clone(columns[:5]), struct{ Key, Label string }{"result", "Result"}), columns[5:]...)
		p.Source, _ = s.Store.Engagement(p.Eng.Source)
	}
	if !f.HasReviewers() {
		// no reviewers: no Reviewers column (finding_rows leaves its cell out)
		cols = slices.DeleteFunc(slices.Clone(cols), func(c struct{ Key, Label string }) bool { return c.Key == "reviewers" })
	}
	for _, c := range cols {
		c := c
		active := c.Key == query.Sort || (query.Sort == "" && c.Key == "id")
		desc := active && !query.Desc
		if c.Key == "chat" && !active {
			desc = true // most open threads first
		}
		p.Columns = append(p.Columns, link{Key: c.Key, Label: c.Label, Active: active, Desc: query.Desc,
			URL: mk(func(v url.Values) {
				v.Set("sort", c.Key)
				setOrDel(v, "desc", map[bool]string{true: "1"}[desc])
			})})
	}
	if !p.Eng.Archived {
		v := url.Values{}
		for k, x := range q {
			v[k] = x
		}
		v.Del("offset")
		p.Bulk = s.bulkBarFor(p.User, eng, v.Encode(), p.Rows)
	}
	return p, nil
}

// maxSearch is the longest search the findings list takes, in characters.
const maxSearch = 200

func setOrDel(v url.Values, k, val string) {
	if val == "" {
		v.Del(k)
	} else {
		v.Set(k, val)
	}
}

// anchor is a section's id suffix: its name in lower case, letters, marks
// and digits of any script kept, every other run of characters one dash, with
// no length cut (store.Slug, which names folders, keeps ASCII only and cuts
// at 40, so names in other scripts and long names shared an anchor).
func anchor(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) { // marks: vowel signs, accents
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	if out := strings.TrimSuffix(b.String(), "-"); out != "" {
		return out
	}
	return "section"
}

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
		p.HTML = s.linkAttachments(s.renderMD(body), ref)
	}
	p.Presence = presView{URL: presURL(ref, name)}
	base := findingURL(ref.EngID, ref.Dir) + "/s/" + url.PathEscape(name)
	p.EditURL, p.SaveURL, p.LiveURL = base+"/edit", base, s.liveURL(base, ref)
	p.PreviewURL = "/e/" + ref.EngID + "/preview?" + url.Values{"f": {ref.Dir}, "s": {name}}.Encode()
	return p
}

// liveKey identifies what a finding's read panels show: its file, status
// and whether its engagement is archived. A live refresh that sends the key
// its panel was drawn with gets 204 (nothing to swap) while it holds, so a
// push to another finding or a poll tick costs no rendering.
func (s *Server) liveKey(ref store.FindingRef) string {
	return store.BodyHash(ref.Hash + "\x00" + ref.F.Meta.Status + "\x00" + workflow.Shown(ref.F.Meta) + "\x00" + strconv.FormatBool(s.Store.Archived(ref.EngID)))
}

// unchanged answers 204 to a live refresh whose panel is still current. A
// section panel's key also holds its open-thread count (o), which a chat
// message changes without changing the file.
func (s *Server) unchanged(w http.ResponseWriter, r *http.Request, ref store.FindingRef) bool {
	q := r.URL.Query()
	if h := q.Get("h"); h == "" || h != s.liveKey(ref) {
		return false
	}
	if o := q.Get("o"); o != "" && o != strconv.Itoa(s.openIn(ref, r.PathValue("section"))) {
		return false
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

// setOpen sets a section panel's open-thread count, which its live
// refresh compares too.
func (p *panel) setOpen(n int) {
	p.Open = n
	if p.LiveURL != "" {
		p.LiveURL += "&o=" + strconv.Itoa(n)
	}
}

// liveURL is a read panel's refresh URL, with the key it is drawn for.
func (s *Server) liveURL(view string, ref store.FindingRef) string {
	return view + "?live=1&h=" + s.liveKey(ref)
}

// headView is the finding page's title column: it refreshes itself when the
// finding changes (a new title or severity by MCP or a push, a status).
type headView struct {
	EngID, EngName, LiveURL string
	Meta                    finding.Meta
	CVSS                    cvssView // the severity pill
}

func (s *Server) headFor(ref store.FindingRef, engName string) headView {
	return headView{EngID: ref.EngID, EngName: engName, LiveURL: s.liveURL(findingURL(ref.EngID, ref.Dir)+"/head", ref), Meta: ref.F.Meta, CVSS: s.cvssPanel(ref)}
}

// findingHead answers the title column alone (live refresh).
func (s *Server) findingHead(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.liveRef(w, r)
	if !ok {
		return
	}
	e, err := s.Store.Engagement(ref.EngID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "finding_head", s.headFor(ref, e.Name))
}

func (s *Server) finding(w http.ResponseWriter, r *http.Request) {
	var d wfDenial
	if js := s.flash.take(r, "wfdenied"); js != "" && json.Unmarshal([]byte(js), &d) == nil && d.Path == r.URL.Path {
		s.renderFindingDenied(w, r, http.StatusOK, d.Error, &d)
		return
	}
	s.renderFinding(w, r, http.StatusOK, "")
}

// renderFinding renders the full finding page, optionally with an error
// banner.
func (s *Server) renderFinding(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	s.renderFindingDenied(w, r, status, errMsg, nil)
}

// renderFindingDenied is renderFinding with a denied workflow action's
// reason panel open again, holding the reason typed (d may be nil).
func (s *Server) renderFindingDenied(w http.ResponseWriter, r *http.Request, status int, errMsg string, d *wfDenial) {
	eng := r.PathValue("eng")
	p, err := s.base(r, eng)
	if err != nil {
		s.fail(w, err)
		return
	}
	var bad *store.UnreadableError
	if p.Finding, err = s.Store.Finding(eng, r.PathValue("fid")); errors.As(err, &bad) {
		// a file put on the server past the push checks: say which and why
		p.Unreadable = "findings/" + bad.Dir + "/finding.md"
		p.Error = bad.Err.Error()
		p.TabTitle = bad.Dir
		s.renderStatus(w, http.StatusUnprocessableEntity, "unreadable.html", p)
		return
	} else if err != nil {
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
		pn.setOpen(p.Chat.BySection[n])
		pn.ReadOnly = p.Archive.On
		if locked {
			pn.EditURL = ""
		}
		p.Panels = append(p.Panels, pn)
	}
	p.CVSS = s.cvssPanel(p.Finding)
	p.CVSS.Locked = locked
	p.Head = s.headFor(p.Finding, p.Eng.Name)
	p.Details = s.detailsFor(p.Finding, nil)
	p.Details.Locked = locked
	p.Assets = s.assetsFor(p.Finding, nil)
	p.Assets.Locked = locked
	p.CanMerge = s.canMerge(r, p.Finding)
	if p.Dups, err = s.dupsFor(r, p.Finding); err != nil {
		s.fail(w, err)
		return
	}
	p.Dups.Side = true
	p.Retest = s.retestFor(r, p.Finding)
	if p.Attach, err = s.attachFor(r, p.Finding); err != nil {
		s.fail(w, err)
		return
	}
	// fast rule errors also block submit/approve; show them in the bar
	p.WF, p.Checks = s.wfGated(r, p.Finding)
	if d != nil {
		p.WF.reopen(d)
	}
	p.TabTitle = p.Finding.F.Meta.ID + " " + p.Finding.F.Meta.Title
	s.renderStatus(w, status, "finding.html", p)
}
