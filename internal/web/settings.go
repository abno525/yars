package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/notify"
	"yars/internal/secret"
)

// settingsView is the account's own settings page and the New token page.
type settingsView struct {
	Tokens   []tokenRow
	Conns    []connRow
	Notify   []notifyRow
	Channels []option
	Themes   []option
	Keys     []option // keyboard shortcuts On / Off
	// what failed, per panel ("" = nothing)
	AccountErr, PasswordErr, ConnErr, NotifyErr string
	Token                                       tokenForm // the New token page
	NewToken                                    string    // a token just created, shown once
}

// tokenRow is one token in a list: what it can do, never its secret.
type tokenRow struct {
	ID                                     int64
	User, Name, Kind, Can, Where, Ending   string
	Expires, LastUsed, Created, ExpireSoon string
}

type connRow struct {
	Service, Label, Host, Ending, Created string
	Has, Broken                           bool
}

type notifyRow struct {
	Event, Label string
	Cells        []option // Value "<event>.<channel>", On = chosen
}

// tokenForm is the New token form, and the created token shown once.
type tokenForm struct {
	Name, Kind, Access, Engs, Expires string
	Actions, EngOpts                  []option
	Error                             string
	Secret                            string // the new token (only right after creating it)
	MCPURL, GitURL                    string
}

var tokenActionLabels = map[string]string{"create": "Create findings", "edit": "Edit findings", "comment": "Comment and resolve",
	"status": "Change status", "reviewers": "Assign reviewers", "checks": "Run checks", "export": "Export reports"}

// tokenActions are the actions a new token can be given: db.TokenActions,
// less Assign reviewers in the simple workflow (it has no reviewers).
func (s *Server) tokenActions() []string {
	if s.flow().Simple {
		return slices.DeleteFunc(slices.Clone(db.TokenActions), func(a string) bool { return a == "reviewers" })
	}
	return db.TokenActions
}

var tokenExpiry =[]option{{Value: "30", Label: "30 days"}, {Value: "90", Label: "90 days"}, {Value: "365", Label: "1 year"}, {Value: "never", Label: "Never"}}

// Connections: outside services a user can keep a personal key for.
var connServices = []option{{Value: "confluence", Label: "Confluence"}, {Value: "jira", Label: "Jira"}}

// Notification channels; email only when the server can send mail.
var notifyChannels = []option{{Value: "app", Label: "In app"}, {Value: "email", Label: "Email"}}

func (s *Server) channels() []option {
	if s.conf().SMTP.Configured() {
		return notifyChannels
	}
	return notifyChannels[:1]
}

func (s *Server) routesSettings(mux *http.ServeMux) {
	mux.HandleFunc("GET /settings", s.settingsPage)
	mux.HandleFunc("POST /settings/account", s.settingsAccount)
	mux.HandleFunc("POST /settings/password", s.settingsPassword)
	mux.HandleFunc("POST /settings/prefs", s.settingsPrefs)
	mux.HandleFunc("GET /settings/tokens/new", s.tokenNewPage)
	mux.HandleFunc("POST /settings/tokens/new", s.tokenCreate)
	mux.HandleFunc("POST /settings/tokens/{id}/revoke", s.tokenRevoke)
	mux.HandleFunc("POST /settings/connections", s.connSave)
	mux.HandleFunc("POST /settings/connections/{service}/remove", s.connRemove)
	mux.HandleFunc("POST /settings/notifications", s.notifySave)
}

// secrets is the box that encrypts stored keys (the data directory's key
// file, created on first use).
func (s *Server) secrets() (*secret.Box, error) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()
	if s.Secret == nil {
		b, err := secret.Open(s.Store.Repo().Dir)
		if err != nil {
			return nil, err
		}
		s.Secret = b
	}
	return s.Secret, nil
}

// tokenRowOf describes a stored token for a list.
func tokenRowOf(t db.TokenInfo, now time.Time) tokenRow {
	r := tokenRow{ID: t.ID, User: t.User, Name: t.Name, Kind: strings.ToUpper(t.Kind), Ending: "…" + t.Last4,
		Expires: "never", LastUsed: "never", Created: day(t.Created)}
	if t.Kind == db.TokenGit {
		r.Kind = "Git"
	}
	if r.Name == "" {
		r.Name = "—"
	}
	switch {
	case slices.Contains(t.Scopes, db.ScopeAll):
		r.Can = "all actions"
	case t.ReadOnly():
		r.Can = "read only"
	default:
		r.Can = strconv.Itoa(len(t.Scopes)) + " action"
		if len(t.Scopes) != 1 {
			r.Can += "s"
		}
	}
	r.Where = "all engagements"
	if t.Restricted() {
		r.Where = strings.Join(t.Engagements, ", ")
	}
	if t.Expires != "" {
		r.Expires = day(t.Expires)
		if exp, err := time.Parse(time.RFC3339, t.Expires); err == nil {
			switch {
			case !exp.After(now):
				r.ExpireSoon = "Expired"
			case exp.Sub(now) < notify.TokenSoon: // when its owner is told
				r.ExpireSoon = "Expires soon"
			}
		}
	}
	if t.LastUsed != "" {
		r.LastUsed = when(t.LastUsed)
	}
	return r
}

// settingsBase is the settings page's data for the request's user.
func (s *Server) settingsBase(r *http.Request) (*page, error) {
	p, err := s.base(r, "")
	if err != nil {
		return nil, err
	}
	p.Nav = "settings"
	u, d := p.User, s.Store.DB()
	now := time.Now()
	for _, t := range s.Tokens.ListFor(u.Username) {
		p.Settings.Tokens = append(p.Settings.Tokens, tokenRowOf(t, now))
	}
	conns, err := d.Connections(u.Username)
	if err != nil {
		return nil, err
	}
	// a row per service host of the destinations, then stored keys for no
	// destination (or for no host: never sent), which can only be removed
	keys := s.connKeys()
	for _, c := range conns {
		if !slices.Contains(keys, c.Service) {
			keys = append(keys, c.Service)
		}
	}
	for _, k := range keys {
		sv, host, _ := strings.Cut(k, "@")
		c := connRow{Service: k, Label: sv, Host: host}
		if i := slices.IndexFunc(connServices, func(o option) bool { return o.Value == sv }); i >= 0 {
			c.Label = connServices[i].Label
		}
		if c.Host == "" {
			c.Host = "—"
		}
		if i := slices.IndexFunc(conns, func(c db.Connection) bool { return c.Service == k }); i >= 0 {
			c.Has, c.Created = true, day(conns[i].Created)
			c.Ending, c.Broken = s.keyEnding(u.Username, k)
		}
		p.Settings.Conns = append(p.Settings.Conns, c)
	}
	prefs, err := d.NotifyChoices(u.Username, notify.Keys())
	if err != nil {
		return nil, err
	}
	p.Settings.Channels = s.channels()
	for _, ev := range notify.Events {
		row := notifyRow{Event: ev.Key, Label: ev.Label}
		for _, ch := range p.Settings.Channels {
			row.Cells = append(row.Cells, option{Value: ev.Key + "." + ch.Value, Label: ch.Label, On: slices.Contains(prefs[ev.Key], ch.Value)})
		}
		p.Settings.Notify = append(p.Settings.Notify, row)
	}
	for _, th := range []option{{Value: "light", Label: "Light"}, {Value: "dark", Label: "Dark"}, {Value: "system", Label: "System"}} {
		th.On = th.Value == u.Theme || (th.Value == "system" && u.Theme == "")
		p.Settings.Themes = append(p.Settings.Themes, th)
	}
	p.Settings.Keys = []option{{Value: "on", Label: "On", On: !u.KeysOff}, {Value: "off", Label: "Off", On: u.KeysOff}}
	return p, nil
}

// keyEnding decrypts a stored personal key to show its last characters;
// broken reports a key that can't be decrypted (another server's key file).
func (s *Server) keyEnding(user, service string) (string, bool) {
	enc, ok, err := s.Store.DB().Connection(user, service)
	if err != nil || !ok {
		return "", true
	}
	box, err := s.secrets()
	if err != nil {
		return "", true
	}
	plain, err := box.Decrypt(enc)
	if err != nil {
		return "", true
	}
	return ending(plain), false
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.settingsBase(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Settings.NewToken = s.flash.take(r, "token")
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "settings.html", p)
}

// settingsError shows the settings page again with a panel's error.
func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, set func(*settingsView)) {
	p, err := s.settingsBase(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	set(&p.Settings)
	s.renderStatus(w, http.StatusBadRequest, "settings.html", p)
}

func (s *Server) settingsAccount(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	email := strings.TrimSpace(r.FormValue("email"))
	if msg := emailProblem(email); msg != "" {
		s.settingsError(w, r, func(v *settingsView) { v.AccountErr = msg })
		return
	}
	if err := s.Store.DB().SetEmail(u.Username, email); errors.Is(err, db.ErrEmailTaken) {
		s.settingsError(w, r, func(v *settingsView) { v.AccountErr = "Email used by another account" })
		return
	} else if err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "user.email", u.Username, email)
	http.Redirect(w, r, "/settings#account", http.StatusSeeOther)
}

func (s *Server) settingsPassword(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	msg := ""
	if _, ok := s.Auth.Check(u.Username, r.FormValue("current")); !ok {
		msg = "Current password is wrong"
	} else {
		msg = passwordProblem(r.FormValue("new"), r.FormValue("repeat"))
	}
	if msg != "" {
		s.settingsError(w, r, func(v *settingsView) { v.PasswordErr = msg })
		return
	}
	hash, err := auth.HashPassword(r.FormValue("new"))
	if err != nil {
		s.fail(w, err)
		return
	}
	// every session of the account ends; this browser signs in again
	if err := s.Store.DB().ChangePassword(u.Username, hash); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "user.password", u.Username, "")
	if tok, ok := s.Auth.Login(u.Username, r.FormValue("new")); ok {
		s.Auth.SetCookie(w, tok)
	}
	http.Redirect(w, r, "/settings#password", http.StatusSeeOther)
}

// settingsPrefs saves the Preferences panel: the theme and the keyboard
// shortcuts (a form without one of them leaves it as it is). Both are
// checked before either is stored.
func (s *Server) settingsPrefs(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	t, setTheme := r.Form.Get("theme"), r.Form.Has("theme")
	if t == "system" {
		t = ""
	}
	if setTheme && !slices.Contains(db.Themes, t) {
		http.Error(w, "theme must be light, dark or system", http.StatusBadRequest)
		return
	}
	keys, setKeys := r.Form.Get("keys"), r.Form.Has("keys")
	if setKeys && keys != "on" && keys != "off" {
		http.Error(w, "keyboard shortcuts must be on or off", http.StatusBadRequest)
		return
	}
	if setTheme {
		if err := s.Store.DB().SetTheme(u.Username, t); err != nil {
			s.fail(w, err)
			return
		}
	}
	if setKeys {
		if err := s.Store.DB().SetKeysOff(u.Username, keys == "off"); err != nil {
			s.fail(w, err)
			return
		}
	}
	http.Redirect(w, r, "/settings#prefs", http.StatusSeeOther)
}

// tokenFormFor fills the New token form's choices: the actions, and the
// engagements the user can see (archived ones included).
func (s *Server) tokenFormFor(r *http.Request, p *page, f tokenForm, picked []string) error {
	var err error
	all, err := s.Index.Engagements()
	if err != nil {
		return err
	}
	vis, err := s.Store.Visible(p.User)
	if err != nil {
		return err
	}
	f.Actions = nil
	for _, a := range s.tokenActions() {
		f.Actions = append(f.Actions, option{Value: a, Label: tokenActionLabels[a], On: slices.Contains(picked, a)})
	}
	f.EngOpts = nil
	engs := r.Form["eng"]
	for _, e := range all {
		if vis != nil && !vis[e.ID] {
			continue
		}
		f.EngOpts = append(f.EngOpts, option{Value: e.ID, Label: e.Name, Muted: e.Archived, On: slices.Contains(engs, e.ID)})
	}
	f.MCPURL = gitBase(r) + "/mcp"
	f.GitURL = gitBase(r) + "/git/e/"
	p.Settings.Token = f
	return nil
}

func (s *Server) tokenNewPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "settings"
	r.ParseForm()
	if err := s.tokenFormFor(r, p, tokenForm{Kind: db.TokenMCP, Access: "read", Engs: "all", Expires: "90"}, nil); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "token_new.html", p)
}

// tokenCreate makes a scoped token for the user and shows its secret once.
func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "settings"
	r.ParseForm()
	f := tokenForm{Name: strings.TrimSpace(r.FormValue("name")), Kind: r.FormValue("kind"), Access: r.FormValue("access"),
		Engs: r.FormValue("engs"), Expires: r.FormValue("expires")}
	spec := db.TokenSpec{Name: f.Name, Kind: f.Kind}
	var picked []string
	for _, a := range s.tokenActions() { // in the list's order; a hidden one is not taken
		if slices.Contains(r.Form["action"], a) {
			picked = append(picked, a)
		}
	}
	vis, err := s.Store.Visible(p.User)
	if err != nil {
		s.fail(w, err)
		return
	}
	switch {
	case f.Name == "":
		f.Error = "Name is required"
	case len(f.Name) > 64:
		f.Error = "Name: at most 64 characters"
	case f.Kind != db.TokenMCP && f.Kind != db.TokenGit:
		f.Error = "Use for: MCP or Git"
	case f.Access == "read":
		spec.Scopes = []string{db.ScopeRead}
	case f.Access == "actions" && len(picked) > 0:
		spec.Scopes = picked
	default:
		f.Error = "Pick at least one action"
	}
	if f.Error == "" {
		switch f.Engs {
		case "all":
		case "selected":
			for _, e := range r.Form["eng"] {
				if _, ok := s.Index.Engagement(e); !ok || (vis != nil && !vis[e]) {
					f.Error = "Unknown engagement " + e
					break
				}
				if !slices.Contains(spec.Engagements, e) {
					spec.Engagements = append(spec.Engagements, e)
				}
			}
			if f.Error == "" && len(spec.Engagements) == 0 {
				f.Error = "Pick at least one engagement"
			}
		default:
			f.Error = "Engagements: all or selected"
		}
	}
	if f.Error == "" {
		switch f.Expires {
		case "never":
		case "30", "90", "365":
			n, _ := strconv.Atoi(f.Expires)
			spec.Expires = time.Now().Add(time.Duration(n) * 24 * time.Hour).UTC().Format(time.RFC3339)
		default:
			f.Error = "Expires: 30 days, 90 days, 1 year or never"
		}
	}
	if f.Error != "" {
		if err := s.tokenFormFor(r, p, f, picked); err != nil {
			s.fail(w, err)
			return
		}
		s.renderStatus(w, http.StatusBadRequest, "token_new.html", p)
		return
	}
	tok, _, err := s.Tokens.Create(p.User.Username, p.User.Username, spec)
	if err != nil {
		s.fail(w, err)
		return
	}
	// POST-redirect-GET: a reload doesn't make a second token; the list
	// shows the secret once
	s.flash.put(r, "token", tok)
	http.Redirect(w, r, "/settings#tokens", http.StatusSeeOther)
}

func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Tokens.RevokeID(u.Username, id, u.Username); err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/settings#tokens", http.StatusSeeOther)
}

// connKeys are the service hosts a personal key can be kept for: those of
// the destinations ("jira@firm.atlassian.net").
func (s *Server) connKeys() []string {
	es, _ := s.exporters()
	var keys []string
	for _, ex := range es {
		if k := ex.KeyName(); k != "" && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// connSave stores the user's personal key for a service host, encrypted.
func (s *Server) connSave(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	sv, key := r.FormValue("service"), strings.TrimSpace(r.FormValue("key"))
	if !slices.Contains(s.connKeys(), sv) || key == "" {
		s.settingsError(w, r, func(v *settingsView) { v.ConnErr = "Service and key are required" })
		return
	}
	box, err := s.secrets()
	if err != nil {
		s.fail(w, err)
		return
	}
	enc, err := box.Encrypt(key)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.DB().SetConnection(u.Username, sv, enc); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "connection.set", sv, ending(key))
	http.Redirect(w, r, "/settings#connections", http.StatusSeeOther)
}

func (s *Server) connRemove(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	sv := r.PathValue("service")
	if _, ok, err := s.Store.DB().Connection(u.Username, sv); err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DB().DeleteConnection(u.Username, sv); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "connection.remove", sv, "")
	http.Redirect(w, r, "/settings#connections", http.StatusSeeOther)
}

// notifySave replaces the user's notification choices with the ticked ones.
func (s *Server) notifySave(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	r.ParseForm()
	d := s.Store.DB()
	// only the channels on the page: a hidden email choice is kept
	var cs []db.NotifyChoice
	for _, ev := range notify.Events {
		for _, ch := range s.channels() {
			cs = append(cs, db.NotifyChoice{Event: ev.Key, Channel: ch.Value, On: slices.Contains(r.PostForm["n"], ev.Key+"."+ch.Value)})
		}
	}
	if err := d.SetNotifyChoices(u.Username, cs); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/settings#notifications", http.StatusSeeOther)
}
