package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/export"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// destCard is one button of the export page: a download or a destination.
type destCard struct {
	ID, Name, Sub string
	Disabled      bool
}

// pickRow is a finding in the export picker.
type pickRow struct {
	Dir, ID, Title, Status, Author, Keys string
	Shown                                string // the state the UI shows (workflow.Shown)
	On, Off                              bool   // ticked; not exportable (not complete or reported)
	OwnKey                               bool   // the author has a personal key
}

// sendItem is what became of one finding in a send (stored as JSON in the
// export history).
type sendItem struct {
	ID     string `json:"id"`
	Dir    string `json:"dir"`
	Author string `json:"author"`
	SentAs string `json:"sent_as"` // the author (own key), "server" or "" (a file)
	OK     bool   `json:"ok"`
	Marked bool   `json:"marked"`
	Error  string `json:"error,omitempty"`
	URL    string `json:"url,omitempty"`
	Action string `json:"action,omitempty"` // created | updated (a page or issue)
	// Retried: a failed finding sent again by a later send, never twice
	Retried bool `json:"retried,omitempty"`
}

// retryable: failed and not sent again since.
func (it sendItem) retryable() bool { return !it.OK && !it.Retried }

// sendResult is a send as the result panel shows it.
type sendResult struct {
	Dest, State        string // ok | partial | failed
	Items              []sendItem
	Sent, Total        int
	Marked             int
	Download, Filename string
	RetryURL           string
	ServerURL          string // sends a failed finding again with the server's key ("" without one)
	Renew              string // where the viewer renews their key for the service
	Viewer             string
}

// historyRow is a line of the History table.
type historyRow struct {
	When, By, Dest, SentAs, State, URL, Error, RetryURL string
	N                                                   int
}

type tocLink struct {
	Anchor, ID, Title string
}

type exportView struct {
	Enabled    bool // exporting is set up on this server
	CanSend    bool // destinations take sends (not archived)
	CanSetup   bool // a director: the Destinations editor
	Dests      []destCard
	Downloads  []destCard
	LoadErrors []string
	Picks      []pickRow
	Pickable   int
	Ticked     int // of those, ticked (the head's "N of M"; app.js keeps it current)
	Result     *sendResult
	History    []historyRow
	Report     template.HTML // preview: the report
	Toc        []tocLink     // preview: the findings
	Picked     []string      // preview: the findings' folders
	Setup      destSetup     // the destinations editor
	exporters  []export.Exporter
}

// downloads are the built-in files; pandoc ones need pandoc on the server.
var downloads = []struct {
	ID, Name, Sub string
	Pandoc        bool
}{
	{"pdf", "PDF report", "pandoc · xelatex", true},
	{"docx", "Word report", "pandoc · docx", true},
	{"zip", "Confluence import", "ZIP · HTML + images", false},
	{"full", "Full export", "ZIP · findings + git", false},
}

// exportable statuses: only finished findings leave YARS.
var exportable = []string{"complete", "reported"}

// exportKeep is how long a finished file waits for its download.
const exportKeep = 10 * time.Minute

// exportUserMax is how many bytes of finished files one user may have
// waiting (one file is at most 100 MiB, export's own limit).
const exportUserMax = 256 << 20

// exportSweepEvery is how often expired files are dropped.
const exportSweepEvery = time.Minute

// exportCache keeps finished files for exportKeep so the result page can
// offer the download. Only the exporting user may fetch a file, and only
// under the engagement it was made in. A user's files are capped in bytes
// (the oldest go first), and expired ones are dropped by sweep, which the
// server runs on a timer.
type exportCache struct {
	mu    sync.Mutex
	items map[string]cachedExport
	seq   uint64           // counts puts: the order of a user's files
	now   func() time.Time // tests; nil = time.Now
	max   int64            // tests; 0 = exportUserMax
}

type cachedExport struct {
	user, eng string
	res       export.Result
	exp       time.Time
	seq       uint64
}

func (c *exportCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// sweepLocked drops the expired files; the caller holds the lock.
func (c *exportCache) sweepLocked() {
	now := c.clock()
	for k, v := range c.items {
		if now.After(v.exp) {
			delete(c.items, k)
		}
	}
}

// sweep drops the expired files.
func (c *exportCache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked()
}

// put keeps res for user under eng and returns its token. When the user's
// files are over the cap, their oldest are dropped; the new one always
// stays, since its send has happened.
func (c *exportCache) put(user, eng string, res export.Result) string {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]cachedExport{}
	}
	c.sweepLocked()
	c.seq++
	c.items[tok] = cachedExport{user, eng, res, c.clock().Add(exportKeep), c.seq}
	max := c.max
	if max <= 0 {
		max = exportUserMax
	}
	for {
		var total int64
		oldest := tok
		for k, v := range c.items {
			if v.user != user {
				continue
			}
			total += int64(len(v.res.Data))
			if v.seq < c.items[oldest].seq {
				oldest = k
			}
		}
		if total <= max || oldest == tok {
			return tok
		}
		delete(c.items, oldest)
	}
}

// get is the file tok names, for the user who made it and under the
// engagement it was made in; anything else (another user, another
// engagement, expired, unknown) is not found, all alike.
func (c *exportCache) get(user, eng, tok string) (export.Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[tok]
	if !ok || it.user != user || it.eng != eng || c.clock().After(it.exp) {
		return export.Result{}, false
	}
	return it.res, true
}

// len is the number of files kept, expired ones not yet swept included.
func (c *exportCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// bytes is how much user's files hold.
func (c *exportCache) bytes(user string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int64
	for _, v := range c.items {
		if v.user == user {
			n += int64(len(v.res.Data))
		}
	}
	return n
}

// keepExport caches a finished file for its download and starts the sweep
// worker with the first one (once; it ends on Close and holds only the
// cache while it waits).
func (s *Server) keepExport(user, eng string, res export.Result) string {
	s.sweepOnce.Do(func() {
		stop, c := s.stop, &s.exports
		go func() {
			t := time.NewTicker(exportSweepEvery)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
					c.sweep()
				}
			}
		}()
	})
	return s.exports.put(user, eng, res)
}

func (s *Server) routesExport(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/export", s.exportForm)
	mux.HandleFunc("POST /e/{eng}/export", s.exportRun)
	mux.HandleFunc("GET /e/{eng}/export/download/{tok}", s.exportDownload)
	mux.HandleFunc("GET /e/{eng}/export/preview", s.exportPreview)
	mux.HandleFunc("POST /e/{eng}/export/history/{id}/retry", s.exportRetry)
	mux.HandleFunc("POST /e/{eng}/export/history/{id}/server", s.exportServerKey)
	s.routesExportSetup(mux)
}

func (s *Server) exportDownload(w http.ResponseWriter, r *http.Request) {
	res, ok := s.exports.get(auth.UserFrom(r.Context()).Username, r.PathValue("eng"), r.PathValue("tok"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	sendFile(w, res)
}

func sendFile(w http.ResponseWriter, res export.Result) {
	w.Header().Set("Content-Type", res.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, strings.ReplaceAll(res.Filename, `"`, "")))
	w.Header().Set("Cache-Control", "no-store")
	// opened in the browser (an HTML file), it runs nothing as YARS
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self'")
	w.Write(res.Data)
}

// destSub is a destination's second line: where it goes, and whether it
// marks what it gets reported.
func destSub(ex export.Exporter) string {
	var parts []string
	switch ex.Type {
	case "jira":
		parts = append(parts, ex.Host(), ex.Jira.Project)
	case "confluence":
		if ex.Service() {
			parts = append(parts, ex.Host(), ex.Confluence.Space)
		} else {
			parts = append(parts, "confluence", "html")
		}
	case "pandoc":
		parts = append(parts, "pandoc", ex.Format)
	case "script":
		parts = append(parts, "script", ex.Extension)
	}
	if ex.Marks() {
		parts = append(parts, "marks reported")
	}
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), " · ")
}

// exporters loads the destinations (nil when exporting is off).
func (s *Server) exporters() ([]export.Exporter, []string) {
	if s.Export == nil {
		return nil, nil
	}
	es, errs := export.Load(s.Export.Dir)
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	return es, msgs
}

func findExporter(es []export.Exporter, id string) (export.Exporter, bool) {
	i := slices.IndexFunc(es, func(e export.Exporter) bool { return e.ID == id })
	if i < 0 {
		return export.Exporter{}, false
	}
	return es[i], true
}

// destName is how the history names a destination or download.
func destName(es []export.Exporter, id string) string {
	if dl, ok := strings.CutPrefix(id, "download:"); ok {
		for _, d := range downloads {
			if d.ID == dl {
				return d.Name
			}
		}
		return dl
	}
	if ex, ok := findExporter(es, id); ok {
		return ex.Name
	}
	return id
}

// exportPage is the export page's data; form, when not nil, is what the
// user had ticked.
func (s *Server) exportPage(r *http.Request, form url.Values) (*page, error) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		return nil, err
	}
	rows, err := s.Index.Rows(index.Query{EngID: p.Eng.ID, Sort: "severity"})
	if err != nil {
		return nil, err
	}
	v := &p.ExportV
	v.Enabled = s.Export != nil
	v.CanSend = v.Enabled && !p.Eng.Archived
	v.CanSetup = v.Enabled && p.CanManage
	v.exporters, v.LoadErrors = s.exporters()
	noPandoc := s.Export == nil || s.Export.PandocPath == ""
	for _, d := range downloads {
		v.Downloads = append(v.Downloads, destCard{ID: d.ID, Name: d.Name, Sub: d.Sub, Disabled: d.Pandoc && noPandoc})
	}
	for _, ex := range v.exporters {
		v.Dests = append(v.Dests, destCard{ID: ex.ID, Name: ex.Name, Sub: destSub(ex), Disabled: !v.CanSend})
	}
	keys := map[string][]string{}
	d := s.Store.DB()
	for _, row := range rows {
		if !workflow.Active(row.Status) {
			continue // withdrawn findings never leave
		}
		pr := pickRow{Dir: row.Dir, ID: row.ID, Title: row.Title, Status: row.Status, Shown: row.Shown, Author: row.Author}
		pr.Off = !slices.Contains(exportable, row.Status)
		if form != nil {
			pr.On = !pr.Off && checkedIn(form, "finding", row.Dir)
		} else {
			// by default what the viewer may send: a colleague's finding
			// would refuse the whole send
			pr.On = row.Status == "complete" && workflow.CanReport(p.User, finding.Meta{Author: row.Author})
		}
		if !pr.Off {
			v.Pickable++
		}
		if pr.On {
			v.Ticked++
		}
		svcs, ok := keys[row.Author]
		if !ok && d != nil && row.Author != "" {
			conns, _ := d.Connections(row.Author)
			for _, c := range conns {
				if strings.Contains(c.Service, "@") { // keys bound to no host are never sent
					svcs = append(svcs, c.Service)
				}
			}
			keys[row.Author] = svcs
		}
		pr.OwnKey = len(svcs) > 0
		pr.Keys = "server key"
		if pr.OwnKey {
			pr.Keys = "own key · " + strings.Join(svcs, ", ")
		}
		v.Picks = append(v.Picks, pr)
	}
	if d != nil {
		recs, err := d.Exports(p.Eng.ID, 20)
		if err != nil {
			return nil, err
		}
		for _, rec := range recs {
			v.History = append(v.History, s.historyRowOf(p, rec))
		}
	}
	return p, nil
}

func itemsOf(rec db.ExportRecord) []sendItem {
	var items []sendItem
	json.Unmarshal([]byte(rec.Findings), &items)
	return items
}

func stateOf(rec db.ExportRecord, items []sendItem) string {
	if rec.OK {
		return "ok"
	}
	if slices.ContainsFunc(items, func(it sendItem) bool { return it.OK }) {
		return "partial"
	}
	return "failed"
}

// retryURL is where a failed send is sent again ("" when it can't be).
func (s *Server) retryURL(p *page, rec db.ExportRecord) string {
	if rec.OK || strings.HasPrefix(rec.Destination, "download:") || !p.ExportV.CanSend || !slices.ContainsFunc(itemsOf(rec), sendItem.retryable) {
		return ""
	}
	if _, ok := findExporter(p.ExportV.exporters, rec.Destination); !ok {
		return ""
	}
	return "/e/" + p.Eng.ID + "/export/history/" + strconv.FormatInt(rec.ID, 10) + "/retry"
}

func (s *Server) historyRowOf(p *page, rec db.ExportRecord) historyRow {
	items := itemsOf(rec)
	h := historyRow{When: when(rec.TS), By: rec.By, Dest: destName(p.ExportV.exporters, rec.Destination), N: len(items),
		SentAs: rec.SentAs, State: stateOf(rec, items), URL: rec.URL, Error: rec.Error, RetryURL: s.retryURL(p, rec)}
	if h.SentAs == "" {
		h.SentAs = "—"
	}
	return h
}

func (s *Server) exportForm(w http.ResponseWriter, r *http.Request) {
	var picked url.Values // back from the preview: what was picked there
	if q := r.URL.Query(); q.Has("finding") {
		picked = q
	}
	p, err := s.exportPage(r, picked)
	if err != nil {
		s.fail(w, err)
		return
	}
	// the result of a send: ?sent=<history id>[&dl=<file token>]
	if id, err := strconv.ParseInt(r.URL.Query().Get("sent"), 10, 64); err == nil {
		if rec, ok, _ := s.Store.DB().Export(id); ok && rec.Eng == p.Eng.ID {
			items := itemsOf(rec)
			res := &sendResult{Dest: destName(p.ExportV.exporters, rec.Destination), State: stateOf(rec, items), Items: items,
				Total: len(items), RetryURL: s.retryURL(p, rec), Viewer: p.User.Username}
			if ex, ok := findExporter(p.ExportV.exporters, rec.Destination); ok && ex.Service() && !rec.OK {
				res.Renew = "/settings#conn-" + ex.KeyName()
				if p.ExportV.CanSend && s.Export.Getenv(ex.TokenEnv()) != "" {
					res.ServerURL = "/e/" + p.Eng.ID + "/export/history/" + strconv.FormatInt(rec.ID, 10) + "/server"
				}
			}
			for _, it := range items {
				if it.OK {
					res.Sent++
				}
				if it.Marked {
					res.Marked++
				}
			}
			if tok := r.URL.Query().Get("dl"); tok != "" {
				if f, ok := s.exports.get(p.User.Username, p.Eng.ID, tok); ok {
					res.Download, res.Filename = "/e/"+p.Eng.ID+"/export/download/"+tok, f.Filename
				}
			}
			p.ExportV.Result = res
		}
	}
	s.render(w, "export.html", p)
}

// picked loads the chosen findings; each must be complete or reported
// (and in the destination's statuses, when given).
func (s *Server) picked(eng string, dirs []string, statuses []string) ([]store.FindingRef, string) {
	if len(dirs) == 0 {
		return nil, "select at least one finding"
	}
	var refs []store.FindingRef
	for _, d := range dirs {
		ref, err := s.Store.Finding(eng, d)
		if err != nil {
			return nil, "unknown finding " + d
		}
		st := ref.F.Meta.Status
		if !slices.Contains(exportable, st) || (statuses != nil && !slices.Contains(statuses, st)) {
			return nil, ref.F.Meta.ID + " is " + st
		}
		if !slices.ContainsFunc(refs, func(r store.FindingRef) bool { return r.Dir == ref.Dir }) { // named twice: once
			refs = append(refs, ref)
		}
	}
	return refs, ""
}

// maySend refuses a send to a destination when one of refs is not u's to
// send: only a finding's author or a director sends it (and so marks it
// reported). One such finding refuses the whole send, before any key is read
// and anything leaves. Downloads and the preview are the team's.
func maySend(u config.User, refs []store.FindingRef) string {
	for _, ref := range refs {
		if !workflow.CanReport(u, ref.F.Meta) {
			return ref.F.Meta.ID + ": only the author or a director can send a finding"
		}
	}
	return ""
}

// reportTexts reads the engagement's report-level sections (Report tab).
func reportTexts(st *store.Store, eng string, names []string) []export.ReportText {
	var out []export.ReportText
	for _, n := range names {
		body, err := st.ReportSection(eng, n)
		if err != nil {
			// the section's name is the team's text: the engagement says where
			st.Log().Error("export: a report section is not read", "eng", eng, "err", err)
			continue
		}
		out = append(out, export.ReportText{Name: n, Body: body})
	}
	return out
}

// exportInput is the report input for refs, reading their attachments.
func (s *Server) exportInput(eng store.Engagement, refs []store.FindingRef) export.Input {
	in := export.Input{Engagement: eng, Cfg: s.conf()}
	in.Report = reportTexts(s.Store, eng.ID, in.Cfg.ReportSections)
	dirOf := map[*finding.Finding]string{}
	for _, ref := range refs {
		in.Findings = append(in.Findings, ref.F)
		dirOf[ref.F] = ref.Dir
	}
	in.Attachment = func(f *finding.Finding, rel string) ([]byte, bool) {
		b, err := s.Store.ReadAttachment(eng.ID, dirOf[f], rel)
		return b, err == nil
	}
	return in
}

// liftDeadline lets an export outlive the server's write timeout.
func (s *Server) liftDeadline(w http.ResponseWriter) {
	limit := 120 * time.Second // export.Runner's default
	if s.Export != nil && s.Export.Timeout > 0 {
		limit = s.Export.Timeout
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(limit + 30*time.Second))
}

func (s *Server) exportRun(w http.ResponseWriter, r *http.Request) {
	s.liftDeadline(w)
	r.ParseForm()
	p, err := s.exportPage(r, r.PostForm)
	if err != nil {
		s.fail(w, err)
		return
	}
	fail := func(status int, msg string) {
		p.Error = msg
		s.renderStatus(w, status, "export.html", p)
	}
	if dl := r.PostForm.Get("download"); dl != "" {
		i := slices.IndexFunc(p.ExportV.Downloads, func(d destCard) bool { return d.ID == dl })
		if i < 0 || p.ExportV.Downloads[i].Disabled {
			fail(http.StatusBadRequest, "unknown download "+dl)
			return
		}
		refs, msg := s.picked(p.Eng.ID, r.PostForm["finding"], nil)
		if msg != "" {
			fail(http.StatusBadRequest, msg)
			return
		}
		began := time.Now()
		res, err := s.download(r.Context(), dl, p.Eng, refs)
		s.record(p.User, p.Eng.ID, "download:"+dl, refs, err, nil, began)
		if err != nil {
			fail(http.StatusInternalServerError, "export failed: "+err.Error())
			return
		}
		sendFile(w, res)
		return
	}
	ex, ok := findExporter(p.ExportV.exporters, r.PostForm.Get("dest"))
	if !ok {
		fail(http.StatusBadRequest, "choose a destination")
		return
	}
	if !p.ExportV.CanSend {
		fail(http.StatusForbidden, store.ErrArchived.Error())
		return
	}
	refs, msg := s.picked(p.Eng.ID, r.PostForm["finding"], ex.Statuses)
	if msg != "" {
		fail(http.StatusBadRequest, msg)
		return
	}
	if msg := maySend(p.User, refs); msg != "" {
		fail(http.StatusForbidden, msg)
		return
	}
	s.sendAndShow(w, r, p, ex, refs, false)
}

// download makes one of the built-in files.
func (s *Server) download(ctx context.Context, id string, eng store.Engagement, refs []store.FindingRef) (export.Result, error) {
	in := s.exportInput(eng, refs)
	switch id {
	case "pdf", "docx":
		if s.Export == nil {
			return export.Result{}, errors.New("exporting is not set up on this server")
		}
		ex := export.Exporter{ID: id, Name: id, Type: "pandoc", Format: id}
		if id == "docx" {
			ex.Args = []string{"--toc"}
		}
		return s.Export.Run(ctx, ex, in)
	case "zip", "full":
		if s.Export != nil { // the ZIPs count among the exports running at once
			release, err := s.Export.Slot(ctx)
			if err != nil {
				return export.Result{}, err
			}
			defer release()
		}
		if id == "zip" {
			return export.HTMLZip(in)
		}
		repo, err := s.Store.EngRepo(eng.ID)
		if err != nil {
			return export.Result{}, err
		}
		return export.FullZip(in, repo.Dir)
	}
	return export.Result{}, fmt.Errorf("unknown download %q", id)
}

// senderKey is the author's own key for service (a destination's KeyName:
// the service at one host) when they keep one ("user:token", or a token
// used with their e-mail or name), otherwise nil: the server's key. sentAs
// names whose key it is.
func (s *Server) senderKey(author, service string) (creds *export.Creds, sentAs string) {
	d := s.Store.DB()
	if d == nil || author == "" || !strings.Contains(service, "@") {
		return nil, "server"
	}
	enc, ok, err := d.Connection(author, service)
	if err != nil || !ok {
		return nil, "server"
	}
	box, err := s.secrets()
	if err != nil {
		return nil, "server"
	}
	key, err := box.Decrypt(enc)
	if err != nil || key == "" {
		s.log().Warn("export: a personal key can't be read; sending as the server", "user", author)
		return nil, "server"
	}
	if user, tok, found := strings.Cut(key, ":"); found && user != "" && tok != "" {
		return &export.Creds{User: user, Token: tok}, author
	}
	login := author
	if u, ok, _ := d.User(author); ok && u.Email != "" {
		login = u.Email
	}
	return &export.Creds{User: login, Token: key}, author
}

// send delivers refs to a destination: a service gets each finding with
// its author's key (the server's with serverKey), updating the page or
// issue it became before; a file destination makes one file. Findings that
// arrived are marked reported when the destination says so. It returns the
// history id and the file's download token ("" for none).
func (s *Server) send(ctx context.Context, u config.User, eng store.Engagement, ex export.Exporter, refs []store.FindingRef, serverKey bool) (int64, string) {
	began := time.Now()
	items := make([]sendItem, len(refs))
	for i, ref := range refs {
		items[i] = sendItem{ID: ref.F.Meta.ID, Dir: ref.Dir, Author: ref.F.Meta.Author}
	}
	tok := ""
	d := s.Store.DB()
	if ex.Service() {
		for i, ref := range refs {
			fid := ref.F.Meta.ID
			in := s.exportInput(eng, refs[i:i+1])
			if serverKey {
				items[i].SentAs = "server"
			} else {
				in.Creds, items[i].SentAs = s.senderKey(ref.F.Meta.Author, ex.KeyName())
			}
			if d != nil {
				if rm, ok, err := d.ExportRemote(ex.ID, eng.ID, fid); err == nil && ok && rm.Target == ex.Target() {
					in.Known = map[string]export.Remote{fid: {ID: rm.RemoteID, Version: rm.Version}}
				}
			}
			res, err := s.Export.Run(ctx, ex, in)
			if err != nil {
				items[i].Error = err.Error()
			} else {
				items[i].OK, items[i].URL = true, res.URL
			}
			// also the page a failed send made: the next send fills it
			if len(res.Items) == 1 && res.Items[0].Remote.ID != "" {
				it := res.Items[0]
				if err == nil {
					items[i].Action = it.Action
				}
				if d != nil {
					rm := db.ExportRemote{Destination: ex.ID, Eng: eng.ID, Finding: fid, Target: ex.Target(), RemoteID: it.Remote.ID, Version: it.Remote.Version, URL: it.URL}
					if err := d.SetExportRemote(rm); err != nil {
						s.log().Error("export: the page or issue a finding became is not remembered", "eng", eng.ID, "finding", fid, "destination", ex.ID, "err", err)
					}
				}
			}
		}
	} else {
		res, err := s.Export.Run(ctx, ex, s.exportInput(eng, refs))
		for i := range items {
			if err != nil {
				items[i].Error = err.Error()
			} else {
				items[i].OK = true
			}
		}
		if err == nil {
			tok = s.keepExport(u.Username, eng.ID, res)
		}
	}
	if ex.Marks() {
		for i, ref := range refs {
			if !items[i].OK || ref.F.Meta.Status != "complete" {
				continue
			}
			if err := s.Store.MarkExported(eng.ID, ref.Dir, ex.Name, u); err != nil {
				s.log().Error("export: a finding is not marked reported", "eng", eng.ID, "finding", ref.F.Meta.ID, "user", u.Username, "err", err)
				continue
			}
			items[i].Marked = true
		}
	}
	return s.record(u, eng.ID, ex.ID, refs, nil, items, began), tok
}

// record writes the export history, the audit line and the export's line in
// the service log (it began at began). items nil: a download, whose findings
// all share err.
func (s *Server) record(u config.User, eng, dest string, refs []store.FindingRef, err error, items []sendItem, began time.Time) int64 {
	if items == nil {
		for _, ref := range refs {
			it := sendItem{ID: ref.F.Meta.ID, Dir: ref.Dir, Author: ref.F.Meta.Author, OK: err == nil}
			if err != nil {
				it.Error = err.Error()
			}
			items = append(items, it)
		}
	}
	// the log's line: counts, the destination's ID and the time. Never the
	// destination's name or why a finding failed (the destination's own
	// words: a page's title, the remote's answer); the history has those
	sent := 0
	for _, it := range items {
		if it.OK {
			sent++
		}
	}
	level := slog.LevelInfo
	if sent < len(items) {
		level = slog.LevelWarn
	}
	s.log().Log(context.Background(), level, "export finished", "eng", eng, "user", u.Username, "destination", dest,
		"findings", len(items), "sent", sent, "failed", len(items)-sent, "ms", time.Since(began).Milliseconds())
	d := s.Store.DB()
	if d == nil {
		return 0
	}
	rec := db.ExportRecord{By: u.Username, Eng: eng, Destination: dest, OK: true}
	var sentAs []string
	for _, it := range items {
		if !it.OK {
			rec.OK = false
			if rec.Error == "" {
				rec.Error = it.Error
			}
		}
		if rec.URL == "" {
			rec.URL = it.URL
		}
		if it.SentAs != "" && !slices.Contains(sentAs, it.SentAs) {
			sentAs = append(sentAs, it.SentAs)
		}
	}
	rec.SentAs = strings.Join(sentAs, ", ")
	b, _ := json.Marshal(items)
	rec.Findings = string(b)
	id, derr := d.AddExport(rec)
	if derr != nil {
		s.log().Error("export: the history entry is not written", "eng", eng, "user", u.Username, "err", derr)
	}
	d.Audit(u.Username, "export", eng, fmt.Sprintf("%s, %d findings", strings.TrimPrefix(dest, "download:"), len(refs)))
	if !strings.HasPrefix(dest, "download:") { // sent to a destination
		ev := store.Event{Kind: store.EventExport, Actor: u.Username, Eng: eng, Destination: dest, OK: rec.OK, Error: rec.Error, URL: rec.URL}
		for _, it := range items {
			ev.Findings = append(ev.Findings, it.ID)
		}
		s.Store.Emit(ev)
	}
	return id
}

// sendAndShow sends and shows the result page (a redirect, so reloading
// it never sends again).
func (s *Server) sendAndShow(w http.ResponseWriter, r *http.Request, p *page, ex export.Exporter, refs []store.FindingRef, serverKey bool) {
	id, tok := s.send(r.Context(), p.User, p.Eng, ex, refs, serverKey)
	to := "/e/" + p.Eng.ID + "/export?sent=" + strconv.FormatInt(id, 10)
	if tok != "" {
		to += "&dl=" + tok
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// exportRetry sends a failed send's failed findings again.
func (s *Server) exportRetry(w http.ResponseWriter, r *http.Request) { s.resend(w, r, false) }

// exportServerKey sends one failed finding of a send again with the
// server's key (form value dir).
func (s *Server) exportServerKey(w http.ResponseWriter, r *http.Request) { s.resend(w, r, true) }

func (s *Server) resend(w http.ResponseWriter, r *http.Request, serverKey bool) {
	s.liftDeadline(w)
	r.ParseForm()
	p, err := s.exportPage(r, nil)
	if err != nil {
		s.fail(w, err)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rec, ok, err := s.Store.DB().Export(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok || rec.Eng != p.Eng.ID {
		http.NotFound(w, r)
		return
	}
	fail := func(status int, msg string) {
		p.Error = msg
		s.renderStatus(w, status, "export.html", p)
	}
	ex, found := findExporter(p.ExportV.exporters, rec.Destination)
	switch {
	case rec.OK || !found || (serverKey && !ex.Service()):
		fail(http.StatusBadRequest, "nothing to retry")
		return
	case !p.ExportV.CanSend:
		fail(http.StatusForbidden, store.ErrArchived.Error())
		return
	}
	var dirs []string
	items := itemsOf(rec)
	for i, it := range items {
		if it.retryable() && (!serverKey || it.Dir == r.PostForm.Get("dir")) {
			dirs = append(dirs, it.Dir)
			items[i].Retried = true
		}
	}
	if len(dirs) == 0 {
		fail(http.StatusBadRequest, "nothing to retry")
		return
	}
	refs, msg := s.picked(p.Eng.ID, dirs, ex.Statuses)
	if msg != "" {
		fail(http.StatusBadRequest, msg)
		return
	}
	// before the claim: a refused sender leaves the retry to the author
	if msg := maySend(p.User, refs); msg != "" {
		fail(http.StatusForbidden, msg)
		return
	}
	// claim them first: a second click or another user finds them retried
	b, _ := json.Marshal(items)
	if ok, err := s.Store.DB().SwapExportFindings(rec.ID, rec.Findings, string(b)); err != nil {
		s.fail(w, err)
		return
	} else if !ok {
		fail(http.StatusConflict, "already retried")
		return
	}
	s.sendAndShow(w, r, p, ex, refs, serverKey)
}

// exportPreview shows the report of the chosen findings as it will be
// sent or downloaded.
func (s *Server) exportPreview(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p, err := s.exportPage(r, q)
	if err != nil {
		s.fail(w, err)
		return
	}
	refs, msg := s.picked(p.Eng.ID, q["finding"], nil)
	if msg != "" {
		p.Error = msg
		s.renderStatus(w, http.StatusBadRequest, "export.html", p)
		return
	}
	in := s.exportInput(p.Eng, refs)
	in.Preview = true                                   // the web's own tables: a header row on each
	p.ExportV.Report = template.HTML(export.Report(in)) // every value escaped, Markdown without raw HTML
	for _, ref := range refs {
		p.ExportV.Picked = append(p.ExportV.Picked, ref.Dir)
	}
	// contents in the report's own order
	for _, f := range in.Ordered() {
		p.ExportV.Toc = append(p.ExportV.Toc, tocLink{Anchor: "rp-" + f.Meta.ID, ID: f.Meta.ID, Title: f.Meta.Title})
	}
	s.render(w, "export_preview.html", p)
}
