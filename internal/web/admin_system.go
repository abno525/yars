package web

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"yars/internal/auth"
	"yars/internal/backup"
	"yars/internal/db"
	"yars/internal/rules"
)

// systemAdmin is Admin › System: the health checks, the backup download,
// the CLI operations as buttons with the last one's result, and the
// server's counts and sizes.
type systemAdmin struct {
	Users, Engagements, Archived, Findings, Messages int
	DBSize, IndexBuild, DataDir, Started, Uptime     string
	Version                                          string // the running build's ("—" when unknown)
	Schema                                           int
	Op, OpResult                                     string   // the operation run and what came of it
	OpOK                                             bool     // … it worked
	OpItems                                          []string // Migrate status: what still needs migrating
	LastBackup, BackupBy, BackupKey, BackupSize      string   // the last backup download ("—" when none)
	GitClone                                         string   // the main repo's clone path ("—" without the git server)
	Health                                           healthAdmin
	// Retention (D24): the settings, the last prune ("—" when none) and a
	// refused save's reason
	Retention                 db.Retention
	LastPrune, RetentionError string
	RetentionBad              string      // the refused field, which takes the focus
	AIUsage                   aiUsageView // D24
	// Restore (D24): a refused upload's reason, a restore just made (shown
	// once) and the last one ("—" when none)
	RestoreError                       string
	Restored                           *restoreResult
	LastRestore, RestoreBy, RestoreDir string
}

// healthAdmin is the System page's Health panel: one row per check.
type healthAdmin struct {
	Rows             []healthRow
	Checked          string
	Errors, Warnings int
	at               time.Time // when the checks ran
}

// healthRow is one check: its state ("good", "warn", "bad", "off") and
// tag label, the result in a few words and the detail behind it.
type healthRow struct {
	Name, URL, State, Label, Result, Detail string
}

// healthResult is what a check found.
type healthResult struct{ State, Label, Result, Detail string }

func (s *Server) routesAdminSystem(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/system", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		s.systemPage(w, r, systemAdmin{})
	}))
	// a POST, so the cross-origin check covers it: a link elsewhere can't
	// make an admin's browser save a backup (with the key)
	mux.HandleFunc("POST /admin/system/backup", s.adminOnly(s.backup))
	mux.HandleFunc("POST /admin/system/check", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		// Run integrity: fsck reads every object of every repository, which
		// can outlast the server's write deadline (lifted for admins only)
		clearDeadlines(w)
		// its AI ping is a call made by this admin (AI usage)
		s.runHealth(rules.WithCaller(r.Context(), rules.Caller{User: auth.UserFrom(r.Context()).Username}), true)
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
	}))
	mux.HandleFunc("POST /admin/system/retention", s.adminOnly(s.retentionSave))
	mux.HandleFunc("POST /admin/system/restore", s.adminOnly(s.restoreUpload))
	mux.HandleFunc("POST /admin/system/sync", s.adminOnly(s.systemOp("sync")))
	mux.HandleFunc("POST /admin/system/reindex", s.adminOnly(s.systemOp("reindex")))
	mux.HandleFunc("POST /admin/system/migrate", s.adminOnly(s.systemOp("migrate")))
	// Health is part of the System page
	mux.HandleFunc("GET /admin/health", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
	}))
}

// dur shows a duration for people: ms or s when short, hours and minutes
// when long.
func dur(d time.Duration) string {
	switch {
	case d < time.Second:
		return strconv.FormatInt(max(d.Milliseconds(), 1), 10) + " ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %02d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
	default:
		return fmt.Sprintf("%d d %d h", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
	}
}

// size shows a byte count: B, KB, MB, GB.
func size(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1<<20:
		return strconv.FormatFloat(float64(n)/1024, 'f', 1, 64) + " KB"
	case n < 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	default:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	}
}

func (s *Server) systemPage(w http.ResponseWriter, r *http.Request, v systemAdmin) {
	s.systemPageStatus(w, r, http.StatusOK, v)
}

// systemPageStatus renders the System page with status (400 for a refused
// form, whose reason v carries).
func (s *Server) systemPageStatus(w http.ResponseWriter, r *http.Request, status int, v systemAdmin) {
	s.adminPage(w, r, "system", status, func(p *page) error {
		d := s.Store.DB()
		var err error
		if v.Users, err = d.UserCount(); err != nil {
			return err
		}
		engs, err := s.Index.Engagements()
		if err != nil {
			return err
		}
		v.Engagements = len(engs)
		for _, e := range engs {
			if e.Archived {
				v.Archived++
			}
		}
		v.Findings = s.Index.Findings()
		if v.Messages, err = d.ChatCount(); err != nil {
			return err
		}
		n, err := d.Size()
		if err != nil {
			return err
		}
		v.DBSize = size(n)
		v.IndexBuild = "—"
		if b := s.Index.LastBuild(); b > 0 {
			v.IndexBuild = dur(b)
		}
		v.Schema, _ = d.Version()
		v.DataDir = s.Store.Repo().Dir
		v.Started = s.started.Format("2006-01-02 15:04")
		v.Uptime = dur(time.Since(s.started))
		v.Version = cmp.Or(s.Version, "—")
		v.LastBackup, v.BackupBy, v.BackupKey, v.BackupSize = "—", "—", "—", "—"
		if l, _, err := d.AuditQuery(db.AuditFilter{Action: "backup", Limit: 1}); err == nil && len(l) == 1 {
			v.LastBackup, v.BackupBy = when(l[0].TS), l[0].Actor
			// "with key · 48.0 MB" (older entries have no size)
			v.BackupKey, v.BackupSize, _ = strings.Cut(l[0].Detail, " · ")
			if v.BackupSize == "" {
				v.BackupSize = "—"
			}
		}
		v.GitClone = "—"
		if s.Git != nil {
			v.GitClone = "/git/yars"
		}
		v.Health = s.lastHealthOr(r.Context())
		if err := s.retentionView(&v); err != nil {
			return err
		}
		if v.AIUsage, err = s.aiUsageFor(d); err != nil {
			return err
		}
		s.restoreView(r, &v)
		if js := s.flash.take(r, "sysop"); js != "" {
			var op sysOp
			if json.Unmarshal([]byte(js), &op) == nil {
				v.Op, v.OpResult, v.OpOK, v.OpItems = op.Op, op.Result, op.OK, op.Items
			}
		}
		p.Admin.System = v
		return nil
	})
}

// sysOp is an operation's result, carried to the page after the redirect.
type sysOp struct {
	Op, Result string
	OK         bool
	Items      []string
}

// systemOp runs one of the CLI operations, then redirects to the System
// page, which shows its result once (a reload doesn't run it again).
func (s *Server) systemOp(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := s.runOp(op)
		s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "system."+op, "", v.Result)
		if js, err := json.Marshal(v); err == nil {
			s.flash.put(r, "sysop", string(js))
		}
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
	}
}

// runOp runs one operation of the System page.
func (s *Server) runOp(op string) sysOp {
	v := sysOp{Op: op}
	switch op {
	case "sync":
		if err := s.Store.SyncPointers(); err != nil {
			v.Result = err.Error()
		} else {
			v.OK, v.Result = true, "Synced"
		}
	case "reindex":
		if d, err := s.Index.Rebuild(); err != nil {
			v.Result = err.Error()
		} else {
			v.OK, v.Result = true, "Rebuilt · "+dur(d)
		}
	case "migrate":
		if s.MigrateStatus != nil {
			v.Items = s.MigrateStatus()
		}
		ver, _ := s.Store.DB().Version()
		v.OK = len(v.Items) == 0
		v.Result = "Schema v" + strconv.Itoa(ver) + " · " + plural(len(v.Items), "item") + " to migrate"
	}
	return v
}

// backup streams a ZIP of the data directory (backup.Write): the main repo
// and every engagement repo, each copied under the store's lock of it, and a
// snapshot of the database at .yars/yars.db; the secret key only with key=1.
func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	withKey := r.PostFormValue("key") == "1"
	dir := s.Store.Repo().Dir
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	name := "yars-backup-" + time.Now().Format("2006-01-02-1504") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	n, err := backup.Write(w, dir, s.Store.DB(), s.Store, backup.Options{WithKey: withKey})
	if err != nil && n == 0 {
		// nothing sent yet (the snapshot failed): an error, not a download
		for _, h := range []string{"Content-Type", "Content-Disposition", "Cache-Control"} {
			w.Header().Del(h)
		}
		s.fail(w, err)
		return
	}
	if err != nil {
		// headers are gone: the download ends broken rather than silently short
		log.Printf("backup: %v", err)
		panic(http.ErrAbortHandler)
	}
	detail := "without key"
	if withKey {
		detail = "with key"
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "backup", "", detail+" · "+size(n))
}

// lastHealthOr is the last run of the health checks, which the System page
// shows without running them again; before any run it runs them, without
// the AI ping.
func (s *Server) lastHealthOr(ctx context.Context) healthAdmin {
	if h := s.lastHealth.Load(); h != nil {
		v := *h
		v.Checked = checkedAt(v.at)
		return v
	}
	return s.runHealth(ctx, false)
}

// runHealth runs the checks and keeps the result; full is Run integrity:
// it also asks the AI provider for a reply (a paid call), runs SQLite's
// full integrity check and fsck on every repository (slow, so only then).
func (s *Server) runHealth(ctx context.Context, full bool) healthAdmin {
	v := s.health(ctx, full)
	s.lastHealth.Store(&v)
	return v
}

// checkedAt shows when the checks ran: the time today, else the day.
func checkedAt(t time.Time) string {
	if y, m, d := t.Date(); y == time.Now().Year() && m == time.Now().Month() && d == time.Now().Day() {
		return t.Format("15:04")
	}
	return t.Format("02 Jan")
}

// health runs every check of the System page's Health panel (full: Run
// integrity, see runHealth).
func (s *Server) health(ctx context.Context, full bool) healthAdmin {
	s.healthRuns.Add(1)
	now := time.Now()
	v := healthAdmin{at: now, Checked: checkedAt(now)}
	check := func(name, url string, fn func() healthResult) {
		h := fn()
		if h.Detail == "" {
			h.Detail = "—"
		}
		v.Rows = append(v.Rows, healthRow{Name: name, URL: url, State: h.State, Label: h.Label, Result: h.Result, Detail: h.Detail})
		switch h.State {
		case "bad":
			v.Errors++
		case "warn":
			v.Warnings++
		}
	}
	check("Rules", "/admin/rules", s.healthRules)
	check("Destinations", "", s.healthDests)
	check("pandoc + PDF engine", "", s.healthPandoc)
	check("Git server repos", "", s.healthGit)
	check("AI provider", "/admin/ai", func() healthResult { return s.healthAI(ctx, full) })
	check("Disk free", "", s.healthDisk)
	check("Database integrity", "", func() healthResult { return s.healthDB(full) })
	check("Git repositories", "", func() healthResult { return s.healthFsck(full) })
	return v
}

// healthFsck runs git fsck on the main repository and every engagement's
// (Run integrity only: it reads every object): the first one that fails is
// named, with git's message.
func (s *Server) healthFsck(full bool) healthResult {
	if !full {
		return healthResult{State: "off", Label: "Not run", Result: "Not run"}
	}
	if err := s.Store.Repo().Fsck(); err != nil {
		return hBad("main", err.Error())
	}
	ids, err := s.Store.EngagementIDs()
	if err != nil {
		return hBad("unreadable", err.Error())
	}
	sort.Strings(ids)
	for _, id := range ids {
		r, err := s.Store.EngRepo(id)
		if err == nil {
			err = r.Fsck()
		}
		if err != nil {
			return hBad(id, err.Error())
		}
	}
	return hGood(plural(len(ids)+1, "repo"), "fsck")
}

func hBad(result, detail string) healthResult {
	return healthResult{State: "bad", Label: "Error", Result: result, Detail: detail}
}

func hGood(result, detail string) healthResult {
	return healthResult{State: "good", Label: "OK", Result: result, Detail: detail}
}

func (s *Server) healthGit() healthResult {
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return hBad("git missing", err.Error())
	}
	ver := strings.TrimSpace(string(out))
	ids, err := s.Store.EngagementIDs()
	if err != nil {
		return hBad("unreadable", err.Error())
	}
	broken := 0
	for _, id := range ids {
		if _, err := s.Store.EngHead(id); err != nil {
			broken++
		}
	}
	res := plural(len(ids)+1, "repo")
	if broken > 0 {
		return hBad(res+" · "+strconv.Itoa(broken)+" unreadable", ver)
	}
	return hGood(res, ver)
}

// healthDB checks the database: quick_check on a page load, the full
// integrity_check on Run integrity.
func (s *Server) healthDB(full bool) healthResult {
	d := s.Store.DB()
	check, name := d.Check, "quick_check"
	if full {
		check, name = d.Integrity, "integrity_check"
	}
	res, err := check()
	if err != nil {
		return hBad("check failed", err.Error())
	}
	n, _ := d.Size()
	ver, _ := d.Version()
	detail := name + " " + res + " · schema v" + strconv.Itoa(ver)
	if res != "ok" || ver != db.SchemaVersion {
		return hBad(size(n), detail)
	}
	return hGood(size(n), detail)
}

func (s *Server) healthDisk() healthResult {
	var st syscall.Statfs_t
	dir := s.Store.Repo().Dir
	if err := syscall.Statfs(dir, &st); err != nil {
		return hBad("unknown", err.Error())
	}
	free, total := int64(st.Bavail)*int64(st.Bsize), int64(st.Blocks)*int64(st.Bsize)
	res := size(free) + " of " + size(total)
	switch {
	case free < 1<<30:
		return hBad(res, dir)
	case total > 0 && free*10 < total:
		return healthResult{State: "warn", Label: "Warning", Result: res, Detail: dir}
	}
	return hGood(res, dir)
}

func (s *Server) healthAI(ctx context.Context, ping bool) healthResult {
	off := healthResult{State: "off", Label: "Off", Result: "Off"}
	rn := s.runner()
	if rn == nil {
		return off
	}
	c, key, fromEnv := rn.Effective()
	if c.Provider == "" {
		return off
	}
	res := c.Provider + " · " + c.Model
	if key == "" {
		return hBad(res, "no key")
	}
	src := "stored key"
	if fromEnv {
		src = c.APIKeyEnv
	}
	if !ping {
		return healthResult{State: "off", Label: "Not run", Result: res, Detail: src}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	took, err := rn.Ping(ctx)
	if err != nil {
		return healthResult{State: "warn", Label: "Warning", Result: res, Detail: err.Error()}
	}
	return hGood(res, src+" · reply in "+dur(took))
}

func (s *Server) healthRules() healthResult {
	if s.Rules == nil {
		return hOff
	}
	set := s.Rules.Rules()
	res := strconv.Itoa(len(set.Rules)) + " loaded"
	if n := len(set.Problems); n > 0 {
		return hBad(res+" · "+strconv.Itoa(n)+" invalid", fmt.Sprint(set.Problems[0]))
	}
	return hGood(res, "")
}

var hOff = healthResult{State: "off", Label: "Off", Result: "Off"}

func hWarn(result, detail string) healthResult {
	return healthResult{State: "warn", Label: "Warning", Result: result, Detail: detail}
}

// healthDests lists the export destinations (.yars/exporters); one that
// doesn't load is an error.
func (s *Server) healthDests() healthResult {
	if s.Export == nil {
		return hOff
	}
	es, errs := s.exporters()
	var names []string
	for _, e := range es {
		names = append(names, e.Name)
	}
	res := strings.Join(names, ", ")
	if res == "" {
		res = "None"
	}
	if len(errs) > 0 {
		return hBad(res+" · "+strconv.Itoa(len(errs))+" invalid", errs[0])
	}
	if len(es) == 0 {
		return healthResult{State: "off", Label: "Off", Result: res, Detail: ".yars/exporters"}
	}
	return hGood(res, plural(len(es), "destination"))
}

// firstLine is the first line of a command's output.
func firstLine(b []byte) string {
	l, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(l)
}

// healthPandoc checks pandoc (Word and PDF downloads) and xelatex, its PDF
// engine.
func (s *Server) healthPandoc() healthResult {
	if s.Export == nil {
		return hOff
	}
	if s.Export.PandocPath == "" {
		return hWarn("pandoc missing", "PDF and Word downloads off")
	}
	out, err := exec.Command(s.Export.PandocPath, "--version").Output()
	if err != nil {
		return hBad("pandoc fails", err.Error())
	}
	ver := firstLine(out)
	xe, err := exec.LookPath("xelatex")
	if err != nil {
		return hWarn(ver+" · no xelatex", "PDF downloads fail")
	}
	xo, err := exec.Command(xe, "--version").Output()
	if err != nil {
		return hWarn(ver+" · xelatex fails", err.Error())
	}
	return hGood(ver+" · xelatex", firstLine(xo))
}
