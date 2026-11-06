package web

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
)

// systemAdmin is Admin › System: the health checks, the backup download,
// the CLI operations as buttons with the last one's result, and the
// server's counts and sizes.
type systemAdmin struct {
	Users, Engagements, Archived, Findings, Messages int
	DBSize, IndexBuild, DataDir, Started, Uptime     string
	Schema                                           int
	Op, OpResult                                     string   // the operation run and what came of it
	OpOK                                             bool     // … it worked
	OpItems                                          []string // Migrate status: what still needs migrating
	LastBackup, BackupBy, BackupKey                  string   // the last backup download ("—" when none)
	Health                                           healthAdmin
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
		s.runHealth(r.Context(), true)
		http.Redirect(w, r, "/admin/system", http.StatusSeeOther)
	}))
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
	s.adminPage(w, r, "system", http.StatusOK, func(p *page) error {
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
		v.LastBackup, v.BackupBy, v.BackupKey = "—", "—", "—"
		if l, _, err := d.AuditQuery(db.AuditFilter{Action: "backup", Limit: 1}); err == nil && len(l) == 1 {
			v.LastBackup, v.BackupBy, v.BackupKey = when(l[0].TS), l[0].Actor, l[0].Detail
		}
		v.Health = s.lastHealthOr(r.Context())
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

// backupSkip reports files of the data directory a backup leaves out: the
// live database (a snapshot goes in instead) and, unless asked for, the
// secret key.
func backupSkip(rel string, withKey bool) bool {
	switch rel {
	case ".yars/yars.db", ".yars/yars.db-wal", ".yars/yars.db-shm", ".yars/yars.db-journal":
		return true
	case ".yars/secret.key":
		return !withKey
	}
	return false
}

// backup streams a ZIP of the data directory: the main repo and every
// engagement repo (their .git folders included) and a snapshot of the
// database (VACUUM INTO) at .yars/yars.db; the secret key only with key=1.
func (s *Server) backup(w http.ResponseWriter, r *http.Request) {
	withKey := r.PostFormValue("key") == "1"
	dir := s.Store.Repo().Dir
	tmp, err := os.MkdirTemp("", "yars-backup-")
	if err != nil {
		s.fail(w, err)
		return
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, "yars.db")
	if err := s.Store.DB().Snapshot(snap); err != nil {
		s.fail(w, err)
		return
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Hour))
	name := "yars-backup-" + time.Now().Format("2006-01-02-1504") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	zw := zip.NewWriter(w)
	add := func(src, rel string, info fs.FileInfo) error {
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name, h.Method = rel, zip.Deflate
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		out, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, f)
		return err
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil || rel == "." {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		// only plain files: links could point out of the data directory
		if d.IsDir() || !d.Type().IsRegular() || backupSkip(rel, withKey) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return add(p, rel, info)
	})
	if err == nil {
		var info fs.FileInfo
		if info, err = os.Stat(snap); err == nil {
			err = add(snap, ".yars/yars.db", info)
		}
	}
	if err == nil {
		err = zw.Close()
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
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "backup", "", detail)
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

// runHealth runs the checks and keeps the result; ping also asks the AI
// provider for a reply (a paid call, so only on Check again).
func (s *Server) runHealth(ctx context.Context, ping bool) healthAdmin {
	v := s.health(ctx, ping)
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

// health runs every check of the System page's Health panel.
func (s *Server) health(ctx context.Context, ping bool) healthAdmin {
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
	check("Git server repos", "", s.healthGit)
	check("AI provider", "/admin/ai", func() healthResult { return s.healthAI(ctx, ping) })
	check("Disk free", "", s.healthDisk)
	check("Database integrity", "", s.healthDB)
	return v
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

func (s *Server) healthDB() healthResult {
	d := s.Store.DB()
	res, err := d.Check()
	if err != nil {
		return hBad("check failed", err.Error())
	}
	n, _ := d.Size()
	ver, _ := d.Version()
	detail := "quick_check " + res + " · schema v" + strconv.Itoa(ver)
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
		return healthResult{State: "off", Label: "Off", Result: "Off"}
	}
	set := s.Rules.Rules()
	res := strconv.Itoa(len(set.Rules)) + " loaded"
	if n := len(set.Problems); n > 0 {
		return healthResult{State: "warn", Label: "Warning", Result: res + " · " + strconv.Itoa(n) + " invalid", Detail: fmt.Sprint(set.Problems[0])}
	}
	return hGood(res, "")
}
