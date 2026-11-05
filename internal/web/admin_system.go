package web

import (
	"archive/zip"
	"context"
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

// systemAdmin is Admin › System: counts, sizes, the backup download and
// the CLI operations as buttons, with the last operation's result.
type systemAdmin struct {
	Users, Engagements, Archived, Findings, Messages int
	DBSize, IndexBuild, DataDir, Started, Uptime     string
	Schema                                           int
	Op, OpResult                                     string   // the operation run and what came of it
	OpOK                                             bool     // … it worked
	OpItems                                          []string // Migrate status: what still needs migrating
}

// healthAdmin is Admin › Health: one row per check.
type healthAdmin struct {
	Rows             []healthRow
	Checked, Uptime  string
	Errors, Warnings int
}

type healthRow struct {
	Name, State, Label, Detail, Took string
}

func (s *Server) routesAdminSystem(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/system", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		s.systemPage(w, r, systemAdmin{})
	}))
	mux.HandleFunc("GET /admin/system/backup", s.adminOnly(s.backup))
	mux.HandleFunc("POST /admin/system/sync", s.adminOnly(s.systemOp("sync")))
	mux.HandleFunc("POST /admin/system/reindex", s.adminOnly(s.systemOp("reindex")))
	mux.HandleFunc("POST /admin/system/migrate", s.adminOnly(s.systemOp("migrate")))
	mux.HandleFunc("GET /admin/health", s.adminOnly(s.healthPage))
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
		p.Admin.System = v
		return nil
	})
}

// systemOp runs one of the CLI operations and shows its result.
func (s *Server) systemOp(op string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := systemAdmin{Op: op}
		switch op {
		case "sync":
			if err := s.Store.SyncPointers(); err != nil {
				v.OpResult = err.Error()
			} else {
				v.OpOK, v.OpResult = true, "Synced"
			}
		case "reindex":
			if d, err := s.Index.Rebuild(); err != nil {
				v.OpResult = err.Error()
			} else {
				v.OpOK, v.OpResult = true, "Rebuilt · "+dur(d)
			}
		case "migrate":
			if s.MigrateStatus != nil {
				v.OpItems = s.MigrateStatus()
			}
			ver, _ := s.Store.DB().Version()
			v.OpOK = len(v.OpItems) == 0
			v.OpResult = "Schema v" + strconv.Itoa(ver) + " · " + plural(len(v.OpItems), "item") + " to migrate"
		}
		s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "system."+op, "", v.OpResult)
		s.systemPage(w, r, v)
	}
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
	withKey := r.URL.Query().Get("key") == "1"
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

func (s *Server) healthPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "health", http.StatusOK, func(p *page) error {
		v := healthAdmin{Checked: time.Now().Format("15:04"), Uptime: dur(time.Since(s.started))}
		check := func(name string, fn func() (state, label, detail string)) {
			start := time.Now()
			st, label, detail := fn()
			v.Rows = append(v.Rows, healthRow{Name: name, State: st, Label: label, Detail: detail, Took: dur(time.Since(start))})
			switch st {
			case "bad":
				v.Errors++
			case "warn":
				v.Warnings++
			}
		}
		check("Git", s.healthGit)
		check("Database", s.healthDB)
		check("Disk", s.healthDisk)
		check("AI", func() (string, string, string) { return s.healthAI(r.Context()) })
		check("Rules", s.healthRules)
		p.Admin.Health = v
		return nil
	})
}

func (s *Server) healthGit() (string, string, string) {
	out, err := exec.Command("git", "--version").Output()
	if err != nil {
		return "bad", "Error", "git: " + err.Error()
	}
	ids, err := s.Store.EngagementIDs()
	if err != nil {
		return "bad", "Error", err.Error()
	}
	broken := 0
	for _, id := range ids {
		if _, err := s.Store.EngHead(id); err != nil {
			broken++
		}
	}
	detail := strings.TrimPrefix(strings.TrimSpace(string(out)), "git version ") + " · " + plural(len(ids)+1, "repo")
	if broken > 0 {
		return "bad", "Error", detail + " · " + strconv.Itoa(broken) + " unreadable"
	}
	return "good", "OK", detail
}

func (s *Server) healthDB() (string, string, string) {
	d := s.Store.DB()
	res, err := d.Check()
	if err != nil {
		return "bad", "Error", err.Error()
	}
	n, _ := d.Size()
	ver, _ := d.Version()
	detail := "quick_check " + res + " · " + size(n) + " · schema v" + strconv.Itoa(ver)
	if res != "ok" || ver != db.SchemaVersion {
		return "bad", "Error", detail
	}
	return "good", "OK", detail
}

func (s *Server) healthDisk() (string, string, string) {
	var st syscall.Statfs_t
	dir := s.Store.Repo().Dir
	if err := syscall.Statfs(dir, &st); err != nil {
		return "bad", "Error", err.Error()
	}
	free, total := int64(st.Bavail)*int64(st.Bsize), int64(st.Blocks)*int64(st.Bsize)
	detail := size(free) + " free of " + size(total) + " · " + dir
	switch {
	case free < 1<<30:
		return "bad", "Error", detail
	case total > 0 && free*10 < total:
		return "warn", "Warning", detail
	}
	return "good", "OK", detail
}

func (s *Server) healthAI(ctx context.Context) (string, string, string) {
	rn := s.runner()
	if rn == nil {
		return "off", "Off", "—"
	}
	c, key, fromEnv := rn.Effective()
	if c.Provider == "" {
		return "off", "Off", "—"
	}
	if key == "" {
		return "bad", "Error", c.Provider + " · no key"
	}
	src := "stored key"
	if fromEnv {
		src = c.APIKeyEnv
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	took, err := rn.Ping(ctx)
	if err != nil {
		return "warn", "Warning", c.Provider + " · " + c.Model + " · " + err.Error()
	}
	return "good", "OK", c.Provider + " · " + c.Model + " · " + src + " · reply in " + dur(took)
}

func (s *Server) healthRules() (string, string, string) {
	if s.Rules == nil {
		return "off", "Off", "—"
	}
	set := s.Rules.Rules()
	detail := plural(len(set.Rules), "rule")
	if n := len(set.Problems); n > 0 {
		return "warn", "Warning", detail + " · " + plural(n, "problem")
	}
	return "good", "OK", detail
}
