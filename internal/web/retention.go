package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
)

// pruneEvery is how often the retention worker runs.
const pruneEvery = 24 * time.Hour

// startRetention starts the retention worker (once; it stops on Close): it
// prunes now and then every day (D24).
func (s *Server) startRetention() {
	d := s.Store.DB()
	if d == nil {
		return
	}
	s.pruneOnce.Do(func() {
		go func() {
			t := time.NewTicker(pruneEvery)
			defer t.Stop()
			for {
				if _, err := s.prune(d); err != nil {
					select {
					case <-s.stop: // the database closes with the server
					default:
						log.Printf("retention: %v", err)
					}
				}
				select {
				case <-s.stop:
					return
				case <-t.C:
				}
			}
		}()
	})
}

// prune deletes what the retention settings no longer keep; a run that
// deleted anything is audited by yars.
func (s *Server) prune(d *db.DB) (db.Pruned, error) {
	r, err := d.Retention()
	if err != nil {
		return db.Pruned{}, err
	}
	p, err := d.Prune(time.Now(), r)
	if err != nil {
		return p, err
	}
	if p.Audit+p.CheckRuns+p.Sessions+p.AIUsage > 0 {
		detail := fmt.Sprintf("audit %d · check runs %d · sessions %d", p.Audit, p.CheckRuns, p.Sessions)
		if p.AIUsage > 0 {
			detail += fmt.Sprintf(" · AI calls %d", p.AIUsage)
		}
		err = d.Audit("yars", "retention.prune", "", detail)
	}
	return p, err
}

// retentionFields are the Retention panel's inputs and their labels, in
// the order of db.Retention.
var retentionFields = [][2]string{{"audit_days", "Audit log"}, {"check_run_days", "Check runs"}, {"session_days", "Sessions"}}

// retentionSave stores the Retention panel (POST /admin/system/retention):
// each value 0–3650 days, or the page answers 400 naming the field and
// stores nothing.
func (s *Server) retentionSave(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var n [3]int
	var bad error
	badField := ""
	for i, f := range retentionFields {
		v, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get(f[0])))
		if (err != nil || v < 0 || v > 3650) && bad == nil {
			bad, badField = fmt.Errorf("%s: 0 to 3650 days", f[1]), f[0]
		}
		n[i] = v
	}
	ret := db.Retention{AuditDays: n[0], CheckRunDays: n[1], SessionDays: n[2]}
	d := s.Store.DB()
	if bad == nil {
		bad = d.SetRetention(ret)
	}
	if bad != nil {
		s.systemPageStatus(w, r, http.StatusBadRequest, systemAdmin{RetentionError: bad.Error(), RetentionBad: badField})
		return
	}
	d.Audit(auth.UserFrom(r.Context()).Username, "setting.retention", "", fmt.Sprintf("audit %d · check runs %d · sessions %d", ret.AuditDays, ret.CheckRunDays, ret.SessionDays))
	http.Redirect(w, r, "/admin/system#retention", http.StatusSeeOther)
}

// retentionView fills the Retention panel: the settings and the last prune.
func (s *Server) retentionView(v *systemAdmin) error {
	d := s.Store.DB()
	var err error
	if v.Retention, err = d.Retention(); err != nil {
		return err
	}
	v.LastPrune = "—"
	if l, _, err := d.AuditQuery(db.AuditFilter{Action: "retention.prune", Limit: 1}); err == nil && len(l) == 1 {
		v.LastPrune = when(l[0].TS) + " · " + l[0].Detail
	}
	return nil
}
