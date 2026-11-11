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
	if p.Audit+p.CheckRuns+p.Sessions > 0 {
		err = d.Audit("yars", "retention.prune", "", fmt.Sprintf("audit %d · check runs %d · sessions %d", p.Audit, p.CheckRuns, p.Sessions))
	}
	return p, err
}

// retentionFields are the Retention panel's inputs, in the order of
// db.Retention.
var retentionFields = []string{"audit_days", "check_run_days", "session_days"}

// retentionSave stores the Retention panel (POST /admin/system/retention):
// each value 0–3650 days, or the page answers 400 and stores nothing.
func (s *Server) retentionSave(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var n [3]int
	var bad error
	for i, k := range retentionFields {
		v, err := strconv.Atoi(strings.TrimSpace(r.PostForm.Get(k)))
		if err != nil && bad == nil {
			bad = fmt.Errorf("%s: a whole number of days", k)
		}
		n[i] = v
	}
	ret := db.Retention{AuditDays: n[0], CheckRunDays: n[1], SessionDays: n[2]}
	d := s.Store.DB()
	if bad == nil {
		bad = d.SetRetention(ret)
	}
	if bad != nil {
		s.systemPageStatus(w, r, http.StatusBadRequest, systemAdmin{RetentionError: bad.Error()})
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
