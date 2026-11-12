package web

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/backup"
	"yars/internal/db"
)

// restoreMax caps an uploaded backup.
const restoreMax = 16 << 30

// restoreResult is a restore's report, carried to the page after the
// redirect (shown once).
type restoreResult struct {
	Target                    string
	Schema, Engagements, Find int
	HasKey                    bool
}

// restoreUpload restores an uploaded backup (POST /admin/system/restore,
// multipart field "backup"; admin only) into a new folder beside the data
// folder; the running server keeps serving its own (D24). The upload is
// streamed to a temporary file, which is removed afterwards; a refused
// backup leaves nothing on disk.
func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request) {
	clearDeadlines(w) // a large upload outlasts the server's read timeout
	r.Body = http.MaxBytesReader(w, r.Body, restoreMax)
	fail := func(status int, msg string) {
		s.systemPageStatus(w, r, status, systemAdmin{RestoreError: msg})
	}
	data := s.Store.Repo().Dir
	mr, err := r.MultipartReader()
	if err != nil {
		fail(http.StatusBadRequest, "choose a backup file")
		return
	}
	tmp, upload := "", "the upload"
	for tmp == "" {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		if part.FormName() != "backup" {
			continue
		}
		if n := filepath.Base(part.FileName()); n != "." && n != "/" && n != "" {
			upload = n
		}
		f, err := os.CreateTemp(filepath.Dir(data), ".yars-restore-*.zip")
		if err != nil { // the restored folder could not go there either
			fail(http.StatusInternalServerError, "cannot write beside "+data+": "+err.Error())
			return
		}
		tmp = f.Name()
		defer os.Remove(tmp)
		_, err = io.Copy(f, part)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			status := http.StatusBadRequest
			var big *http.MaxBytesError
			if errors.As(err, &big) {
				status = http.StatusRequestEntityTooLarge
			}
			fail(status, err.Error())
			return
		}
	}
	if tmp == "" {
		fail(http.StatusBadRequest, "choose a backup file")
		return
	}
	// one restore at a time: two in the same second would share the target,
	// and the one refused would remove the other's folder
	s.restoreMu.Lock()
	target := data + ".restored-" + time.Now().Format("20060102-150405")
	rep, err := backup.Restore(tmp, target)
	s.restoreMu.Unlock()
	if err != nil {
		// the reason names the file the admin chose, not its temporary copy
		msg := strings.ReplaceAll(err.Error(), tmp, upload)
		if errors.Is(err, zip.ErrFormat) {
			msg = "not a ZIP file"
		}
		fail(http.StatusBadRequest, msg)
		return
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "restore.upload", target, "")
	if js, err := json.Marshal(restoreResult{Target: target, Schema: rep.Schema, Engagements: rep.Engagements, Find: rep.Findings, HasKey: rep.HasKey}); err == nil {
		s.flash.put(r, "restore", string(js))
	}
	http.Redirect(w, r, "/admin/system#restore", http.StatusSeeOther)
}

// restoreView fills the Restore panel: a restore just made (once) and the
// last one (from the audit log).
func (s *Server) restoreView(r *http.Request, v *systemAdmin) {
	v.LastRestore, v.RestoreBy, v.RestoreDir = "—", "—", "—"
	if l, _, err := s.Store.DB().AuditQuery(db.AuditFilter{Action: "restore.upload", Limit: 1}); err == nil && len(l) == 1 {
		v.LastRestore, v.RestoreBy, v.RestoreDir = when(l[0].TS), l[0].Actor, l[0].Target
	}
	if js := s.flash.take(r, "restore"); js != "" {
		var res restoreResult
		if json.Unmarshal([]byte(js), &res) == nil {
			v.Restored = &res
		}
	}
}
