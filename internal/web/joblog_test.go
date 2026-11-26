package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The background work of the website writes one line each time it ends: a
// backup download, a restore upload (made or refused), the daily prune and
// token notices, and an export with its counts. A refused upload's line does
// not name the uploaded file.
func TestWebJobsAreLogged(t *testing.T) {
	e := setupSerial(t)
	one := func(msg string) (rec struct {
		Level slog.Level
		Str   func(string) string
		Has   func(string) bool
	}) {
		t.Helper()
		recs := e.log.With(msg)
		if len(recs) != 1 {
			t.Fatalf("%d lines %q:\n%s", len(recs), msg, e.log.Text())
		}
		rec.Level, rec.Str, rec.Has = recs[0].Level, recs[0].Str, recs[0].Has
		return rec
	}
	zip := e.do(t, "dora", "POST", "/admin/system/backup", url.Values{}, nil)
	if zip.Code != 200 {
		t.Fatalf("backup %d", zip.Code)
	}
	if r := one("backup downloaded"); r.Level != slog.LevelInfo || r.Str("user") != "dora" || r.Str("bytes") == "0" || !r.Has("bytes") || !r.Has("ms") {
		t.Fatalf("backup line:\n%s", e.log.Text())
	}
	if rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "b.zip", zip.Body.Bytes()); rec.Code != http.StatusSeeOther {
		t.Fatalf("restore %d", rec.Code)
	}
	if r := one("restore: an uploaded backup is restored into a new folder"); r.Level != slog.LevelInfo || r.Str("user") != "dora" ||
		r.Str("engagements") != "1" || r.Str("findings") != "1" || !r.Has("ms") {
		t.Fatalf("restore line:\n%s", e.log.Text())
	}
	if rec := e.uploadFile(t, "dora", "/admin/system/restore", "backup", "zqupload7f3kq.zip", []byte("no zip")); rec.Code != http.StatusBadRequest {
		t.Fatalf("a refused restore %d", rec.Code)
	}
	if r := one("restore: an uploaded backup is refused"); r.Level != slog.LevelWarn || r.Str("user") != "dora" || !r.Has("ms") {
		t.Fatalf("refused restore line:\n%s", e.log.Text())
	}

	// the server's own first daily run may have written its lines already
	e.srv.daily(e.srv.Store.DB())
	if recs := e.log.With("retention: the daily prune finished"); len(recs) == 0 || recs[0].Level != slog.LevelInfo || !recs[0].Has("audit") ||
		!recs[0].Has("check_runs") || !recs[0].Has("sessions") || !recs[0].Has("ms") {
		t.Fatalf("prune line:\n%s", e.log.Text())
	}
	if recs := e.log.With("token notices: the daily run finished"); len(recs) == 0 || recs[0].Level != slog.LevelInfo || !recs[0].Has("ms") {
		t.Fatalf("token notices line:\n%s", e.log.Text())
	}

	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("export %d", rec.Code)
	}
	if r := one("export finished"); r.Level != slog.LevelInfo || r.Str("eng") != "acme" || r.Str("user") != "alice" || r.Str("destination") != "docx" ||
		r.Str("findings") != "1" || r.Str("sent") != "1" || r.Str("failed") != "0" || !r.Has("ms") {
		t.Fatalf("export line:\n%s", e.log.Text())
	}
	if text := e.log.Text(); strings.Contains(text, "zqupload7f3kq") {
		t.Fatalf("the log names the uploaded file:\n%s", text)
	}
}
