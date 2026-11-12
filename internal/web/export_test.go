package web

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/export"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

const fakePandoc = `#!/bin/sh
out=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
cat > "$out"
`

func (e *env) exporters(t *testing.T, pandocBody string) {
	t.Helper()
	e.serialOnly(t, "a fake pandoc is written and run")
	dir := filepath.Join(e.dir, ".yars", "exporters")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "docx.yaml"), []byte("name: Client report (DOCX)\ntype: pandoc\nformat: docx\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "confluence.yaml"), []byte("name: Confluence HTML\ntype: confluence\nmark_reported: false\n"), 0o644)
	bin := filepath.Join(t.TempDir(), "pandoc")
	os.WriteFile(bin, []byte(pandocBody), 0o755)
	e.srv.Export = &export.Runner{Dir: dir, PandocPath: bin, HTTP: http.DefaultClient, Getenv: func(string) string { return "" }, Timeout: 5 * time.Second}
}

// jiraStub is a Jira that keeps issues with their labels and records who
// created or updated which issue.
type jiraStub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	users  []string            // login per issue created or updated
	fail   bool                // answer 500
	reject string              // a login answered 401
	issues map[string][]string // key → labels
	writes []string            // "POST" or "PUT PEN-1"
	n      int
}

func (e *env) jira(t *testing.T, marks bool) *jiraStub {
	t.Helper()
	j := &jiraStub{issues: map[string][]string{}}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.fail {
			w.WriteHeader(500)
			io.WriteString(w, `{"errorMessages":["jira is down"]}`)
			return
		}
		u, p, _ := r.BasicAuth()
		if j.reject != "" && u+":"+p == j.reject {
			w.WriteHeader(401)
			io.WriteString(w, `{"errorMessages":["key expired"]}`)
			return
		}
		switch r.Method {
		case "GET": // search by label
			q := r.URL.Query().Get("jql")
			var found []map[string]string
			for k, ls := range j.issues {
				for _, l := range ls {
					if strings.Contains(q, `labels = "`+l+`"`) {
						found = append(found, map[string]string{"key": k})
					}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"issues": found})
		case "PUT":
			k := strings.TrimPrefix(r.URL.Path, "/rest/api/2/issue/")
			if _, ok := j.issues[k]; !ok {
				w.WriteHeader(404)
				return
			}
			j.users = append(j.users, u+":"+p)
			j.writes = append(j.writes, "PUT "+k)
			w.WriteHeader(204)
		default:
			var body struct {
				Fields struct{ Labels []string }
			}
			json.NewDecoder(r.Body).Decode(&body)
			j.users = append(j.users, u+":"+p)
			j.writes = append(j.writes, "POST")
			j.n++
			k := "PEN-" + string(rune('0'+j.n))
			j.issues[k] = body.Fields.Labels
			w.WriteHeader(201)
			io.WriteString(w, `{"key":"`+k+`"}`)
		}
	}))
	t.Cleanup(j.srv.Close)
	base := strings.Replace(j.srv.URL, "127.0.0.1", "localhost", 1)
	m := ""
	if !marks {
		m = "mark_reported: false\n"
	}
	os.WriteFile(filepath.Join(e.srv.Export.Dir, "jira.yaml"), []byte("name: Jira\ntype: jira\n"+m+"jira: {base_url: "+base+", project: PEN, user_env: JIRA_USER, token_env: JIRA_TOKEN}\n"), 0o644)
	e.srv.Export.Getenv = func(k string) string { return map[string]string{"JIRA_USER": "bot", "JIRA_TOKEN": "srvkey5c2e"}[k] }
	return j
}

// secondComplete adds F-002 by bob and brings it to complete.
func (e *env) secondComplete(t *testing.T) string {
	t.Helper()
	st := e.srv.Store
	ref, err := st.CreateFinding("acme", "Missing HSTS", gitrepo.Author{Name: "bob", Email: "bob@yars.local"})
	if err != nil {
		t.Fatal(err)
	}
	wCarol := config.User{Username: "carol", Role: "reviewer"}
	if err := st.SetReviewers("acme", ref.Dir, []string{"carol"}, wBob); err != nil {
		t.Fatal(err)
	}
	st.UpdateSeverity("acme", ref.Dir, "low", "", e.authorOf(wBob))
	for _, step := range []struct {
		a workflow.Action
		u config.User
	}{{workflow.Submit, wBob}, {workflow.Clear, wCarol}, {workflow.Approve, wDora}} {
		if err := st.Transition("acme", ref.Dir, step.a, "", step.u); err != nil {
			t.Fatal(err)
		}
	}
	return ref.Dir
}

// follow returns the page a send redirected to.
func (e *env) follow(t *testing.T, user string, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("send code %d:\n%s", rec.Code, rec.Body.String())
	}
	loc, _, _ := strings.Cut(rec.Header().Get("Location"), "#") // a browser keeps the fragment to itself
	return e.do(t, user, "GET", loc, nil, nil).Body.String()
}

func TestExportPage(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	e.srv.Store.CreateFinding("acme", "Draft one", gitrepo.Author{Name: "alice"})
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	for _, want := range []string{
		`name="download" value="pdf"`, `name="download" value="docx"`, `name="download" value="zip"`, `name="download" value="full"`,
		`name="dest" value="docx"`, `name="dest" value="confluence"`, "Client report (DOCX)",
		"<th class=\"c-pick\">", ">ID</th>", ">Title</th>", ">Status</th>", ">Sent as</th>",
		`id="pick-F-001-sql-injection" checked`, `href="/e/acme/export/setup"`, ">History</h2>",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// a draft can't be picked
	if !regexp.MustCompile(`id="pick-F-002-draft-one" disabled`).MatchString(b) {
		t.Error("draft pickable")
	}
	// pentesters may send; the Destinations link keeps its slot
	b = e.do(t, "alice", "GET", "/e/acme/export", nil, nil).Body.String()
	if strings.Contains(b, `href="/e/acme/export/setup"`) || !strings.Contains(b, `<span class="slot w152"></span>`) || regexp.MustCompile(`value="docx"[^>]*disabled`).MatchString(b) {
		t.Fatalf("pentester page:\n%s", b)
	}
	if strings.Contains(b, "style=") {
		t.Fatal("inline style")
	}
}

// Downloads are files of complete findings; they never mark anything.
func TestExportDownloads(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"download": {"pdf"}, "finding": {fdir}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), `filename="acme.pdf"`) || !strings.Contains(rec.Body.String(), `<div class="rp-cover">`) {
		t.Fatalf("pdf %d %v", rec.Code, rec.Header())
	}
	if e.status(t) != "complete" {
		t.Fatal("download marked reported")
	}
	rec = e.do(t, "alice", "POST", "/e/acme/export", url.Values{"download": {"docx"}, "finding": {fdir}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), `filename="acme.docx"`) {
		t.Fatalf("docx %d", rec.Code)
	}
	rec = e.do(t, "alice", "POST", "/e/acme/export", url.Values{"download": {"zip"}, "finding": {fdir}}, nil)
	if files := zipList(t, rec.Body.Bytes()); rec.Code != 200 || !strings.Contains(files, "acme/index.html") {
		t.Fatalf("zip %d %s", rec.Code, files)
	}
	rec = e.do(t, "alice", "POST", "/e/acme/export", url.Values{"download": {"full"}, "finding": {fdir}}, nil)
	if files := zipList(t, rec.Body.Bytes()); rec.Code != 200 || !strings.Contains(files, "acme/.git/HEAD") || !strings.Contains(files, "acme/findings/F-001-sql-injection/finding.md") || !strings.Contains(files, "acme/report.html") {
		t.Fatalf("full %d %s", rec.Code, files)
	}
	h, _ := e.srv.Store.DB().Exports("acme", 10)
	if len(h) != 4 || h[0].Destination != "download:full" || !h[0].OK || h[0].By != "alice" || h[0].SentAs != "" {
		t.Fatalf("history %+v", h)
	}
	l, _ := e.srv.Store.DB().AuditLog(1)
	if len(l) != 1 || l[0].Action != "export" || l[0].Detail != "full, 1 findings" {
		t.Fatalf("audit %+v", l)
	}
	if e.status(t) != "complete" {
		t.Fatal("download marked reported")
	}
}

func zipList(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	var out []string
	for _, f := range zr.File {
		out = append(out, f.Name)
	}
	return strings.Join(out, " ")
}

// Only complete and reported findings are exported, never withdrawn ones.
func TestExportPicksComplete(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"download": {"docx"}, "finding": {fdir}}, nil)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Content-Disposition") != "" || !strings.Contains(rec.Body.String(), "F-001 is draft") {
		t.Fatalf("draft exported: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {"duplicate"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("withdraw code %d", rec.Code)
	}
	if b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String(); strings.Contains(b, "pick-F-001-sql-injection") {
		t.Fatal("withdrawn finding offered for export")
	}
	rec = e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("withdrawn export code %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"download": {"pdf"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("nothing picked: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"nope"}, "finding": {fdir}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown destination: %d", rec.Code)
	}
}

// A file destination: the sender (a pentester here) gets the file, and the
// findings sent are marked reported because the destination says so.
func TestExportSendFile(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	f2 := e.secondComplete(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil)
	page := e.follow(t, "alice", rec)
	i := strings.Index(page, "/e/acme/export/download/")
	if i < 0 || !strings.Contains(page, "Client report (DOCX)") {
		t.Fatalf("result page:\n%s", page)
	}
	link := page[i : i+strings.Index(page[i:], `"`)]
	if e.status(t) != "reported" || !strings.Contains(e.events(t), "alice:report") {
		t.Fatalf("not reported: %s / %s", e.status(t), e.events(t))
	}
	// only what was sent
	if e.statusOf(t, "acme", f2) != "complete" {
		t.Fatal("unsent finding marked")
	}
	if rec := e.do(t, "bob", "GET", link, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("other user downloaded: %d", rec.Code)
	}
	dl := e.do(t, "alice", "GET", link, nil, nil)
	if dl.Code != 200 || !strings.Contains(dl.Header().Get("Content-Disposition"), `filename="acme.docx"`) || !strings.Contains(dl.Body.String(), "<h1>F-001 SQL injection</h1>") {
		t.Fatalf("download code %d headers %v", dl.Code, dl.Header())
	}
	// mark_reported: false marks nothing
	e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"confluence"}, "finding": {f2}}, nil)
	if e.statusOf(t, "acme", f2) != "complete" {
		t.Fatal("mark_reported false marked")
	}
}

// Each finding goes to Jira with its author's own key when there is one,
// otherwise the server's; the history says which.
func TestExportSendAsAuthor(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	f2 := e.secondComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"jira@" + j.host()}, "key": {"alice@acme:ownkey"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("key %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	if !strings.Contains(b, `name="dest" value="jira"`) || !strings.Contains(b, "own key") || !strings.Contains(b, "server key") {
		t.Fatalf("page:\n%s", b)
	}
	page := e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir, f2}}, nil))
	if strings.Join(j.users, " ") != "alice@acme:ownkey bot:srvkey5c2e" {
		t.Fatalf("logins %v", j.users)
	}
	if !strings.Contains(page, "/browse/PEN-1") || !strings.Contains(page, "own key") || !strings.Contains(page, "server key") {
		t.Fatalf("result:\n%s", page)
	}
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	if len(h) != 1 || !h[0].OK || h[0].Destination != "jira" || h[0].SentAs != "alice, server" || !strings.HasSuffix(h[0].URL, "/browse/PEN-1") {
		t.Fatalf("history %+v", h)
	}
	var items []sendItem
	json.Unmarshal([]byte(h[0].Findings), &items)
	if len(items) != 2 || items[0].SentAs != "alice" || items[1].SentAs != "server" || !items[0].Marked || !items[1].Marked {
		t.Fatalf("items %+v", items)
	}
	if e.status(t) != "reported" || e.statusOf(t, "acme", f2) != "reported" {
		t.Fatal("not marked")
	}
	// the setup table shows the server key by its ending only
	b = e.do(t, "dora", "GET", "/e/acme/export/setup", nil, nil).Body.String()
	if !strings.Contains(b, "…5c2e") || strings.Contains(b, "srvkey") {
		t.Fatalf("setup:\n%s", b)
	}
}

// A failed send is recorded with its error, marks nothing and can be
// retried from the history.
func TestExportRetry(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	j.fail = true
	page := e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	if !strings.Contains(page, "jira is down") || !strings.Contains(page, `tag bad`) {
		t.Fatalf("failure not shown:\n%s", page)
	}
	if e.status(t) != "complete" {
		t.Fatal("marked after failure")
	}
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	if len(h) != 1 || h[0].OK || !strings.Contains(h[0].Error, "jira is down") {
		t.Fatalf("history %+v", h)
	}
	retry := "/e/acme/export/history/" + itoa(h[0].ID) + "/retry"
	if !strings.Contains(page, `action="`+retry+`"`) {
		t.Fatalf("no retry:\n%s", page)
	}
	// someone else's engagement history can't be retried from here
	if rec := e.do(t, "alice", "POST", "/e/other/export/history/"+itoa(h[0].ID)+"/retry", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("other engagement: %d", rec.Code)
	}
	j.fail = false
	page = e.follow(t, "alice", e.do(t, "alice", "POST", retry, url.Values{}, nil))
	if !strings.Contains(page, "/browse/PEN-1") || e.status(t) != "reported" {
		t.Fatalf("retry:\n%s", page)
	}
	if h, _ := e.srv.Store.DB().Exports("acme", 5); len(h) != 2 || !h[0].OK {
		t.Fatalf("history %+v", h)
	}
	// a successful send has nothing to retry
	h, _ = e.srv.Store.DB().Exports("acme", 1)
	if rec := e.do(t, "alice", "POST", "/e/acme/export/history/"+itoa(h[0].ID)+"/retry", url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("retry of a success: %d", rec.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// An archived engagement can't send (the slot stays), downloads still work.
func TestExportArchived(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	if !regexp.MustCompile(`name="dest" value="docx" disabled`).MatchString(b) {
		t.Fatalf("send enabled:\n%s", b)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("archived send %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"download": {"docx"}, "finding": {fdir}}, nil); rec.Code != 200 {
		t.Fatalf("archived download %d", rec.Code)
	}
}

// Every button on the export pages has a fixed width.
func TestExportFixedWidths(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, true)
	j.fail = true
	e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil)
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	btn := regexp.MustCompile(`class="btn ([^"]*)"`)
	width := regexp.MustCompile(`\b(w\d+|icon)\b`)
	for _, path := range []string{"/e/acme/export?sent=" + itoa(h[0].ID), "/e/acme/export/preview?finding=" + fdir, "/e/acme/export/setup", "/e/acme/export/setup?edit=jira"} {
		b := e.do(t, "dora", "GET", path, nil, nil).Body.String()
		b = regexp.MustCompile(`(?s)<noscript>.*?</noscript>`).ReplaceAllString(b, "") // the layout's no-JS fallback
		ms := btn.FindAllStringSubmatch(b, -1)
		if len(ms) < 3 {
			t.Fatalf("%s: %d buttons", path, len(ms))
		}
		for _, m := range ms {
			if !width.MatchString(m[1]) {
				t.Errorf("%s: button without a fixed width: %q", path, m[0])
			}
		}
		if strings.Contains(b, "style=") || strings.Contains(b, "min-width") {
			t.Errorf("%s: inline style", path)
		}
	}
	// no pandoc: the PDF button stays, disabled
	e.srv.Export.PandocPath = ""
	b := e.do(t, "dora", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil).Body.String()
	if !strings.Contains(b, `name="download" value="pdf" disabled`) {
		t.Fatal("PDF without pandoc")
	}
}

func TestExportPreview(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	b := e.do(t, "alice", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil).Body.String()
	for _, want := range []string{`<div class="rp-cover">`, "SQL injection", `href="#rp-summary"`, `href="#rp-F-001"`, `name="download" value="pdf"`, `<h2>Contents</h2><span class="badge">1</span>`} {
		if !strings.Contains(b, want) {
			t.Errorf("preview lacks %q", want)
		}
	}
	if strings.Contains(b, "style=") {
		t.Fatal("inline style")
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/export/preview", nil, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty preview %d", rec.Code)
	}
}

// Destinations are edited by directors, written to .yars/exporters and
// committed to the main repository; a file export.Load refuses is not saved.
func TestExportSetup(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	if rec := e.do(t, "alice", "GET", "/e/acme/export/setup", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester setup %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/export/setup", url.Values{"id": {"x"}, "type": {"pandoc"}, "format": {"docx"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester save %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/e/acme/export/setup", nil, nil).Body.String()
	for _, want := range []string{">Destination</th>", ">Kind</th>", ">Server key</th>", ">Marks reported</th>", "Client report (DOCX)", `href="/e/acme/export/setup?edit=docx"`, `<td class="mono">—</td>`} {
		if !strings.Contains(b, want) {
			t.Errorf("setup lacks %q", want)
		}
	}
	form := url.Values{"new": {"1"}, "id": {"jira"}, "name": {"Jira PEN"}, "type": {"jira"}, "base_url": {"https://jira.acme.com"}, "project": {"PEN"},
		"issue_type": {"Task"}, "user_env": {"JIRA_USER"}, "token_env": {"JIRA_TOKEN"}, "status": {"complete"}, "mark_reported": {"1"}}
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Del("project")
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", bad, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "project") {
		t.Fatalf("invalid saved: %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(e.srv.Export.Dir, "jira.yaml")); err == nil {
		t.Fatal("invalid file left")
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	es, errs := export.Load(e.srv.Export.Dir)
	var j *export.Exporter
	for i := range es {
		if es[i].ID == "jira" {
			j = &es[i]
		}
	}
	if len(errs) != 0 || j == nil || j.Name != "Jira PEN" || j.Jira.Project != "PEN" || j.Jira.IssueType != "Task" || !j.Marks() {
		t.Fatalf("saved %+v %v", j, errs)
	}
	out, _ := exec.Command("git", "-C", e.dir, "log", "-1", "--format=%an|%s", "--", ".yars/exporters/jira.yaml").Output()
	if !strings.HasPrefix(string(out), "dora|exporters: save jira") {
		t.Fatalf("commit %q", out)
	}
	// a new destination can't take an existing id
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", form, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate id: %d", rec.Code)
	}
	// edit: no longer marks reported
	form.Del("new")
	form.Del("mark_reported")
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("edit %d", rec.Code)
	}
	es, _ = export.Load(e.srv.Export.Dir)
	for _, x := range es {
		if x.ID == "jira" && x.Marks() {
			t.Fatal("mark_reported not cleared")
		}
	}
	if b := e.do(t, "dora", "GET", "/e/acme/export/setup?edit=jira", nil, nil).Body.String(); !strings.Contains(b, `value="https://jira.acme.com"`) || !strings.Contains(b, ">Delete</button>") {
		t.Fatalf("editor:\n%s", b)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup/delete", url.Values{"id": {"jira"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("delete %d", rec.Code)
	}
	if _, err := os.Stat(filepath.Join(e.srv.Export.Dir, "jira.yaml")); err == nil {
		t.Fatal("not deleted")
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", url.Values{"new": {"1"}, "id": {"../x"}, "name": {"x"}, "type": {"pandoc"}, "format": {"docx"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", rec.Code)
	}
}

func TestExportEmbedsOnlyAttachments(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	att := filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "attachments")
	os.MkdirAll(att, 0o755)
	os.WriteFile(filepath.Join(att, "shot.png"), []byte("PNGDATA"), 0o644)
	e.srv.Store.UpdateSection("acme", fdir, "Impact", "![s](attachments/shot.png) ![x](/etc/hostname)", "", e.authorOf(wAlice))
	e.toComplete(t)
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"download": {"docx"}, "finding": {fdir}}, nil)
	if b := rec.Body.String(); rec.Code != 200 || !strings.Contains(b, "data:image/png;base64,UE5HREFUQQ==") || strings.Contains(b, "/etc/hostname\"") {
		t.Fatalf("report %d:\n%s", rec.Code, b)
	}
}

// An export may run longer than the server's write timeout (the exporter's
// own limit is longer): the export request lifts it, so the file arrives.
func TestExportOutlivesWriteTimeout(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, "#!/bin/sh\nsleep 1\n"+strings.TrimPrefix(fakePandoc, "#!/bin/sh\n"))
	hs := e.srv.HTTPServer("127.0.0.1:0")
	hs.WriteTimeout = 300 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/e/acme/export",
		strings.NewReader(url.Values{"download": {"docx"}, "finding": {fdir}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 || !strings.Contains(string(b), "SQL injection") {
		t.Fatalf("code %d err %v:\n%s", resp.StatusCode, err, b)
	}
	// other requests keep the timeout
	if hs.WriteTimeout != 300*time.Millisecond {
		t.Fatal("server timeout changed")
	}
}

func TestExportFailureMarksNothing(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, "#!/bin/sh\necho 'pandoc: boom' >&2\nexit 1\n")
	page := e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil))
	if !strings.Contains(page, "boom") || strings.Contains(page, "/export/download/") {
		t.Fatalf("page:\n%s", page)
	}
	if e.status(t) != "complete" {
		t.Fatal("marked after failure")
	}
	rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"download": {"pdf"}, "finding": {fdir}}, nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "boom") || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("download failure %d", rec.Code)
	}
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	if len(h) != 1 || h[0].OK || h[0].Destination != "download:pdf" {
		t.Fatalf("history %+v", h)
	}
}

// host is the stub's host as its destination names it.
func (j *jiraStub) host() string {
	u, _ := url.Parse(strings.Replace(j.srv.URL, "127.0.0.1", "localhost", 1))
	return u.Host
}

func (j *jiraStub) lastUser() string {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.users) == 0 {
		return ""
	}
	return j.users[len(j.users)-1]
}

// A personal key is kept for one service host and sent only there: another
// destination of the same service gets the server's key, and a key bound to
// no host (stored before keys had hosts) is never sent.
func TestExportKeyBoundToHost(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	client := e.jira(t, false)
	if err := os.Rename(filepath.Join(e.srv.Export.Dir, "jira.yaml"), filepath.Join(e.srv.Export.Dir, "client.yaml")); err != nil {
		t.Fatal(err)
	}
	firm := e.jira(t, false)
	send := func(dest string) {
		t.Helper()
		e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {dest}, "finding": {fdir}}, nil))
	}
	// a key stored for the service alone
	box, err := e.srv.secrets()
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := box.Encrypt("alice@acme:legacy")
	if err := e.srv.Store.DB().SetConnection("alice", "jira", enc); err != nil {
		t.Fatal(err)
	}
	send("jira")
	if u := firm.lastUser(); u != "bot:srvkey5c2e" {
		t.Fatalf("unbound key sent: %s", u)
	}
	// a key for the firm's Jira
	svc := "jira@" + firm.host()
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {svc}, "key": {"alice@acme:ownkey"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("key %d:\n%s", rec.Code, rec.Body.String())
	}
	if b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `id="conn-`+svc+`"`) || !strings.Contains(b, firm.host()) || !strings.Contains(b, client.host()) {
		t.Fatalf("settings:\n%s", b)
	}
	send("client")
	if u := client.lastUser(); u != "bot:srvkey5c2e" {
		t.Fatalf("firm key sent to the client's Jira: %s", u)
	}
	send("jira")
	if u := firm.lastUser(); u != "alice@acme:ownkey" {
		t.Fatalf("own key not used at its host: %s", u)
	}
	// keys only for the hosts of destinations
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"jira@evil.example"}, "key": {"x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown host %d", rec.Code)
	}
	// the unbound key can still be removed
	if rec := e.do(t, "alice", "POST", "/settings/connections/jira/remove", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove %d", rec.Code)
	}
	if _, ok, _ := e.srv.Store.DB().Connection("alice", "jira"); ok {
		t.Fatal("unbound key not removed")
	}
}

// A failed send is retried once: after its retry the old row offers no
// Retry and refuses one, so its findings are never sent twice.
func TestExportRetryOnce(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	j := e.jira(t, false)
	j.fail = true
	e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"jira"}, "finding": {fdir}}, nil))
	h, _ := e.srv.Store.DB().Exports("acme", 1)
	first := itoa(h[0].ID)
	retry := "/e/acme/export/history/" + first + "/retry"
	j.fail = false
	e.follow(t, "alice", e.do(t, "alice", "POST", retry, url.Values{}, nil))
	if rec := e.do(t, "alice", "POST", retry, url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("second retry %d", rec.Code)
	}
	if strings.Join(j.writes, " ") != "POST" {
		t.Fatalf("sent again: %v", j.writes)
	}
	b := e.do(t, "alice", "GET", "/e/acme/export?sent="+first, nil, nil).Body.String()
	if strings.Contains(b, `action="`+retry+`"`) || strings.Contains(b, `formaction="`+retry+`"`) {
		t.Fatalf("old row still retries:\n%s", b)
	}
}

// What the team wrote in the Report tab is in the exported report.
func TestExportIncludesReportTab(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if err := e.srv.Store.UpdateReportSection("acme", "Executive summary", "Two **critical** issues.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil).Body.String()
	if !strings.Contains(b, "Two <strong>critical</strong> issues.") {
		t.Fatalf("preview lacks the executive summary:\n%s", b)
	}
}

// The export Findings panel has its head before its table (reading and
// keyboard order), with the ticked count rendered by the server.
func TestExportPickHeadFirst(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	panel := between(b, `<section class="panel compact pickpanel">`, "</section>")
	head, table := strings.Index(panel, `class="panelhead"`), strings.Index(panel, "<table")
	if head < 0 || table < 0 || head > table {
		t.Fatalf("pick panel order:\n%s", panel)
	}
	if !regexp.MustCompile(`class="mono selof" data-of="\d+">\d+ of \d+</span>`).MatchString(panel) {
		t.Fatalf("no count in the head:\n%s", panel)
	}
	css := e.do(t, "dora", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if strings.Contains(css, "order: -1") && strings.Contains(between(css, ".pickpanel > .panelhead", "}"), "order") {
		t.Fatal("the head is still moved by CSS order")
	}
	// boxes restored by the browser (reload, back/forward) are recounted
	js := e.do(t, "dora", "GET", staticPrefix()+"/app.js", nil, nil).Body.String()
	for _, want := range []string{"addEventListener('DOMContentLoaded', yarsPickCountAll)", "addEventListener('pageshow', yarsPickCountAll)", "addEventListener('htmx:afterSettle', yarsPickCountAll)"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
}
