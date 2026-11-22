package export

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"yars/internal/finding"
)

// fakeJira keeps issues by key with their labels; it answers searches by
// label, updates and creations, and records every request.
type fakeJira struct {
	mu     sync.Mutex
	issues map[string][]string // key → labels
	calls  []string            // "METHOD path"
	jql    []string
	bodies []map[string]any
	n      int
}

func (j *fakeJira) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.calls = append(j.calls, r.Method+" "+r.URL.Path)
	var body map[string]any
	json.NewDecoder(r.Body).Decode(&body)
	j.bodies = append(j.bodies, body)
	switch {
	case r.Method == "GET" && r.URL.Path == "/rest/api/2/search":
		q := r.URL.Query().Get("jql")
		j.jql = append(j.jql, q)
		var found []map[string]string
		for k, ls := range j.issues {
			for _, l := range ls {
				if strings.Contains(q, `labels = "`+l+`"`) {
					found = append(found, map[string]string{"key": k})
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"issues": found})
	case r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/rest/api/2/issue/"):
		if _, ok := j.issues[strings.TrimPrefix(r.URL.Path, "/rest/api/2/issue/")]; !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"errorMessages":["Issue does not exist"]}`)
			return
		}
		w.WriteHeader(204)
	case r.Method == "POST" && r.URL.Path == "/rest/api/2/issue":
		j.n++
		k := "PEN-" + string(rune('0'+j.n))
		var labels []string
		if f, ok := body["fields"].(map[string]any); ok {
			ls, _ := f["labels"].([]any)
			for _, l := range ls {
				labels = append(labels, l.(string))
			}
		}
		j.issues[k] = labels
		w.WriteHeader(201)
		io.WriteString(w, `{"key":"`+k+`"}`)
	default:
		w.WriteHeader(400)
	}
}

func jiraSetup(t *testing.T) (*Runner, Exporter, *fakeJira, string) {
	t.Helper()
	j := &fakeJira{issues: map[string][]string{}}
	srv := httptest.NewServer(j)
	t.Cleanup(srv.Close)
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"JIRA_USER": "bot", "JIRA_TOKEN": "server"}[k] }
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	e := Exporter{ID: "j", Type: "jira", Jira: &JiraConf{BaseURL: base, Project: "PEN", IssueType: "Bug", UserEnv: "JIRA_USER", TokenEnv: "JIRA_TOKEN"}}
	return r, e, j, base
}

func oneFinding(t *testing.T) Input {
	in := input(t)
	in.Findings = in.Findings[1:2] // F-001
	return in
}

// A new issue carries the finding's label; sending again finds it by that
// label and updates it instead of making a second one.
func TestJiraCreatesThenUpdates(t *testing.T) {
	r, e, j, base := jiraSetup(t)
	res, err := r.Run(context.Background(), e, oneFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	it := res.Items[0]
	if it.Action != "created" || it.Remote.ID != "PEN-1" || it.URL != base+"/browse/PEN-1" {
		t.Fatalf("first send %+v", it)
	}
	if ls := j.issues["PEN-1"]; len(ls) != 1 || ls[0] != "yars-acme-F-001" {
		t.Fatalf("labels %v", ls)
	}
	if len(j.jql) != 1 || !strings.Contains(j.jql[0], `project = "PEN"`) || !strings.Contains(j.jql[0], `labels = "yars-acme-F-001"`) {
		t.Fatalf("jql %v", j.jql)
	}
	res, err = r.Run(context.Background(), e, oneFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	it = res.Items[0]
	if it.Action != "updated" || it.Remote.ID != "PEN-1" || it.URL != base+"/browse/PEN-1" || j.n != 1 {
		t.Fatalf("second send %+v, %d issues", it, j.n)
	}
	last := j.calls[len(j.calls)-1]
	f := j.bodies[len(j.bodies)-1]["fields"].(map[string]any)
	if last != "PUT /rest/api/2/issue/PEN-1" || f["summary"] != "F-001 SQL injection" || f["priority"].(map[string]any)["name"] != "High" ||
		!strings.Contains(f["description"].(string), "h2. Description") || f["project"] != nil || f["issuetype"] != nil {
		t.Fatalf("update %s %v", last, f)
	}
}

// A remembered issue is updated without a search; when it was deleted at
// Jira, a new one is made.
func TestJiraKnownIssue(t *testing.T) {
	r, e, j, _ := jiraSetup(t)
	j.issues["PEN-7"] = nil
	in := oneFinding(t)
	in.Known = map[string]Remote{"F-001": {ID: "PEN-7"}}
	res, err := r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "updated" || it.Remote.ID != "PEN-7" || len(j.jql) != 0 || j.n != 0 {
		t.Fatalf("known %+v calls %v", it, j.calls)
	}
	delete(j.issues, "PEN-7")
	res, err = r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "created" || it.Remote.ID != "PEN-1" || j.n != 1 {
		t.Fatalf("gone %+v calls %v", it, j.calls)
	}
	// other failures of the update are errors, nothing is created
	j.issues["PEN-7"] = nil
	r.Getenv = func(string) string { return "" }
	in.Creds = &Creds{User: "a", Token: "b"}
	srvDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srvDown.Close()
	e.Jira.BaseURL = srvDown.URL
	if _, err := r.Run(context.Background(), e, in); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("down: %v", err)
	}
}

// fakeConfluence keeps pages by id with their title, version and
// attachments; writes holds the storage body of every page write.
type fakeConfluence struct {
	mu         sync.Mutex
	pages      map[string]*fakePage
	calls      []string
	body       map[string]any
	writes     []string
	n          int
	failUpload bool // uploads are refused, as for a user who may not add attachments
}

type fakePage struct {
	Title       string
	Version     int
	Attachments map[string]*fakeAttachment // by file name
}

type fakeAttachment struct {
	Data                 []byte
	Type, Comment, Minor string
	Version              int
}

func storageOf(body map[string]any) string {
	b, _ := body["body"].(map[string]any)
	s, _ := b["storage"].(map[string]any)
	v, _ := s["value"].(string)
	return v
}

// attachments answers a page's attachment list (one file by ?filename=)
// and uploads, which need the XSRF header as Confluence's do.
func (c *fakeConfluence) attachments(w http.ResponseWriter, r *http.Request, pid string) {
	p, ok := c.pages[pid]
	if !ok {
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"No content found"}`)
		return
	}
	if p.Attachments == nil {
		p.Attachments = map[string]*fakeAttachment{}
	}
	item := func(name string, a *fakeAttachment) map[string]any {
		return map[string]any{"id": "att-" + name, "type": "attachment", "title": name, "version": map[string]int{"number": a.Version},
			"metadata": map[string]string{"comment": a.Comment, "mediaType": a.Type}, "extensions": map[string]any{"comment": a.Comment, "mediaType": a.Type, "fileSize": len(a.Data)}}
	}
	switch r.Method {
	case "GET":
		res := []map[string]any{}
		for name, a := range p.Attachments {
			if q := r.URL.Query().Get("filename"); q == "" || q == name {
				res = append(res, item(name, a))
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	case "PUT":
		if r.Header.Get("X-Atlassian-Token") != "no-check" {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"XSRF check failed"}`)
			return
		}
		if c.failUpload {
			w.WriteHeader(403)
			io.WriteString(w, `{"message":"User not permitted to create attachments for content: `+pid+`"}`)
			return
		}
		file, fh, err := r.FormFile("file")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		data, _ := io.ReadAll(file)
		a := p.Attachments[fh.Filename]
		if a == nil {
			a = &fakeAttachment{}
			p.Attachments[fh.Filename] = a
		}
		a.Data, a.Type, a.Comment, a.Minor, a.Version = data, fh.Header.Get("Content-Type"), r.FormValue("comment"), r.FormValue("minorEdit"), a.Version+1
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{item(fh.Filename, a)}})
	default:
		w.WriteHeader(405)
	}
}

func (c *fakeConfluence) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, r.Method+" "+r.URL.Path)
	page := func(id string, p *fakePage) map[string]any {
		return map[string]any{"id": id, "title": p.Title, "version": map[string]int{"number": p.Version}, "space": map[string]string{"key": "S"},
			"_links": map[string]string{"base": "https://w", "webui": "/p/" + id}}
	}
	id := strings.TrimPrefix(r.URL.Path, "/rest/api/content/")
	if pid, ok := strings.CutSuffix(id, "/child/attachment"); ok {
		c.attachments(w, r, pid)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/rest/api/content":
		res := []map[string]any{}
		for pid, p := range c.pages {
			if p.Title == r.URL.Query().Get("title") {
				res = append(res, page(pid, p))
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"results": res})
	case r.Method == "GET":
		p, ok := c.pages[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"No content found"}`)
			return
		}
		json.NewEncoder(w).Encode(page(id, p))
	case r.Method == "PUT":
		c.body = nil
		json.NewDecoder(r.Body).Decode(&c.body)
		p, ok := c.pages[id]
		if !ok {
			w.WriteHeader(404)
			return
		}
		v := int(c.body["version"].(map[string]any)["number"].(float64))
		if v != p.Version+1 {
			w.WriteHeader(409)
			io.WriteString(w, `{"message":"version conflict"}`)
			return
		}
		p.Version, p.Title = v, c.body["title"].(string)
		c.writes = append(c.writes, storageOf(c.body))
		json.NewEncoder(w).Encode(page(id, p))
	case r.Method == "POST":
		c.body = nil
		json.NewDecoder(r.Body).Decode(&c.body)
		c.writes = append(c.writes, storageOf(c.body))
		c.n++
		pid := string(rune('0' + c.n))
		c.pages[pid] = &fakePage{Title: c.body["title"].(string), Version: 1}
		json.NewEncoder(w).Encode(page(pid, c.pages[pid]))
	}
}

// A remembered page is read for its current version and updated; a page
// deleted at Confluence is made again.
func TestConfluenceKnownPage(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{"55": {Title: "old title", Version: 4}}}
	srv := httptest.NewServer(c)
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CONFLUENCE_U": "u", "CONFLUENCE_T": "t"}[k] }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CONFLUENCE_U", TokenEnv: "CONFLUENCE_T"}}
	in := oneFinding(t)
	in.Known = map[string]Remote{"F-001": {ID: "55", Version: 2}} // edited at Confluence since
	res, err := r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "updated" || it.Remote != (Remote{ID: "55", Version: 5}) || it.URL != "https://w/p/55" || c.n != 0 {
		t.Fatalf("known %+v calls %v", it, c.calls)
	}
	if p := c.pages["55"]; p.Title != "F-001 SQL injection — ACME Web" {
		t.Fatalf("title %q", p.Title)
	}
	delete(c.pages, "55")
	res, err = r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "created" || it.Remote != (Remote{ID: "1", Version: 1}) || it.URL != "https://w/p/1" {
		t.Fatalf("gone %+v calls %v", it, c.calls)
	}
	// unknown, but a page with the title is there: updated
	in.Known = nil
	res, err = r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "updated" || it.Remote != (Remote{ID: "1", Version: 2}) || c.n != 1 {
		t.Fatalf("by title %+v calls %v", it, c.calls)
	}
}

func confSetup(t *testing.T, c *fakeConfluence) (*Runner, Exporter) {
	t.Helper()
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CONFLUENCE_U": "bot", "CONFLUENCE_T": "tok123"}[k] }
	return r, Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CONFLUENCE_U", TokenEnv: "CONFLUENCE_T"}}
}

// confImages is F-001 alone with two pictures, one of them shown twice,
// read from files ("<finding>/<file>") the test may change.
func confImages(t *testing.T, files map[string][]byte) Input {
	in := oneFinding(t)
	in.Findings[0].SetSection("Impact", "Before ![shot](attachments/shot.png) after.\n\n![again](attachments/shot.png)\n\n![net](attachments/net.gif)")
	in.Attachment = func(f *finding.Finding, rel string) ([]byte, bool) {
		b, ok := files[f.Meta.ID+"/"+strings.TrimPrefix(rel, "attachments/")]
		return b, ok
	}
	return in
}

func confFiles() map[string][]byte {
	return map[string][]byte{"F-001/shot.png": pngBytes(), "F-001/net.gif": []byte("GIF89a net")}
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func count(calls []string, call string) int {
	n := 0
	for _, c := range calls {
		if c == call {
			n++
		}
	}
	return n
}

// A finding's pictures become attachments of its page, shown inline where
// they stood: a new page is made first (empty), the pictures uploaded,
// then the body written (Q5).
func TestConfluenceImagesNewPage(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{}}
	r, e := confSetup(t, c)
	res, err := r.Run(context.Background(), e, confImages(t, confFiles()))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /rest/api/content", "POST /rest/api/content", "PUT /rest/api/content/1/child/attachment", "PUT /rest/api/content/1/child/attachment", "PUT /rest/api/content/1"}
	if strings.Join(c.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls %v", c.calls)
	}
	if it := res.Items[0]; it.Action != "created" || it.Remote != (Remote{ID: "1", Version: 2}) || it.URL != "https://w/p/1" {
		t.Fatalf("item %+v", it)
	}
	if len(c.writes) != 2 || c.writes[0] != "" {
		t.Fatalf("writes %q", c.writes)
	}
	body := c.writes[1]
	for _, s := range []string{
		`Before <ac:image ac:alt="shot"><ri:attachment ri:filename="F-001-shot.png" /></ac:image> after.`,
		`<ac:image ac:alt="again"><ri:attachment ri:filename="F-001-shot.png" /></ac:image>`,
		`<ac:image ac:alt="net"><ri:attachment ri:filename="F-001-net.gif" /></ac:image>`,
	} {
		if !strings.Contains(body, s) {
			t.Errorf("body lacks %s:\n%s", s, body)
		}
	}
	if strings.Contains(body, "data:") || strings.Contains(body, "<img") {
		t.Fatalf("image inlined:\n%s", body)
	}
	p := c.pages["1"]
	shot, net := p.Attachments["F-001-shot.png"], p.Attachments["F-001-net.gif"]
	if len(p.Attachments) != 2 || shot == nil || net == nil {
		t.Fatalf("attachments %v", p.Attachments)
	}
	if !bytes.Equal(shot.Data, pngBytes()) || shot.Type != "image/png" || shot.Comment != sum(pngBytes()) || shot.Version != 1 || shot.Minor != "true" {
		t.Fatalf("shot %+v", shot)
	}
	if string(net.Data) != "GIF89a net" || net.Type != "image/gif" || net.Comment != sum(net.Data) {
		t.Fatalf("net %+v", net)
	}
}

// On a page of several findings each finding's picture is an attachment
// of its own, though the files have the same name.
func TestConfluenceImageNamesPerFinding(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{}}
	r, e := confSetup(t, c)
	in := input(t)
	for _, f := range in.Findings {
		f.SetSection("Impact", "![shot](attachments/shot.png)")
	}
	in.Attachment = func(f *finding.Finding, rel string) ([]byte, bool) {
		return []byte(f.Meta.ID), rel == "attachments/shot.png"
	}
	if _, err := r.Run(context.Background(), e, in); err != nil {
		t.Fatal(err)
	}
	p := c.pages["1"]
	if p == nil || p.Title != "ACME Web — findings" || len(p.Attachments) != 3 {
		t.Fatalf("page %+v", p)
	}
	body := c.writes[len(c.writes)-1]
	for _, id := range []string{"F-001", "F-002", "F-003"} {
		if a := p.Attachments[id+"-shot.png"]; a == nil || string(a.Data) != id {
			t.Errorf("%s: %+v", id, a)
		}
		if strings.Count(body, `ri:filename="`+id+`-shot.png"`) != 1 {
			t.Errorf("%s not shown once:\n%s", id, body)
		}
	}
}

// A remembered page gets the pictures it lacks, then its new body; no page
// is made.
func TestConfluenceImagesKnownPage(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{"55": {Title: "old title", Version: 4}}}
	r, e := confSetup(t, c)
	in := confImages(t, confFiles())
	in.Known = map[string]Remote{"F-001": {ID: "55", Version: 4}}
	res, err := r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GET /rest/api/content/55",
		"GET /rest/api/content/55/child/attachment", "PUT /rest/api/content/55/child/attachment",
		"GET /rest/api/content/55/child/attachment", "PUT /rest/api/content/55/child/attachment",
		"PUT /rest/api/content/55"}
	if strings.Join(c.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls %v", c.calls)
	}
	if it := res.Items[0]; it.Action != "updated" || it.Remote != (Remote{ID: "55", Version: 5}) || c.n != 0 {
		t.Fatalf("item %+v", it)
	}
	if p := c.pages["55"]; len(p.Attachments) != 2 || !strings.Contains(c.writes[0], `ri:filename="F-001-net.gif"`) {
		t.Fatalf("page %+v body %q", p, c.writes)
	}
}

// Sending again uploads no picture that is unchanged (no attachment
// versions pile up); a changed one becomes a new version of its attachment.
func TestConfluenceImagesUnchangedNotUploaded(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{}}
	r, e := confSetup(t, c)
	files := confFiles()
	res, err := r.Run(context.Background(), e, confImages(t, files))
	if err != nil {
		t.Fatal(err)
	}
	upload := "PUT /rest/api/content/1/child/attachment"
	// again, remembered and found by title
	for _, known := range []map[string]Remote{{"F-001": res.Items[0].Remote}, nil} {
		c.calls = nil
		in := confImages(t, files)
		in.Known = known
		if _, err := r.Run(context.Background(), e, in); err != nil {
			t.Fatal(err)
		}
		if n := count(c.calls, upload); n != 0 || count(c.calls, "GET /rest/api/content/1/child/attachment") != 2 {
			t.Fatalf("unchanged uploaded: %v", c.calls)
		}
	}
	p := c.pages["1"]
	if p.Version != 4 || p.Attachments["F-001-shot.png"].Version != 1 || p.Attachments["F-001-net.gif"].Version != 1 {
		t.Fatalf("page v%d, attachments %+v %+v", p.Version, p.Attachments["F-001-shot.png"], p.Attachments["F-001-net.gif"])
	}
	c.calls = nil
	files["F-001/shot.png"] = append(pngBytes(), 0)
	if _, err := r.Run(context.Background(), e, confImages(t, files)); err != nil {
		t.Fatal(err)
	}
	shot := p.Attachments["F-001-shot.png"]
	if count(c.calls, upload) != 1 || shot.Version != 2 || !bytes.Equal(shot.Data, files["F-001/shot.png"]) || shot.Comment != sum(shot.Data) ||
		p.Attachments["F-001-net.gif"].Version != 1 {
		t.Fatalf("changed: %v %+v", c.calls, shot)
	}
}

// An upload that fails fails the export with its picture named, and the
// page's body is not written.
func TestConfluenceImageUploadError(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{"55": {Title: "old title", Version: 4}}, failUpload: true}
	r, e := confSetup(t, c)
	in := confImages(t, confFiles())
	in.Known = map[string]Remote{"F-001": {ID: "55", Version: 4}}
	_, err := r.Run(context.Background(), e, in)
	if err == nil || !strings.Contains(err.Error(), "F-001-shot.png") || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "not permitted to create attachments") {
		t.Fatalf("err %v", err)
	}
	if p := c.pages["55"]; p.Version != 4 || count(c.calls, "PUT /rest/api/content/55") != 0 || count(c.calls, "PUT /rest/api/content/55/child/attachment") != 1 {
		t.Fatalf("page v%d calls %v", p.Version, c.calls)
	}
	// a new page is made, stays empty
	c.calls, c.writes = nil, nil
	_, err = r.Run(context.Background(), e, confImages(t, confFiles()))
	if err == nil || !strings.Contains(err.Error(), "F-001-shot.png") || len(c.writes) != 1 || c.writes[0] != "" || count(c.calls, "PUT /rest/api/content/1") != 0 {
		t.Fatalf("new: %v writes %q calls %v", err, c.writes, c.calls)
	}
}

// The Confluence HTML file keeps its pictures inline: it has no page to
// attach them to.
func TestConfluenceDownloadInlinesImages(t *testing.T) {
	r, _ := runner(t, "")
	res, err := r.Run(context.Background(), Exporter{ID: "c", Type: "confluence"}, confImages(t, confFiles()))
	if err != nil || !bytes.Contains(res.Data, []byte(`src="data:image/png;base64,`)) || !bytes.Contains(res.Data, []byte(`src="data:image/gif;base64,`)) || bytes.Contains(res.Data, []byte("ac:image")) {
		t.Fatalf("%v\n%s", err, res.Data)
	}
}
