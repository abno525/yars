package export

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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

// fakeConfluence keeps pages by id with their title and version.
type fakeConfluence struct {
	mu    sync.Mutex
	pages map[string]*fakePage
	calls []string
	body  map[string]any
	n     int
}

type fakePage struct {
	Title   string
	Version int
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
		json.NewEncoder(w).Encode(page(id, p))
	case r.Method == "POST":
		c.body = nil
		json.NewDecoder(r.Body).Decode(&c.body)
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
