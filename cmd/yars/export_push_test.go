package main

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

// wiki is a Confluence that, as the real one, takes one page of a title and
// has no search: a push must know its page.
type wiki struct {
	mu     sync.Mutex
	titles map[string]string // page id → title
	vers   map[string]int
	calls  []string
	// failUpload: an attachment upload is answered 502
	failUpload bool
}

func (w *wiki) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, r.Method+" "+r.URL.Path)
	id := strings.TrimPrefix(r.URL.Path, "/rest/api/content/")
	answer := func(id string) {
		json.NewEncoder(rw).Encode(map[string]any{"id": id, "version": map[string]int{"number": w.vers[id]}, "space": map[string]string{"key": "S"},
			"_links": map[string]string{"base": "https://w", "webui": "/p/" + id}})
	}
	var body struct{ Title string }
	json.NewDecoder(r.Body).Decode(&body)
	switch {
	case strings.HasSuffix(id, "/child/attachment"):
		if r.Method == "PUT" && w.failUpload {
			rw.WriteHeader(502)
			return
		}
		io.WriteString(rw, `{"results":[]}`)
	case r.Method == "POST" && r.URL.Path == "/rest/api/content":
		for _, t := range w.titles {
			if t == body.Title {
				rw.WriteHeader(400)
				io.WriteString(rw, `{"message":"A page with this title already exists"}`)
				return
			}
		}
		id := strconv.Itoa(len(w.titles) + 1)
		w.titles[id], w.vers[id] = body.Title, 1
		answer(id)
	case r.Method == "GET" && w.titles[id] != "":
		answer(id)
	case r.Method == "PUT" && w.titles[id] != "":
		w.titles[id] = body.Title
		w.vers[id]++
		answer(id)
	default: // a search by title among them
		rw.WriteHeader(404)
		io.WriteString(rw, `{"message":"No content found"}`)
	}
}

// A first push of a finding with a picture makes the page, then the upload
// fails. The page is remembered all the same: the next run fills it, where a
// second page of the title would be refused.
func TestExportCLIRemembersThePageOfAFailedPush(t *testing.T) {
	dir := exportFixture(t)
	d := openDB(t, dir)
	repo, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(repo, config.Default(), d)
	dora := config.User{Username: "dora", Role: "director"}
	var shot bytes.Buffer
	if err := png.Encode(&shot, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	const fdir = "F-002-open-redirect"
	if _, err := st.AddAttachment("acme", fdir, "shot.png", shot.Bytes(), dora); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSection("acme", fdir, "Impact", "![shot](attachments/shot.png)", "", dora); err != nil {
		t.Fatal(err)
	}
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-002", db.State{Status: "complete"}) }); err != nil {
		t.Fatal(err)
	}
	w := &wiki{titles: map[string]string{}, vers: map[string]int{}, failUpload: true}
	srv := httptest.NewServer(w)
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	yaml := "name: Wiki\ntype: confluence\nconfluence:\n    base_url: " + base + "\n    space: S\n    user_env: CONFLUENCE_U\n    token_env: CONFLUENCE_T\n"
	if err := os.WriteFile(filepath.Join(dir, ".yars", "exporters", "wiki.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFLUENCE_U", "bot")
	t.Setenv("CONFLUENCE_T", "tok")
	args := []string{"--data", dir, "--exporter", "wiki", "acme", "F-002"}
	var log bytes.Buffer
	if code, err := cmdExport(args, &log); code != 1 || err == nil || !strings.Contains(err.Error(), "upload") {
		t.Fatalf("the failed push: code %d, %v\n%s\ncalls %v", code, err, log.String(), w.calls)
	}
	if rm, ok, err := d.ExportRemote("wiki", "acme", "F-002"); err != nil || !ok || rm.RemoteID != "1" || rm.Target != base+" S" {
		t.Fatalf("the page the failed push made is not remembered: %+v %v %v", rm, ok, err)
	}
	w.failUpload = false
	log.Reset()
	if code, err := cmdExport(args, &log); code != 0 || err != nil || !strings.Contains(log.String(), "published: https://w/p/1") {
		t.Fatalf("the next run: code %d, %v\n%s\ncalls %v", code, err, log.String(), w.calls)
	}
	if len(w.titles) != 1 || w.vers["1"] != 2 {
		t.Fatalf("pages %v versions %v calls %v", w.titles, w.vers, w.calls)
	}
}

// yars export to a Confluence destination remembers its page as the website
// does: a second run updates the page the first one made, for the page of
// several findings and for one finding's own page, which is the row the
// website reads.
func TestExportCLIUpdatesItsConfluencePage(t *testing.T) {
	dir := exportFixture(t)
	d := openDB(t, dir)
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-002", db.State{Status: "complete"}) }); err != nil {
		t.Fatal(err)
	}
	w := &wiki{titles: map[string]string{}, vers: map[string]int{}}
	srv := httptest.NewServer(w)
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	yaml := "name: Wiki\ntype: confluence\nconfluence:\n    base_url: " + base + "\n    space: S\n    user_env: CONFLUENCE_U\n    token_env: CONFLUENCE_T\n"
	if err := os.WriteFile(filepath.Join(dir, ".yars", "exporters", "wiki.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONFLUENCE_U", "bot")
	t.Setenv("CONFLUENCE_T", "tok")
	run := func(findings ...string) {
		t.Helper()
		var log bytes.Buffer
		args := append([]string{"--data", dir, "--exporter", "wiki", "acme"}, findings...)
		if code, err := cmdExport(args, &log); code != 0 || err != nil || !strings.Contains(log.String(), "published: https://w/p/") {
			t.Fatalf("yars export %v: code %d, %v\n%s\ncalls %v", findings, code, err, log.String(), w.calls)
		}
	}
	// every complete finding: one page, updated by the second run
	run()
	run()
	if len(w.titles) != 1 || w.vers["1"] != 2 || w.titles["1"] != "ACME — findings" {
		t.Fatalf("after two runs: pages %v versions %v calls %v", w.titles, w.vers, w.calls)
	}
	// one finding: a page of its own, updated by the second run
	run("F-001")
	run("F-001")
	if len(w.titles) != 2 || w.vers["2"] != 2 || w.vers["1"] != 2 {
		t.Fatalf("after two runs of one finding: pages %v versions %v calls %v", w.titles, w.vers, w.calls)
	}
	for _, c := range w.calls {
		if c == "GET /rest/api/content" {
			t.Fatalf("a page was searched by title: %v", w.calls)
		}
	}
	// remembered where the website looks: the finding's row, and the row of
	// the page of several findings
	for finding, id := range map[string]string{"F-001": "2", "": "1"} {
		rm, ok, err := d.ExportRemote("wiki", "acme", finding)
		if err != nil || !ok || rm.RemoteID != id || rm.Version != 2 || rm.Target != base+" S" {
			t.Errorf("remembered for %q: %+v %v %v", finding, rm, ok, err)
		}
	}
}
