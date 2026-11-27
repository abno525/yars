package web

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A first send of a finding with a picture makes the Confluence page, then
// the upload fails. The page is remembered all the same: the next send fills
// it, where Confluence would refuse a second page of the title.
func TestExportRemembersThePageOfAFailedSend(t *testing.T) {
	e := setupSerial(t)
	st := e.srv.Store
	var shot bytes.Buffer
	if err := png.Encode(&shot, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddAttachment("acme", fdir, "shot.png", shot.Bytes(), wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSection("acme", fdir, "Impact", "![shot](attachments/shot.png)", "", wAlice); err != nil {
		t.Fatal(err)
	}
	e.toComplete(t)
	e.exporters(t, fakePandoc)

	// a Confluence that takes one page of a title and has no search
	var (
		mu         sync.Mutex
		titles     = map[string]string{}
		vers       = map[string]int{}
		failUpload = true
		calls      []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)
		id := strings.TrimPrefix(r.URL.Path, "/rest/api/content/")
		answer := func(id string) {
			json.NewEncoder(w).Encode(map[string]any{"id": id, "version": map[string]int{"number": vers[id]}, "space": map[string]string{"key": "S"},
				"_links": map[string]string{"base": "https://w", "webui": "/p/" + id}})
		}
		var body struct{ Title string }
		json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.HasSuffix(id, "/child/attachment"):
			if r.Method == "PUT" && failUpload {
				w.WriteHeader(502)
				return
			}
			io.WriteString(w, `{"results":[]}`)
		case r.Method == "POST" && r.URL.Path == "/rest/api/content":
			for _, t := range titles {
				if t == body.Title {
					w.WriteHeader(400)
					io.WriteString(w, `{"message":"A page with this title already exists"}`)
					return
				}
			}
			titles["1"], vers["1"] = body.Title, 1
			answer("1")
		case r.Method == "GET" && titles[id] != "":
			answer(id)
		case r.Method == "PUT" && titles[id] != "":
			vers[id]++
			answer(id)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	yaml := "name: Wiki\ntype: confluence\nmark_reported: false\nconfluence: {base_url: " + base + ", space: S, user_env: CONFLUENCE_U, token_env: CONFLUENCE_T}\n"
	if err := os.WriteFile(filepath.Join(e.srv.Export.Dir, "wiki.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	e.srv.Export.Getenv = func(k string) string {
		return map[string]string{"CONFLUENCE_U": "bot", "CONFLUENCE_T": "srvkey5c2e"}[k]
	}
	send := func() {
		e.follow(t, "dora", e.do(t, "dora", "POST", "/e/acme/export", url.Values{"dest": {"wiki"}, "finding": {fdir}}, nil))
	}

	send()
	h, _ := st.DB().Exports("acme", 1)
	if len(h) != 1 || h[0].OK || !strings.Contains(h[0].Error, "upload") {
		t.Fatalf("the failed send: %+v calls %v", h, calls)
	}
	if items := itemsOf(h[0]); len(items) != 1 || items[0].OK || items[0].Action != "" {
		t.Fatalf("the failed send's item: %+v", items)
	}
	rm, ok, err := st.DB().ExportRemote("wiki", "acme", "F-001")
	if err != nil || !ok || rm.RemoteID != "1" || rm.Target != base+" S" {
		t.Fatalf("the page the failed send made is not remembered: %+v %v %v", rm, ok, err)
	}

	mu.Lock()
	failUpload = false
	mu.Unlock()
	send()
	h, _ = st.DB().Exports("acme", 1)
	if items := itemsOf(h[0]); !h[0].OK || len(items) != 1 || items[0].Action != "updated" {
		t.Fatalf("the next send: %+v calls %v", h[0], calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(titles) != 1 || vers["1"] != 2 {
		t.Fatalf("pages %v versions %v calls %v", titles, vers, calls)
	}
}
