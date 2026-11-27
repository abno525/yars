package export

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// A push with no remembered page makes a new page. It never looks a page up
// by its title: the page of another engagement of the same name, or one a
// person wrote, is not overwritten.
func TestConfluenceNeverTakesAPageByTitle(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{"999": {Title: "F-001 SQL injection — ACME Web", Version: 3}}}
	r, e := confSetup(t, c)
	res, err := r.Run(context.Background(), e, oneFinding(t))
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "created" || it.Remote != (Remote{ID: "1", Version: 1}) {
		t.Fatalf("item %+v calls %v", it, c.calls)
	}
	if p := c.pages["999"]; p.Version != 3 || slices.Contains(c.calls, "PUT /rest/api/content/999") {
		t.Fatalf("the page of that title was written: v%d, calls %v", p.Version, c.calls)
	}
	if slices.Contains(c.calls, "GET /rest/api/content") {
		t.Fatalf("a page was searched by title: %v", c.calls)
	}
	if !slices.Equal(c.calls, []string{"POST /rest/api/content"}) {
		t.Fatalf("calls %v", c.calls)
	}
}

// A remembered page that now lives in another space is not written: a new
// page is made in the destination's space.
func TestConfluenceKnownPageInAnotherSpace(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{"55": {Title: "old title", Version: 4}}}
	r, e := confSetup(t, c)
	e.Confluence.Space = "T" // the fake's pages are in S
	in := oneFinding(t)
	in.Known = map[string]Remote{"F-001": {ID: "55", Version: 4}}
	res, err := r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "created" || it.Remote.ID != "1" || c.pages["55"].Version != 4 {
		t.Fatalf("item %+v calls %v", it, c.calls)
	}
}

// The page of several findings is remembered under PageKey: given back, the
// next push updates that page and makes no second one.
func TestConfluencePageOfSeveralFindingsIsRemembered(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{}}
	r, e := confSetup(t, c)
	res, err := r.Run(context.Background(), e, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 3 || res.Items[0].Action != "created" || res.Items[0].Remote.ID != "1" {
		t.Fatalf("first push %+v", res.Items)
	}
	in := input(t)
	in.Known = map[string]Remote{PageKey: res.Items[0].Remote}
	res, err = r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; it.Action != "updated" || it.Remote != (Remote{ID: "1", Version: 2}) || c.n != 1 {
		t.Fatalf("second push %+v, %d pages, calls %v", it, c.n, c.calls)
	}
	// a finding's own remembered page is not the page of several
	in = input(t)
	in.Known = map[string]Remote{"F-001": {ID: "1", Version: 2}}
	if res, err = r.Run(context.Background(), e, in); err != nil || res.Items[0].Action != "created" || c.n != 2 {
		t.Fatalf("a finding's page was taken for the page of several: %+v %v", res.Items, err)
	}
}

// Confluence refuses a second page of one title in a space. The refusal
// says why a new page was being made.
func TestConfluenceTitleTakenSaysWhy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"A page with this title already exists"}`)
	}))
	defer srv.Close()
	r, e := confSetup(t, &fakeConfluence{})
	e.Confluence.BaseURL = strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	for what, in := range map[string]Input{"no pictures": oneFinding(t), "pictures": confImages(t, confFiles())} {
		_, err := r.Run(context.Background(), e, in)
		if err == nil || !strings.Contains(err.Error(), "HTTP 400 A page with this title already exists") || !strings.Contains(err.Error(), "no page is remembered") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
