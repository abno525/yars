package export

import (
	"context"
	"testing"
)

// A first push with pictures makes the page empty, then uploads. When an
// upload fails the page is there: the failed push names it, and the next
// push, given that page, fills it and makes no second one (Confluence
// refuses a second page of the title).
func TestConfluenceFailedPushNamesThePageItMade(t *testing.T) {
	c := &fakeConfluence{pages: map[string]*fakePage{}, failUpload: true}
	r, e := confSetup(t, c)
	res, err := r.Run(context.Background(), e, confImages(t, confFiles()))
	if err == nil {
		t.Fatal("the upload was refused and the push says it went")
	}
	if res.Pushed || len(res.Items) != 1 || res.Items[0].ID != "F-001" || res.Items[0].Remote != (Remote{ID: "1", Version: 1}) {
		t.Fatalf("the page the push made is not named: %+v (%v)", res, err)
	}
	c.failUpload = false
	in := confImages(t, confFiles())
	in.Known = map[string]Remote{"F-001": res.Items[0].Remote}
	res, err = r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if it := res.Items[0]; !res.Pushed || it.Action != "updated" || it.Remote != (Remote{ID: "1", Version: 2}) || c.n != 1 {
		t.Fatalf("retry %+v, %d pages, calls %v", it, c.n, c.calls)
	}
	if p := c.pages["1"]; len(p.Attachments) != 2 || c.writes[len(c.writes)-1] == "" {
		t.Fatalf("the page is not filled: %+v writes %q", p, c.writes)
	}

	// a push that made no page names none
	c = &fakeConfluence{pages: map[string]*fakePage{"55": {Title: "old title", Version: 4}}, failUpload: true}
	r, e = confSetup(t, c)
	in = confImages(t, confFiles())
	in.Known = map[string]Remote{"F-001": {ID: "55", Version: 4}}
	if res, err = r.Run(context.Background(), e, in); err == nil || len(res.Items) != 0 {
		t.Fatalf("a failed update: %+v %v", res, err)
	}
}
