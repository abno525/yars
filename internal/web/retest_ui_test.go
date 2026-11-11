package web

import (
	"image/color"
	"strings"
	"testing"

	"yars/internal/store"
)

func TestNewRetestLayout(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	b := e.do(t, "dora", "GET", "/e/acme/retest/new", nil, nil).Body.String()
	for _, want := range []string{"<h2>Retest</h2>", "<h2>Findings to retest</h2>", "<th", ">Original status<", `class="btn primary w160"`, `class="btn secondary w112"`, `id="pick-F-001-sql-injection" checked`} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
	noInline(t, "new retest", b)
}

// D4: on a retest the Original starts collapsed; its head keeps Open.
func TestRetestOriginalCollapsed(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{fdir}, "", wDora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String()
	i := strings.Index(b, `<details class="panel compact orig"`)
	if i < 0 {
		t.Fatalf("no collapsible Original:\n%s", b)
	}
	tag := b[i : i+strings.Index(b[i:], ">")+1]
	head := between(b[i:], `<summary class="panelhead">`, "</summary>")
	if strings.Contains(tag, " open") || !strings.Contains(head, "<h2>Original</h2>") || !strings.Contains(head, `href="/e/acme/f/001">Open</a>`) {
		t.Fatalf("Original: %s\n%s", tag, head)
	}
	// closed it is its head alone, one line under it (the panel's)
	if css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, ".panel.orig:not([open]) > .panelhead { border-bottom: 0; }") {
		t.Fatal("the closed Original keeps its head's line")
	}
}

func TestRetestSideBySide(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.UpdateSection("acme", fdir, "Steps to Reproduce", "Send `user=admin'--`.\n\n![shot](attachments/shot.png)", "", e.authorOf(wAlice))
	if _, err := st.AddAttachment("acme", fdir, "shot.png", testPNG(t, color.Black), e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	st.UpdateDetails("acme", fdir, map[string]string{"Location": "POST /login"}, "", e.authorOf(wAlice))
	if err := st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{fdir}, "", wDora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String()
	for _, want := range []string{`class="retestgrid"`, "<h2>Original</h2>", `class="btn secondary sm w96" href="/e/acme/f/001"`, "POST /login", "<code>user=admin", `src="/e/acme/f/001/attachments/shot.png?v=`, `class="seg result-seg"`, ">Fixed<", ">Partially fixed<", ">Not fixed<", "Needs result"} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
	noInline(t, "retest finding", b)
	// someone off the original's team doesn't see its current content
	st.UpdateSection("acme", fdir, "Impact", "Later secret.", "", e.authorOf(wAlice))
	if err := st.AddMembers("rt", []string{"alice"}, wDora); err != nil {
		t.Fatal(err)
	}
	if err := st.RemoveMember("acme", "alice", wDora); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String(); strings.Contains(b, "Later secret.") || !strings.Contains(b, "<h2>Original</h2>") {
		t.Fatalf("original leaked or panel gone:\n%s", b)
	}
	st.AddMembers("acme", []string{"alice"}, wDora)
	st.SetRetestResult("rt", fdir, "fixed", wDora)
	if b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String(); strings.Contains(b, ">Needs result<") || !strings.Contains(b, `value="fixed" checked`) {
		t.Fatalf("after result:\n%s", b)
	}
}
