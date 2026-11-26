package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// tablesWithoutHead lists the opening tags of tables in b that have no
// header row.
func tablesWithoutHead(b string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?s)(<table[^>]*>)(.*?)</table>`).FindAllStringSubmatch(b, -1) {
		if !strings.Contains(m[2], "<thead>") {
			out = append(out, m[1])
		}
	}
	return out
}

// D16: two-column label/value tables (finding Details, retest Original,
// report preview) have a "Field | Value" header row like every table.
func TestLabelValueTablesHaveHeader(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.UpdateDetails("acme", fdir, map[string]string{"Location": "POST /login", "Legacy": "kept"}, "", e.authorOf(wAlice))
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	det := between(b, `id="details"`, "</section>")
	if strings.Count(det, `<thead><tr><th scope="col">Field</th><th scope="col">Value</th></tr></thead>`) != 2 {
		t.Fatalf("details tables (configured and Other):\n%s", det)
	}
	if bad := tablesWithoutHead(b); len(bad) > 0 {
		t.Fatalf("finding page tables without a header: %v", bad)
	}
	if bad := tablesWithoutHead(e.do(t, "alice", "GET", fpath+"/details", nil, nil).Body.String()); len(bad) > 0 {
		t.Fatalf("details panel: %v", bad)
	}
}

// The retest Original too.
func TestRetestOriginalHasHeader(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.UpdateDetails("acme", fdir, map[string]string{"Location": "POST /login"}, "", e.authorOf(wAlice))
	if err := st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{fdir}, "", wDora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String()
	orig := between(b, `class="panel compact orig"`, "</details>")
	if !strings.Contains(orig, `<th scope="col">Field</th><th scope="col">Value</th>`) {
		t.Fatalf("retest Original:\n%s", orig)
	}
	if bad := tablesWithoutHead(b); len(bad) > 0 {
		t.Fatalf("retest page tables without a header: %v", bad)
	}
}

// The report preview too.
func TestReportPreviewHasHeader(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	st := e.srv.Store
	if s := e.status(t); s != "complete" {
		t.Fatalf("status %s after approve", s)
	}
	if err := st.UpdateDetails("acme", fdir, map[string]string{"Location": "POST /login"}, "", wDora); err != nil {
		t.Fatal(err)
	}
	if s := e.status(t); s != "complete" {
		t.Fatalf("status %s after a director's details edit", s)
	}
	b := e.do(t, "dora", "GET", "/e/acme/export/preview?finding="+fdir, nil, nil).Body.String()
	for _, cls := range []string{"rp-kv", "rp-details"} {
		i := strings.Index(b, `class="`+cls+`"`)
		if i < 0 {
			t.Fatalf("no %s table in the preview:\n%s", cls, b)
		}
		if !strings.Contains(between(b[i:], ">", "</table>"), "<th>Field</th><th>Value</th>") {
			t.Errorf("%s has no header", cls)
		}
	}
}
