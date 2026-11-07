package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// checkEmptyRows checks every empty table of b: the one empty style (the
// header row, then one row whose dash spans every column), no old style.
func checkEmptyRows(t *testing.T, page, b string) int {
	t.Helper()
	for _, old := range []string{`class="muted empty"`, "No findings match", `class="muted">—</td></tr>`} {
		if strings.Contains(b, old) {
			t.Errorf("%s: old empty style %q", page, old)
		}
	}
	n := 0
	for _, m := range regexp.MustCompile(`(?s)<table[^>]*>(.*?)</table>`).FindAllStringSubmatch(b, -1) {
		tbl := m[1]
		if body := between(tbl, "<tbody>", "</tbody>"); strings.Contains(tbl, "<tbody>") && !strings.Contains(body, "<tr") {
			t.Errorf("%s: a table with only its header row: %.120s", page, tbl)
		}
		e := regexp.MustCompile(`<tr class="emptyrow"><td colspan="(\d+)">—</td></tr>`).FindStringSubmatch(tbl)
		if e == nil {
			continue
		}
		n++
		head := between(tbl, "<thead>", "</thead>")
		if head == "" {
			t.Errorf("%s: an empty table without a header row", page)
			continue
		}
		cols := len(regexp.MustCompile(`<th[ >]`).FindAllString(head, -1))
		if got, _ := strconv.Atoi(e[1]); got != cols {
			t.Errorf("%s: the empty row spans %d of %d columns", page, got, cols)
		}
	}
	return n
}

// Every literal empty_row column count in the templates matches its
// table's header (tables whose empty state no test page shows included).
func TestEmptyRowColspansInTemplates(t *testing.T) {
	ents, err := os.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, en := range ents {
		b, _ := os.ReadFile(filepath.Join("templates", en.Name()))
		for _, m := range regexp.MustCompile(`(?s)<table[^>]*>(.*?)</table>`).FindAllStringSubmatch(string(b), -1) {
			e := regexp.MustCompile(`\{\{template "empty_row" (\d+)\}\}`).FindStringSubmatch(m[1])
			if e == nil {
				continue
			}
			seen++
			head := between(m[1], "<thead>", "</thead>")
			cols := len(regexp.MustCompile(`<th[ >]`).FindAllString(head, -1))
			if got, _ := strconv.Atoi(e[1]); got != cols || strings.Contains(head, "{{range") {
				t.Errorf("%s: empty_row %d under %d header columns", en.Name(), got, cols)
			}
		}
	}
	if seen < 20 {
		t.Fatalf("only %d literal empty rows found", seen)
	}
}

// D17: one empty-table style everywhere.
func TestOneEmptyTableStyle(t *testing.T) {
	e := setup(t)
	pages := map[string]string{
		"/e/acme?status=reported": "dora", "/inbox": "dora", "/templates": "alice", "/notifications": "alice",
		"/e/acme/board": "alice", "/e/acme/export": "dora", fpath: "alice", "/e/acme/findings/new": "alice",
		"/admin/tokens": "dora", "/admin/activity": "dora", "/admin/webhooks": "dora", "/admin/rules": "dora", "/settings": "alice",
		"/e/acme/settings": "dora", "/e/acme/overview": "dora", "/e/acme/report": "dora", "/engagements": "dora", "/docs": "alice",
		fpath + "/history": "alice", "/e/acme/export/setup": "dora", "/admin/system": "dora", "/admin/users": "dora",
		fpath + "/merge": "alice", "/e/acme/retest/new": "dora", "/admin/structure": "dora", "/admin/ai": "dora",
	}
	total := 0
	for p, u := range pages {
		n := checkEmptyRows(t, p, e.do(t, u, "GET", p, nil, nil).Body.String())
		t.Logf("%s: %d empty tables", p, n)
		total += n
	}
	if total < 6 {
		t.Fatalf("only %d empty tables seen", total)
	}
}
