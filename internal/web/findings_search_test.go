package web

import (
	"regexp"
	"strings"
	"testing"
)

// D23: the findings list searches ID, title and assets.
func TestBoardSearchFilters(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme?q=sql", nil, nil).Body.String(); !strings.Contains(b, "F-001") {
		t.Fatalf("q=sql does not list F-001:\n%s", b)
	}
	b := e.do(t, "alice", "GET", "/e/acme?q=zzz", nil, nil).Body.String()
	rows := between(b, "<tbody>", "</tbody>")
	if !strings.Contains(rows, `class="emptyrow"`) || strings.Contains(rows, "F-001") {
		t.Fatalf("q=zzz rows:\n%s", rows)
	}
}

// The search travels with every sort and status link, and the box shows it.
func TestBoardSearchKeepsFilterAndSort(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme?q=sql&sort=title&status=draft", nil, nil).Body.String()
	list := between(b, `<div class="filters">`, "</thead>") // status links and column sorts
	links := regexp.MustCompile(`href="(/e/acme[^"]*)"`).FindAllStringSubmatch(list, -1)
	if len(links) == 0 {
		t.Fatalf("no list links:\n%s", list)
	}
	for _, l := range links {
		if !strings.Contains(l[1], "q=sql") {
			t.Errorf("link without the search: %s", l[1])
		}
	}
	if !strings.Contains(b, `id="fq"`) || !strings.Contains(between(b, `id="fq"`, ">"), `value="sql"`) {
		t.Fatalf("the box does not show the search:\n%s", between(b, `<form class="fsearch"`, "</form>"))
	}
	// the form's own address leaves q to the box
	if form := between(b, `<form class="fsearch"`, ">"); strings.Contains(form, "q=") || !strings.Contains(form, "sort=title") {
		t.Fatalf("search form: %s", form)
	}
}

// A search with no match still shows the engagement's status counts.
func TestBoardSearchNoMatch(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme?q=zzz", nil, nil).Body.String()
	if !strings.Contains(between(b, `aria-label="Status"`, "</nav>"), "Draft · 1") {
		t.Fatalf("status counts:\n%s", between(b, `aria-label="Status"`, "</nav>"))
	}
	// and the table is the one empty row
	if rows := between(b, "<tbody>", "</tbody>"); strings.Count(rows, "<tr") != 1 || !strings.Contains(rows, `class="emptyrow"`) {
		t.Fatalf("rows:\n%s", rows)
	}
}

// The box keeps one id across swaps, so htmx gives it its focus back.
func TestBoardSearchInputHasStableID(t *testing.T) {
	e := setup(t)
	for _, path := range []string{"/e/acme", "/e/acme?q=sql"} {
		if n := strings.Count(e.do(t, "alice", "GET", path, nil, nil).Body.String(), `id="fq"`); n != 1 {
			t.Fatalf("%s: id=fq %d times", path, n)
		}
	}
	// the list htmx swaps in has it too
	if b := e.do(t, "alice", "GET", "/e/acme?q=s", nil, map[string]string{"HX-Request": "true"}).Body.String(); strings.Count(b, `id="fq"`) != 1 {
		t.Fatalf("htmx list without the box:\n%s", b)
	}
}

// A long search is cut, and surrounding spaces do not count.
func TestBoardSearchTrimmed(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme?q=++sql++", nil, nil).Body.String(); !strings.Contains(between(b, "<tbody>", "</tbody>"), "F-001") {
		t.Fatal("spaces around the search hide F-001")
	}
	long := strings.Repeat("a", 300)
	b := e.do(t, "alice", "GET", "/e/acme?q="+long, nil, nil).Body.String()
	if strings.Contains(b, long) || !strings.Contains(b, `value="`+strings.Repeat("a", 200)+`"`) {
		t.Fatal("the search is not cut to 200 characters")
	}
}
