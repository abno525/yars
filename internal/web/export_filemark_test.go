package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/export"
)

// Q7: a file destination whose file has no mark_reported makes its file and
// marks nothing: the finding stays complete, and neither its card nor its
// row in the editor says it marks. The same file with mark_reported: true
// marks.
func TestExportFileDoesNotMarkByDefault(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	word := filepath.Join(e.srv.Export.Dir, "word.yaml")
	os.WriteFile(word, []byte("name: Word\ntype: pandoc\nformat: docx\n"), 0o644)
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	if !strings.Contains(b, `<span class="dname">Word</span><span class="dsub" title="pandoc · docx">pandoc · docx</span>`) {
		t.Fatalf("the card of a file destination without the key:\n%s", between(b, `class="dgrid"`, "</div>"))
	}
	b = e.do(t, "dora", "GET", "/e/acme/export/setup?edit=word", nil, nil).Body.String()
	row := between(b, `title="word.yaml · `, "</tr>")
	if !strings.Contains(row, `aria-label="does not mark"`) || !strings.Contains(b, `<input type="checkbox" name="mark_reported" value="1">Marks reported`) {
		t.Fatalf("the editor of a file destination without the key:\n%s", row)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"word"}, "finding": {fdir}}, nil)
	page := e.follow(t, "alice", rec)
	if !strings.Contains(page, "/e/acme/export/download/") || !strings.Contains(page, "1 of 1 · 0 reported") {
		t.Fatalf("result page:\n%s", between(page, `class="panel compact result`, "</section>"))
	}
	if e.status(t) != "complete" || strings.Contains(e.events(t), "report") {
		t.Fatalf("a file destination without the key marked: %s / %s", e.status(t), e.events(t))
	}
	os.WriteFile(word, []byte("name: Word\ntype: pandoc\nformat: docx\nmark_reported: true\n"), 0o644)
	e.follow(t, "alice", e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"word"}, "finding": {fdir}}, nil))
	if e.status(t) != "reported" {
		t.Fatalf("mark_reported: true did not mark: %s", e.status(t))
	}
}

// Q7: push destinations keep marking. The box of the editor stands for the
// kind of destination it was shown for (the hidden mark_for): a form shown
// for a file and saved as a service takes the service's default and marks,
// and the other way round. Shown for a service, the box is the user's.
func TestNewServiceDestinationMarks(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	dir := e.srv.Export.Dir
	marks := func(id string) (bool, bool) {
		es, _ := export.Load(dir)
		ex, ok := findExporter(es, id)
		return ex.Marks(), ok
	}
	file := func(id string) string {
		b, _ := os.ReadFile(filepath.Join(dir, id+".yaml"))
		return string(b)
	}
	save := func(name string, f url.Values) {
		t.Helper()
		if rec := e.do(t, "dora", "POST", "/e/acme/export/setup", f, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d\n%s", name, rec.Code, between(rec.Body.String(), `class="pstate error"`, "</span>"))
		}
	}
	// New destination, type jira, the box not touched: as the form posts it
	jira := url.Values{"new": {"1"}, "id": {"tracker"}, "name": {"Tracker"}, "type": {"jira"}, "base_url": {"https://jira.firm.example"},
		"project": {"PEN"}, "status": {"complete"}, "mark_for": {"file"}}
	save("new jira", jira)
	if m, ok := marks("tracker"); !ok || !m {
		t.Fatalf("a new jira destination saved from the untouched form does not mark (found %v):\n%s", ok, file("tracker"))
	}
	b := e.do(t, "dora", "GET", "/e/acme/export/setup", nil, nil).Body.String()
	if form := between(b, `<h2>New destination</h2>`, "</form>"); !strings.Contains(form, `<input type="hidden" name="mark_for" value="file">`) {
		t.Fatalf("the new destination's form:\n%s", form)
	}
	b = e.do(t, "dora", "GET", "/e/acme/export/setup?edit=tracker", nil, nil).Body.String()
	form := between(b, `<h2>Edit destination</h2>`, "</form>")
	if !strings.Contains(form, `<input type="hidden" name="mark_for" value="service">`) || !strings.Contains(form, `name="mark_reported" value="1" checked>Marks reported`) {
		t.Fatalf("the editor of the saved jira destination:\n%s", form)
	}
	// unticked in the form shown for a service: the user's choice
	jira.Del("new")
	jira.Set("mark_for", "service")
	save("jira unticked", jira)
	if m, _ := marks("tracker"); m {
		t.Fatalf("a jira destination unticked in its own form marks:\n%s", file("tracker"))
	}
	// the example of yars init: an HTML file without the key gets an address
	os.WriteFile(filepath.Join(dir, "wiki.yaml"), []byte("name: Wiki\ntype: confluence\n"), 0o644)
	b = e.do(t, "dora", "GET", "/e/acme/export/setup?edit=wiki", nil, nil).Body.String()
	form = between(b, `<h2>Edit destination</h2>`, "</form>")
	if !strings.Contains(form, `<input type="hidden" name="mark_for" value="file">`) || !strings.Contains(form, `name="mark_reported" value="1">Marks reported`) {
		t.Fatalf("the editor of the HTML file:\n%s", form)
	}
	save("wiki with an address", url.Values{"id": {"wiki"}, "name": {"Wiki"}, "type": {"confluence"}, "base_url": {"https://wiki.firm.example"},
		"space": {"PEN"}, "status": {"complete"}, "mark_for": {"file"}})
	if m, ok := marks("wiki"); !ok || !m {
		t.Fatalf("the HTML file turned into a push does not mark (found %v):\n%s", ok, file("wiki"))
	}
	// a service turned into a file: the file's default, whatever the box said
	save("wiki as a file", url.Values{"id": {"wiki"}, "name": {"Wiki"}, "type": {"pandoc"}, "format": {"docx"}, "status": {"complete"},
		"mark_for": {"service"}, "mark_reported": {"1"}})
	if m, ok := marks("wiki"); !ok || m {
		t.Fatalf("a service turned into a file marks (found %v):\n%s", ok, file("wiki"))
	}
	// a file ticked in its own form marks
	save("wiki ticked", url.Values{"id": {"wiki"}, "name": {"Wiki"}, "type": {"pandoc"}, "format": {"docx"}, "status": {"complete"},
		"mark_for": {"file"}, "mark_reported": {"1"}})
	if m, _ := marks("wiki"); !m {
		t.Fatalf("a file ticked in its own form does not mark:\n%s", file("wiki"))
	}
}

// The editor starts a new destination (a pandoc file) with Marks reported
// unticked, and saves it so.
func TestNewDestinationDoesNotMark(t *testing.T) {
	e := setupSerial(t)
	e.exporters(t, fakePandoc)
	b := e.do(t, "dora", "GET", "/e/acme/export/setup", nil, nil).Body.String()
	form := between(b, `<h2>New destination</h2>`, "</form>")
	if !strings.Contains(form, `<input type="checkbox" name="mark_reported" value="1">Marks reported`) {
		t.Fatalf("the new destination's form:\n%s", form)
	}
	// as the form posts it: an unticked box sends nothing
	rec := e.do(t, "dora", "POST", "/e/acme/export/setup", url.Values{"new": {"1"}, "id": {"odt"}, "name": {"ODT"}, "type": {"pandoc"}, "format": {"odt"}, "status": {"complete"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d", rec.Code)
	}
	es, _ := export.Load(e.srv.Export.Dir)
	if ex, ok := findExporter(es, "odt"); !ok || ex.Marks() {
		t.Fatalf("saved as %+v", ex)
	}
}
