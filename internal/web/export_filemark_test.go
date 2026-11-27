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
