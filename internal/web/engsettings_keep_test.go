package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

// The Settings form posts all four values every time. A pushed
// engagement.yaml keeps its comments and its other keys through a save, and
// one the form cannot rewrite is refused with words on the page.
func TestEngagementSettingsSaveKeepsPushedLines(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "engagements", "acme", "engagement.yaml")
	push := func(text string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		er, _ := e.srv.Store.EngRepo("acme")
		if err := er.Commit([]string{"engagement.yaml"}, "pushed", gitrepo.Author{Name: "dora", Email: "dora@yars.local"}); err != nil {
			t.Fatal(err)
		}
		e.srv.Store.Invalidate("acme")
	}
	const hand = "# delivery notes\nname: ACME Web\nclient: ACME # billed monthly\nscope:\n    - app.example\ntype: pentest\n"
	push(hand)
	form := url.Values{"name": {"ACME Web"}, "client": {"ACME"}, "start": {"2026-01-05"}, "end": {""}}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d:\n%s", rec.Code, rec.Body.String())
	}
	b, _ := os.ReadFile(p)
	if string(b) != hand+"start: \"2026-01-05\"\n" {
		t.Fatalf("the save rewrote the file:\n%s", b)
	}

	const flow = "{name: ACME Web, client: ACME, type: pentest}\n"
	push(flow)
	form.Set("name", "Other")
	rec := e.do(t, "dora", "POST", "/e/acme/settings", form, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "one key per line") {
		t.Fatalf("flow style %d:\n%s", rec.Code, rec.Body.String())
	}
	if b, _ := os.ReadFile(p); string(b) != flow {
		t.Fatalf("the refused save changed the file:\n%s", b)
	}
}
