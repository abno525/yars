package web

import (
	"strings"
	"testing"
)

// The page shell: new header, theme toggle, toast area, no inline styles.
func TestShellHeader(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/e/acme", fpath, "/inbox", "/e/acme/export", "/e/acme/findings/new"} {
		b := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		for _, want := range []string{`class="topbar"`, `class="logo"`, `id="toasts"`, `data-theme-toggle`, `class="btn ghost w96 logout"`, `class="who"`} {
			if !strings.Contains(b, want) {
				t.Fatalf("%s lacks %s:\n%s", p, want, b)
			}
		}
		if strings.Contains(b, ` style="`) || strings.Contains(b, "<style") {
			t.Fatalf("%s has inline styles", p)
		}
		if strings.Contains(b, "fonts.googleapis") {
			t.Fatalf("%s loads remote fonts", p)
		}
	}
	// the inbox count keeps its place: a black 0 when nothing waits
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, `class="badge0">0<`) {
		t.Fatal("no zero badge in the nav")
	}
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); strings.Contains(b, ` style="`) || !strings.Contains(b, `class="logo big"`) {
		t.Fatalf("login page:\n%s", b)
	}
}

// The header's right side runs Go to, theme, bell, user name, Log out.
// Developers is reached from the user name (Settings), not the top bar,
// so its pages light the user name.
func TestShellHeaderOrder(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/docs/mcp"} {
		b := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		i := strings.Index(b, `<header class="topbar">`)
		j := strings.Index(b, `</header>`)
		if i < 0 || j < i {
			t.Fatalf("%s: no header:\n%s", p, b)
		}
		head := b[i:j]
		if strings.Contains(head, `href="/docs`) || strings.Contains(head, "Developers") {
			t.Fatalf("%s: Developers in the top bar:\n%s", p, head)
		}
		last := -1
		for _, want := range []string{`data-goto`, `data-theme-toggle`, `class="bell`, `class="who`, `logout`} {
			k := strings.Index(head, want)
			if k <= last {
				t.Fatalf("%s: %s out of order (at %d, after %d):\n%s", p, want, k, last, head)
			}
			last = k
		}
		if on := strings.Contains(head, `class="who on"`); on != (p == "/docs/mcp") {
			t.Fatalf("%s: user name lit %v:\n%s", p, on, head)
		}
	}
}

// Status and severity render as fixed-size tags; empty chat counts show 0.
func TestShellTags(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	tbl := b[strings.Index(b, `id="findings"`):]
	for _, want := range []string{`class="tag status-draft"`, `class="badge0">0<`, `class="seg`, `class="table`} {
		if !strings.Contains(tbl, want) {
			t.Fatalf("findings lack %s:\n%s", want, tbl)
		}
	}
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `class="titlerow"`) || !strings.Contains(b, `class="tag status-draft"`) {
		t.Fatalf("finding head:\n%s", b)
	}
}

func TestShellAssets(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		"--navy: #13233F", "--accent: #F26B1D", "@media (prefers-color-scheme: dark)",
		`:root:not([data-theme="light"])`, `:root[data-theme="dark"]`,
		".btn", ".btn.primary", ".btn.secondary", ".btn.ghost", ".btn.danger", ".btn.sm",
		".w96", ".w112", ".w128", ".w136", ".w152", ".tag", ".status-verification", ".sev-critical",
		".badge0", ".seg", ".panel", ".panelhead", ".table", ".slot", ".titlerow", ".topbar", "#toasts",
		"Bungee", "IBM Plex Sans", "IBM Plex Mono",
	} {
		if !strings.Contains(css, want) {
			t.Fatalf("style.css lacks %q", want)
		}
	}
	if strings.Contains(css, "fonts.googleapis") || strings.Contains(css, "border-radius: 8px") {
		t.Fatal("style.css: remote fonts or rounded corners")
	}
	// pages run up to 1760 px wide; the finding page's side column is 560
	for _, want := range []string{"main { max-width: 1760px;", ".finding-grid { display: grid; grid-template-columns: minmax(0, 1fr) 560px;"} {
		if !strings.Contains(css, want) {
			t.Fatalf("style.css lacks %q", want)
		}
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, want := range []string{"htmx:responseError", "toasts", "localStorage", "data-theme", "try"} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js lacks %q", want)
		}
	}
}
