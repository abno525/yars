package web

import (
	"strings"
	"testing"

	"yars/internal/config"
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

// Long user names end in "…" where they do not fit, rather than losing
// their start (the header), running past their cell (Reviewers on the
// findings list), being cut without one (a reviewer tag on a narrow finding
// row) or pushing the host out of a lead's head (the team board).
func TestLongNamesFit(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.SetReviewers("acme", "F-001-sql-injection", []string{"bob"}, config.User{Username: "alice", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	row := b[strings.Index(b, "F-001"):]
	row = row[:strings.Index(row, "</tr>")]
	if !strings.Contains(row, `<td class="revs"><span class="rvs"><span class="rv" title="bob"><span class="name">bob</span></span></span></td>`) {
		t.Fatalf("reviewers cell:\n%s", row)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		"a.who { height: 64px; display: block; line-height: 64px;",
		".rvs { display: flex; gap: 14px; min-width: 0; overflow: hidden; }",
		".rv .name { min-width: 0; overflow: hidden; text-overflow: ellipsis; }",
		"width: 160px; height: 28px; padding: 0 10px; flex: 0 1 auto; min-width: 0;",
		".tbby { flex: 0 1 auto; min-width: 0; max-width: 40%; display: flex; white-space: pre; }",
		".tbby strong { min-width: 0; overflow: hidden; text-overflow: ellipsis;",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %q", want)
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
