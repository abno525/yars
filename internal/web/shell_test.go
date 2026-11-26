package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
)

// The page shell: new header, toast area, no inline styles.
func TestShellHeader(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/e/acme", fpath, "/inbox", "/e/acme/export", "/e/acme/findings/new"} {
		b := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		for _, want := range []string{`class="topbar"`, `class="logo"`, `id="toasts"`, `class="btn ghost w96 logout"`, `class="who"`} {
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

// The header's right side runs user name, Go to, Log out. Developers and the
// theme are reached from the user name (Settings), not the top bar, so the
// Developers pages light the user name; the notices are in the inbox (no
// bell).
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
		if strings.Contains(head, "data-theme-toggle") || strings.Contains(head, "Theme") {
			t.Fatalf("%s: a theme button in the top bar:\n%s", p, head)
		}
		if strings.Contains(head, `class="bell`) || strings.Contains(head, `href="/notifications"`) {
			t.Fatalf("%s: a bell in the top bar:\n%s", p, head)
		}
		last := -1
		for _, want := range []string{`class="who`, `data-goto`, `logout`} {
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
	// the theme is chosen in Settings › Preferences only; the button's script
	// is gone with it
	if b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `role="radiogroup" aria-label="Theme"`) {
		t.Error("Settings has no theme choice")
	}
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); strings.Contains(js, "yarsTheme") || strings.Contains(js, "data-theme-toggle") {
		t.Error("app.js keeps the theme button's code")
	}
}

// A page outside any engagement (the inbox, Settings, Admin) keeps the
// engagement last opened in this browser: the picker shows it (on a hidden
// option of its own, so picking it opens it) and Findings (f) goes to its
// list. One the user cannot see is not kept; logging out forgets it.
func TestLastEngagementKept(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	rec := e.do(t, "alice", "GET", "/e/acme", nil, nil)
	var kc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yars_eng" {
			kc = c
		}
	}
	if kc == nil || kc.Value != "acme" || !kc.HttpOnly || kc.SameSite != http.SameSiteLaxMode || kc.Path != "/" {
		t.Fatalf("no engagement cookie: %+v", kc)
	}
	kept := map[string]string{"Cookie": "yars_eng=acme"}
	for _, p := range []string{"/inbox", "/settings", "/"} {
		b := e.do(t, "alice", "GET", p, nil, kept).Body.String()
		head := between(b, `<header class="topbar">`, "</header>")
		for _, w := range []string{`<option value="acme" selected hidden>`, `<a class="`, `href="/e/acme" aria-keyshortcuts="F">Findings</a>`} {
			if !strings.Contains(head, w) {
				t.Errorf("%s: header lacks %s:\n%s", p, w, head)
			}
		}
		if strings.Contains(head, `<option value="">Engagement</option>`) {
			t.Errorf("%s: the picker shows no engagement", p)
		}
	}
	// the inbox is still the inbox's page, not the engagement's
	if b := e.do(t, "alice", "GET", "/inbox", nil, kept).Body.String(); !strings.Contains(b, "<title>YARS</title>") {
		t.Error("the kept engagement names the inbox's tab")
	}
	// none kept: the placeholder, and f still goes to Findings
	if head := between(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), `<header class="topbar">`, "</header>"); !strings.Contains(head, `<option value="">Engagement</option>`) || !strings.Contains(head, `href="/" aria-keyshortcuts="F">Findings</a>`) {
		t.Errorf("no kept engagement:\n%s", head)
	}
	// eve is not on acme's team: nothing kept for her
	if head := between(e.do(t, "eve", "GET", "/inbox", nil, kept).Body.String(), `<header class="topbar">`, "</header>"); strings.Contains(head, "/e/acme") {
		t.Errorf("an engagement eve cannot see:\n%s", head)
	}
	if c := e.do(t, "alice", "POST", "/logout", url.Values{}, kept).Header().Values("Set-Cookie"); !strings.Contains(strings.Join(c, "\n"), "yars_eng=; Path=/; Max-Age=0") {
		t.Errorf("logout keeps the engagement: %q", c)
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
		// a short reviewer beside a long one keeps a letter and its "…"
		".rv { display: inline-flex; align-items: center; gap: 6px; min-width: 48px;",
		".tbby, .tbwho { flex: 0 1 auto; min-width: 0; max-width: 40%; display: flex; align-items: baseline; white-space: pre; }",
		".tbby strong { min-width: 0; overflow: hidden; text-overflow: ellipsis;",
		".slot.pres strong { flex: 0 1 auto; min-width: 0; overflow: hidden; text-overflow: ellipsis;",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %q", want)
		}
	}
	// the other names that can run long end in "…" and show in full on hover:
	// who is editing, the new-password page, a lead's head and its strips
	for _, c := range [][2]string{
		{"templates/assets.html", `<strong title="{{.Who}}">{{.Who}}</strong>`},
		{"templates/password.html", `<span class="mono muted clip" title="{{.User.Username}}">`},
		{"templates/team_board.html", `<span class="tbby"><strong title="{{.By}}">{{.By}}</strong>`},
		{"templates/team_board.html", `<span class="tbwho"><span class="clip" title="{{.User}}">{{.User}}</span> · `},
	} {
		src, err := templateFS.ReadFile(c[0])
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), c[1]) {
			t.Errorf("%s lacks %s", c[0], c[1])
		}
	}
}

// The user name is a tab like the nav's: as wide as the name with 12px on
// each side, so when lit (Settings, Developers) its underline is under the
// name, not under a 120px slot with the name at its right end. Up to 120px
// of name shows; a longer one still ends in "…".
func TestUserTabFitsName(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	rule := between(css, "\n.who {", "}")
	for _, want := range []string{"max-width: 144px;", "padding: 0 12px;", "flex: none;", "overflow: hidden; text-overflow: ellipsis;"} {
		if !strings.Contains(rule, want) {
			t.Errorf(".who lacks %q: %q", want, rule)
		}
	}
	if strings.Contains(rule, " width: 120px") || strings.Contains(rule, "text-align: right") {
		t.Errorf(".who keeps its 120px right-aligned slot: %q", rule)
	}
	if nav := between(css, "\n.nav a { padding:", "}"); !strings.Contains(nav, "0 12px") {
		t.Errorf("the nav tabs' padding changed: %q", nav)
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

// The vendored fonts and htmx travel with their licence texts: the OFL
// asks for the copyright line and the licence in each copy.
func TestStaticCarriesLicences(t *testing.T) {
	e := setup(t)
	for path, wants := range map[string][]string{
		"/static/fonts/OFL-IBM-Plex.txt": {`IBM Corp. with Reserved Font Name "Plex"`, "SIL OPEN FONT LICENSE Version 1.1"},
		"/static/fonts/OFL-Bungee.txt":   {"The Bungee Project Authors", "SIL OPEN FONT LICENSE Version 1.1"},
		"/static/htmx.LICENSE.txt":       {"Zero-Clause BSD", "htmx 2.0.4"},
	} {
		rec := e.do(t, "alice", "GET", path, nil, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: %d", path, rec.Code)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(rec.Body.String(), w) {
				t.Errorf("%s lacks %q", path, w)
			}
		}
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
