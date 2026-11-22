package web

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"yars/internal/db"
	"yars/internal/workflow"
)

// cssWidth is the px width a one-line rule of style.css gives (selector as
// written; several such rules may share a line).
func cssWidth(t *testing.T, css, selector string) int {
	t.Helper()
	m := regexp.MustCompile(`(?m)(?:^|\} )` + regexp.QuoteMeta(selector) + ` \{ width: (\d+)px; \}`).FindStringSubmatch(css)
	if m == nil {
		t.Fatalf("style.css has no %s width", selector)
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// The inbox's action column holds its longest label: Mark reported is 83px
// of 13px Plex Sans 600 (measured at 1440 x 900), so its sm button (12px
// padding and a 1px border each side) needs 109px; a w104 button let it run
// into the padding to the border. Every row's action has the one width (no
// queue's column differs), and the column is that width plus its 8px and
// 20px padding.
func TestInboxActionFitsMarkReported(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	st := e.srv.Store
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", fdir, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
	st.DB().AddNotification(db.Notification{User: "dora", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "bob", Text: "@dora a look?"})
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	acts := regexp.MustCompile(`<td class="c-go"><(?:a|button) class="btn (?:primary|secondary) sm (w\d+)"[^>]*>([^<]+)<`).FindAllStringSubmatch(b, -1)
	labels := map[string]bool{}
	for _, a := range acts {
		labels[a[2]] = true
		if a[1] != acts[0][1] {
			t.Errorf("%s is %s, %s is %s", a[2], a[1], acts[0][2], acts[0][1])
		}
	}
	if !labels["Mark reported"] || !labels["Open"] {
		t.Fatalf("actions %v:\n%s", labels, b)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	w := cssWidth(t, css, "."+acts[0][1])
	if w < 83+2*12+2*1 {
		t.Errorf("Mark reported (83px) in a %dpx sm button", w)
	}
	if col := cssWidth(t, css, ".table.inboxt .c-go"); col != w+8+20 {
		t.Errorf("action column %dpx for a %dpx button", col, w)
	}
}

// An inbox row's who · what has its dot only between the two: a notice
// without text (Approved) shows who did it, not "dora · ".
func TestInboxWhoWithoutWhat(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	d.AddNotification(db.Notification{User: "alice", Event: "approved", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "dora"})
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "SQL injection", Actor: "bob", Text: "a look?"})
	sec := notesSection(t, e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String())
	for _, want := range []string{`<td class="c-what" title="dora"><strong>dora</strong></td>`,
		`<td class="c-what" title="bob · a look?"><strong>bob</strong> · a look?</td>`} {
		if !strings.Contains(sec, want) {
			t.Errorf("section lacks %s:\n%s", want, sec)
		}
	}
}
