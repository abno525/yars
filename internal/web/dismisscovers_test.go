package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// The Dismissed table says how many matches a dismissal covers, in the cell
// that names who dismissed it: the cell is in every row, so nothing moves
// (pre1 7.9).
func TestDismissedRowShowsWhatItCovers(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: letter-i\n  level: warning\n  target: title\n  regex_forbid: 'i'\n  message: no letter i\n", nil)
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	n := strings.Count(ref.F.Meta.Title, "i")
	if n < 2 {
		t.Fatalf("the title %q has the letter %d times: the test needs two", ref.F.Meta.Title, n)
	}
	form := url.Values{"rule": {"letter-i"}, "target": {"title"}, "quote": {"i"}, "reason": {"fine"}}
	if rec := e.do(t, "dora", "POST", fpath+"/checks/dismiss", form, nil); rec.Code != http.StatusOK {
		t.Fatalf("dismiss %d\n%s", rec.Code, rec.Body.String())
	}
	panel := checksPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	for _, want := range []string{`<th class="c-where">Covers · By</th>`, `>` + strconv.Itoa(n) + ` · dora</td>`} {
		if !strings.Contains(panel, want) {
			t.Fatalf("the panel lacks %s:\n%s", want, panel)
		}
	}
	// a posted number is not taken: the server counts
	form.Set("covers", "99")
	e.do(t, "dora", "POST", fpath+"/checks/dismiss", form, nil)
	if panel := checksPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(panel, `>`+strconv.Itoa(n)+` · dora</td>`) {
		t.Fatalf("a posted count was taken:\n%s", panel)
	}
}
