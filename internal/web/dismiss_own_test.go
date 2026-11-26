package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

// Standard workflow: on his own finding a reviewer gets no Dismiss button
// for an error (the row keeps the button's slot) and the POST is refused;
// a warning's button is there. On a colleague's finding he has both. A
// director's own finding is the same (pre1 2.31, Q6).
func TestOwnErrorHasNoDismiss(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"warn","quote":"q"}]'` + "\n"})
	const own = "an error on your own finding is dismissed by another reviewer or a director"
	for _, author := range []string{"bob", "dora"} {
		ref, err := e.srv.Store.CreateFinding("acme", "Blind injection by "+author, gitrepo.Author{Name: author})
		if err != nil {
			t.Fatal(err)
		}
		path := findingURL("acme", ref.Dir)
		e.do(t, author, "POST", path+"/checks", url.Values{}, nil)
		e.srv.Store.WaitChecks()
		// the author: the warning's Dismiss only, the error's slot empty
		p := e.do(t, author, "GET", path+"/checks", nil, nil).Body.String()
		if strings.Count(p, "data-dismiss-toggle") != 1 || strings.Contains(p, ">Dismiss error</button>") || !strings.Contains(p, `<span class="slot w96"></span>`) {
			t.Fatalf("%s on their own finding:\n%s", author, p)
		}
		form := url.Values{"rule": {"title-word"}, "quote": {"injection"}, "reason": {"it is fine"}}
		rec := e.do(t, author, "POST", path+"/checks/dismiss", form, nil)
		if rec.Code != 403 || !strings.Contains(rec.Body.String(), own) {
			t.Fatalf("%s dismissed the error on their own finding: %d %s", author, rec.Code, rec.Body.String())
		}
		// another person with the role: both buttons, and the dismissal lands
		other := map[string]string{"bob": "dora", "dora": "bob"}[author]
		if p := e.do(t, other, "GET", path+"/checks", nil, nil).Body.String(); strings.Count(p, "data-dismiss-toggle") != 2 || !strings.Contains(p, ">Dismiss error</button>") {
			t.Fatalf("%s on %s's finding:\n%s", other, author, p)
		}
		if rec := e.do(t, other, "POST", path+"/checks/dismiss", form, nil); rec.Code != 200 {
			t.Fatalf("%s on %s's finding: %d %s", other, author, rec.Code, rec.Body.String())
		}
		// the dismissed row has no Restore for the author, and the POST is refused
		p = e.do(t, author, "GET", path+"/checks", nil, nil).Body.String()
		if i := strings.Index(p, `<details class="dismissed"`); i < 0 || strings.Contains(p[i:], ">Restore</button>") {
			t.Fatalf("%s restores on their own finding:\n%s", author, p)
		}
		if rec := e.do(t, author, "POST", path+"/checks/undismiss", form, nil); rec.Code != 403 {
			t.Fatalf("%s restored the error on their own finding: %d", author, rec.Code)
		}
	}
}
