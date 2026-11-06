package web

import (
	"net/url"
	"strings"
	"testing"
)

// Once every assigned reviewer has signed off, a verification finding shows
// as signed off: its tag, its own filter segment between verification and
// complete, a step of its own in the bar, the inbox and the board counts.
func TestSignedOffShown(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	before := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	for _, want := range []string{`>Verification · 1</a>`, `>Signed off · 0</a>`, `class="tag status-verification">verification<`} {
		if !strings.Contains(before, want) {
			t.Fatalf("before sign-off lacks %s:\n%s", want, before)
		}
	}
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	if got := e.status(t); got != "verification" {
		t.Fatalf("stored status %q", got)
	}

	b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	for _, want := range []string{`class="tag status-signed-off">signed off<`, `>Verification · 0</a>`, `>Signed off · 1</a>`,
		`href="/e/acme?status=signed-off"`, `<span class="lgname">Signed off</span>`, `<span class="lgname">Verification</span>`, `class="seg-signed-off"`} {
		if !strings.Contains(b, want) {
			t.Fatalf("list lacks %s:\n%s", want, b)
		}
	}
	// segments in order: verification, signed off, complete
	v, so, c := strings.Index(b, `>Verification · `), strings.Index(b, `>Signed off · `), strings.Index(b, `>Complete · `)
	if !(v < so && so < c) {
		t.Fatalf("segment order %d %d %d", v, so, c)
	}
	if f := e.do(t, "dora", "GET", "/e/acme?status=signed-off", nil, nil).Body.String(); !strings.Contains(f, `href="/e/acme/f/001"`) {
		t.Fatalf("signed off filter misses the finding:\n%s", f)
	}
	if f := e.do(t, "dora", "GET", "/e/acme?status=verification", nil, nil).Body.String(); strings.Contains(f, `href="/e/acme/f/001"`) {
		t.Fatalf("verification filter still lists it:\n%s", f)
	}

	page := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	wf := wfSection(t, page)
	for _, want := range []string{`<li class="step done">verification</li>`, `<li class="step current">signed off</li>`, `<li class="step">complete</li>`} {
		if !strings.Contains(wf, want) {
			t.Fatalf("step bar lacks %s:\n%s", want, wf)
		}
	}
	if !strings.Contains(page, `<span class="tag status-signed-off">signed off</span>`) {
		t.Fatalf("finding head tag:\n%s", page)
	}

	in := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(in, `class="tag status-signed-off">signed off<`) {
		t.Fatalf("inbox tag:\n%s", in)
	}

	// approved: the signed off step is past
	e.do(t, "dora", "POST", fpath+"/action/approve", url.Values{}, nil)
	wf = wfSection(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(wf, `<li class="step done">signed off</li>`) || !strings.Contains(wf, `<li class="step current">complete</li>`) {
		t.Fatalf("complete step bar:\n%s", wf)
	}
}
