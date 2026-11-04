package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/store"
	"yars/internal/workflow"
)

func TestNewRetestFlow(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.srv.Store.CreateFinding("acme", "Open redirect", e.authorOf(wAlice))
	if rec := e.do(t, "alice", "GET", "/e/acme/retest/new", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester form code %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/e/acme/retest/new", nil, nil).Body.String()
	// the complete finding is pre-selected, the draft isn't
	if !strings.Contains(b, `id="pick-F-001-sql-injection" checked`) || strings.Contains(b, `id="pick-F-002-open-redirect" checked`) {
		t.Fatalf("form selection:\n%s", b)
	}
	if !strings.Contains(b, `value="acme-retest"`) {
		t.Fatal("id not prefilled")
	}
	form := url.Values{"id": {"acme-rt"}, "name": {"ACME retest"}, "finding": {"F-001-sql-injection", "F-002-open-redirect"}}
	rec := e.do(t, "dora", "POST", "/e/acme/retest/new", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme-rt" {
		t.Fatalf("code %d loc %q body %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	b = e.do(t, "alice", "GET", "/e/acme-rt", nil, nil).Body.String()
	if !strings.Contains(b, "Retest of") || !strings.Contains(b, `href="/e/acme"`) || !strings.Contains(b, "Open redirect") || !strings.Contains(b, "<th><a") || !strings.Contains(b, ">Result") {
		t.Fatalf("retest engagement page:\n%s", b)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/retest/new", url.Values{"id": {"x"}, "name": {"X"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty selection code %d", rec.Code)
	}
}

func TestRetestPanel(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, wDora); err != nil {
		t.Fatal(err)
	}
	p := "/e/rt/f/F-001-sql-injection"
	b := e.do(t, "alice", "GET", p, nil, nil).Body.String()
	if !strings.Contains(b, `id="retest"`) || !strings.Contains(b, `href="/e/acme/f/F-001-sql-injection"`) {
		t.Fatalf("retest panel missing:\n%s", b)
	}
	rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"partially_fixed"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `value="partially_fixed" checked`) {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "alice", "POST", p+"/retest", url.Values{"result": {"maybe"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid result code %d", rec.Code)
	}
	if b := e.do(t, "alice", "GET", "/e/rt", nil, nil).Body.String(); !strings.Contains(b, "Partially fixed") {
		t.Fatal("table lacks result pill")
	}
	// the original finding page has no retest panel
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `id="retest"`) {
		t.Fatal("retest panel on original")
	}
}

func TestRetestPanelLocked(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sql-injection"}, wDora)
	d := "F-001-sql-injection"
	st.SetRetestResult("rt", d, "fixed", wDora)
	st.SetReviewers("rt", d, []string{"bob"}, wDora)
	st.UpdateSeverity("rt", d, "high", "", wDora)
	if err := st.Transition("rt", d, workflow.Submit, "", wDora); err != nil {
		t.Fatal(err)
	}
	st.Transition("rt", d, workflow.Clear, "", wBob)
	if err := st.Transition("rt", d, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "POST", "/e/rt/f/"+d+"/retest", url.Values{"result": {"not_fixed"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("locked code %d", rec.Code)
	}
}
