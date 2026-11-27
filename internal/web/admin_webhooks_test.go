package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/webhook"
)

type hookSink struct {
	mu    sync.Mutex
	codes []int
	got   []string
	sigs  []string
	ts    []int64  // X-YARS-Timestamp
	evs   []string // X-YARS-Event
}

func (h *hookSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.got = append(h.got, string(b))
	h.sigs = append(h.sigs, r.Header.Get("X-YARS-Signature"))
	ts, _ := strconv.ParseInt(r.Header.Get("X-YARS-Timestamp"), 10, 64)
	h.ts = append(h.ts, ts)
	h.evs = append(h.evs, r.Header.Get("X-YARS-Event"))
	code := 200
	if len(h.codes) > 0 {
		code, h.codes = h.codes[0], h.codes[1:]
	}
	h.mu.Unlock()
	w.WriteHeader(code)
}

// Sending to a destination is an export.sent event; marking the finding
// reported on the way is a status change. Downloads send nothing.
func TestExportSentEvent(t *testing.T) {
	e := setupSerial(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	var mu sync.Mutex
	var got []store.Event
	e.srv.Store.OnEvent(func(ev store.Event) { mu.Lock(); got = append(got, ev); mu.Unlock() })
	e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {fdir}}, nil)
	mu.Lock()
	defer mu.Unlock()
	var kinds []string
	for _, ev := range got {
		kinds = append(kinds, ev.Kind)
	}
	if strings.Join(kinds, ",") != "finding.status_changed,export.sent" {
		t.Fatalf("events %v", kinds)
	}
	if ex := got[1]; ex.Destination != "docx" || !ex.OK || ex.Actor != "alice" || len(ex.Findings) != 1 || ex.Findings[0] != "F-001" {
		t.Fatalf("%+v", ex)
	}
	if st := got[0]; st.Action != "report" || st.To != "reported" || st.Destination == "" {
		t.Fatalf("%+v", st)
	}
}

func TestAdminWebhooks(t *testing.T) {
	e := setup(t)
	sink := &hookSink{codes: []int{500}}
	srv := httptest.NewServer(sink)
	defer srv.Close()

	// admin only
	for _, p := range []string{"/admin/webhooks"} {
		if rec := e.do(t, "bob", "GET", p, nil, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("%s for bob: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "bob", "POST", "/admin/webhooks", url.Values{"url": {srv.URL}, "event": {"chat.posted"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("create by bob: %d", rec.Code)
	}
	// bad input is shown, nothing stored
	rec := e.do(t, "dora", "POST", "/admin/webhooks", url.Values{"url": {"ftp://x"}, "event": {"chat.posted"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "http or https") {
		t.Fatalf("bad url %d", rec.Code)
	}
	// created: the secret is shown once
	rec = e.do(t, "dora", "POST", "/admin/webhooks", url.Values{"url": {srv.URL + "/hook"}, "event": {"chat.posted", "finding.status_changed"}}, nil)
	secRe := regexp.MustCompile(`whsec_[0-9a-f]{48}`)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/admin/webhooks?hook=") ||
		secRe.MatchString(rec.Header().Get("Location")) || secRe.MatchString(rec.Body.String()) {
		t.Fatalf("create %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Activity lists its events as the other lists there read: "a, b"
	if log, _ := e.srv.Store.DB().AuditLog(1); len(log) != 1 || log[0].Action != "webhook.add" || log[0].Detail != "finding.status_changed, chat.posted" {
		t.Fatalf("audit %+v", log)
	}
	first := e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil)
	sec := secRe.FindString(first.Body.String())
	if sec == "" || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret not shown after the redirect")
	}
	b := e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil).Body.String()
	if secRe.MatchString(b) {
		t.Fatal("secret shown on the second visit")
	}
	b = e.do(t, "dora", "GET", "/admin/webhooks", nil, nil).Body.String()
	if strings.Contains(b, sec) || !strings.Contains(b, "…"+sec[len(sec)-4:]) || !strings.Contains(b, srv.URL+"/hook") || !strings.Contains(b, "<thead>") {
		t.Fatal("list shows the secret or lacks the hook")
	}
	if strings.Contains(b, ` style="`) {
		t.Fatal("inline style")
	}
	hooks, _ := e.srv.Store.DB().Webhooks()
	if len(hooks) != 1 {
		t.Fatalf("hooks %+v", hooks)
	}
	id := strconv.FormatInt(hooks[0].ID, 10)

	// an event is delivered, signed; the first try fails, Redeliver resends
	rec = e.do(t, "bob", "POST", "/e/acme/f/001/chat", url.Values{"text": {"hello"}}, map[string]string{"HX-Request": "true"})
	if rec.Code >= 300 {
		t.Fatalf("chat %d", rec.Code)
	}
	if _, err := e.srv.Webhooks.RunDue(); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	if len(sink.got) != 1 || !strings.Contains(sink.got[0], `"event":"chat.posted"`) || sink.ts[0] == 0 || sink.sigs[0] != webhook.Sign(sec, sink.ts[0], []byte(sink.got[0])) {
		t.Fatalf("delivery %v %v", sink.got, sink.sigs)
	}
	sink.mu.Unlock()
	b = e.do(t, "dora", "GET", "/admin/webhooks?hook="+id, nil, nil).Body.String()
	if !strings.Contains(b, "500") || !strings.Contains(b, "Redeliver") {
		t.Fatal("delivery status not listed")
	}
	dl, _ := e.srv.Store.DB().Deliveries(hooks[0].ID, 1)
	rec = e.do(t, "dora", "POST", "/admin/webhooks/deliveries/"+strconv.FormatInt(dl[0].ID, 10)+"/redeliver", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("redeliver %d", rec.Code)
	}
	e.srv.Webhooks.RunDue()
	if last, _ := e.srv.Store.DB().LastDeliveries(); last[hooks[0].ID].State != db.DeliveryOK {
		t.Fatalf("after redeliver %+v", last)
	}

	// edit: URL and events; the toggle turns it off
	rec = e.do(t, "dora", "POST", "/admin/webhooks/"+id, url.Values{"url": {srv.URL + "/v2"}, "event": {"export.sent"}, "enabled": {"1"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("edit %d %s", rec.Code, rec.Body)
	}
	if h, _, _ := e.srv.Store.DB().WebhookByID(hooks[0].ID); h.URL != srv.URL+"/v2" || len(h.Events) != 1 || !h.Enabled {
		t.Fatalf("%+v", h)
	}
	e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/toggle", url.Values{}, nil)
	if h, _, _ := e.srv.Store.DB().WebhookByID(hooks[0].ID); h.Enabled {
		t.Fatal("still enabled")
	}
	e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/delete", url.Values{}, nil)
	if l, _ := e.srv.Store.DB().Webhooks(); len(l) != 0 {
		t.Fatal("not deleted")
	}
}
