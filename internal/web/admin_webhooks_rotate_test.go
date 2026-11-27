package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/webhook"
)

// hookWith adds a webhook to sink for chat.posted as dora and returns its id
// and its secret.
func (e *env) hookWith(t *testing.T, srvURL string) (int64, string) {
	t.Helper()
	rec := e.do(t, "dora", "POST", "/admin/webhooks", url.Values{"url": {srvURL + "/hook"}, "event": {"chat.posted"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d", rec.Code)
	}
	sec := regexp.MustCompile(`whsec_[0-9a-f]{48}`).FindString(e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil).Body.String())
	hooks, _ := e.srv.Store.DB().Webhooks()
	if sec == "" || len(hooks) != 1 {
		t.Fatalf("secret %q hooks %+v", sec, hooks)
	}
	return hooks[0].ID, sec
}

// New secret gives a webhook another secret in place: it is shown once, the
// deliveries stay listed, and the next delivery is signed with it.
func TestWebhookRotateSecret(t *testing.T) {
	e := setup(t)
	sink := &hookSink{}
	srv := httptest.NewServer(sink)
	defer srv.Close()
	hid, old := e.hookWith(t, srv.URL)
	id := strconv.FormatInt(hid, 10)
	d := e.srv.Store.DB()
	chat := func() {
		t.Helper()
		if rec := e.do(t, "bob", "POST", "/e/acme/f/001/chat", url.Values{"text": {"hello"}}, map[string]string{"HX-Request": "true"}); rec.Code >= 300 {
			t.Fatalf("chat %d", rec.Code)
		}
		if _, err := e.srv.Webhooks.RunDue(); err != nil {
			t.Fatal(err)
		}
	}
	chat()

	if rec := e.do(t, "bob", "POST", "/admin/webhooks/"+id+"/rotate", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("rotate by bob: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/webhooks/999/rotate", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("rotate of no webhook: %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/rotate", url.Values{}, nil)
	secRe := regexp.MustCompile(`whsec_[0-9a-f]{48}`)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/webhooks?hook="+id || secRe.MatchString(rec.Body.String()) {
		t.Fatalf("rotate %d %q", rec.Code, rec.Header().Get("Location"))
	}
	first := e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil)
	sec := secRe.FindString(first.Body.String())
	if sec == "" || sec == old || first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("the new secret is not shown once: %q", sec)
	}
	b := e.do(t, "dora", "GET", rec.Header().Get("Location"), nil, nil).Body.String()
	if secRe.MatchString(b) {
		t.Fatal("the secret is shown on the second visit")
	}
	// the list has the new ending, and the old delivery is still there
	if !strings.Contains(b, "…"+sec[len(sec)-4:]) || !strings.Contains(b, "chat.posted</td>") {
		t.Fatal("the list lacks the new ending or the old delivery")
	}
	if dl, _ := d.Deliveries(hid, 10); len(dl) != 1 || dl[0].State != db.DeliveryOK {
		t.Fatalf("deliveries after the rotation: %+v", dl)
	}
	log, _ := d.AuditLog(1)
	if len(log) != 1 || log[0].Action != "webhook.rotate" || log[0].Actor != "dora" || strings.Contains(log[0].Target+log[0].Detail, "whsec_") {
		t.Fatalf("audit %+v", log)
	}
	// the next delivery verifies with the new secret, not with the old one
	chat()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) != 2 {
		t.Fatalf("deliveries %d", len(sink.got))
	}
	if sink.sigs[1] != webhook.Sign(sec, sink.ts[1], []byte(sink.got[1])) || sink.sigs[1] == webhook.Sign(old, sink.ts[1], []byte(sink.got[1])) {
		t.Fatal("the delivery after the rotation is not signed with the new secret")
	}
}

// Send test queues one delivery of the event ping: signed, listed, through
// the same send. A failed one does not count towards the switch-off.
func TestWebhookTestDelivery(t *testing.T) {
	e := setup(t)
	sink := &hookSink{codes: []int{204, 500}}
	srv := httptest.NewServer(sink)
	defer srv.Close()
	hid, sec := e.hookWith(t, srv.URL)
	id := strconv.FormatInt(hid, 10)
	d := e.srv.Store.DB()

	if rec := e.do(t, "bob", "POST", "/admin/webhooks/"+id+"/test", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("test by bob: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/webhooks/999/test", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("test of no webhook: %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/test", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/webhooks?hook="+id {
		t.Fatalf("test %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := e.srv.Webhooks.RunDue(); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	if len(sink.got) != 1 || sink.evs[0] != "ping" || !strings.Contains(sink.got[0], `"event":"ping"`) || !strings.Contains(sink.got[0], `"id":"evt_`) ||
		sink.sigs[0] != webhook.Sign(sec, sink.ts[0], []byte(sink.got[0])) {
		t.Fatalf("test delivery %v %v", sink.got, sink.evs)
	}
	// nothing of a finding is in it
	if strings.Contains(sink.got[0], "finding") || strings.Contains(sink.got[0], "acme") {
		t.Fatalf("the test payload holds data: %s", sink.got[0])
	}
	sink.mu.Unlock()
	b := e.do(t, "dora", "GET", "/admin/webhooks?hook="+id, nil, nil).Body.String()
	if !strings.Contains(b, `<td class="mono">ping</td>`) || !strings.Contains(b, "Send test") || !strings.Contains(b, "New secret") {
		t.Fatal("the test delivery is not listed, or the buttons are missing")
	}
	log, _ := d.AuditLog(1)
	if len(log) != 1 || log[0].Action != "webhook.test" || log[0].Actor != "dora" {
		t.Fatalf("audit %+v", log)
	}

	// a test that fails is listed with its status, is tried once, and counts
	// for nothing
	for range webhook.DisableAfter + 1 {
		sink.mu.Lock()
		sink.codes = []int{500}
		sink.mu.Unlock()
		e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/test", url.Values{}, nil)
		if _, err := e.srv.Webhooks.RunDue(); err != nil {
			t.Fatal(err)
		}
	}
	dl, _ := d.Deliveries(hid, 1)
	if dl[0].Event != "ping" || dl[0].State != db.DeliveryFailed || dl[0].Status != 500 || dl[0].Attempts != 1 {
		t.Fatalf("a failed test: %+v", dl[0])
	}
	if h, _, _ := d.WebhookByID(hid); !h.Enabled || h.Failures != 0 {
		t.Fatalf("failed tests switched the webhook off: %+v", h)
	}
	// Redeliver sends a test again
	if rec := e.do(t, "dora", "POST", "/admin/webhooks/deliveries/"+strconv.FormatInt(dl[0].ID, 10)+"/redeliver", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("redeliver %d", rec.Code)
	}
	e.srv.Webhooks.RunDue()
	if dl, _ := d.Deliveries(hid, 1); dl[0].Event != "ping" || dl[0].State != db.DeliveryOK {
		t.Fatalf("a test sent again: %+v", dl[0])
	}

	// a webhook that is off is not tested: nothing is queued, it stays off
	e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/toggle", url.Values{}, nil)
	n, _ := d.Deliveries(hid, 100)
	if rec := e.do(t, "dora", "POST", "/admin/webhooks/"+id+"/test", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("test of a webhook that is off: %d", rec.Code)
	}
	if after, _ := d.Deliveries(hid, 100); len(after) != len(n) {
		t.Fatal("a test was queued for a webhook that is off")
	}
	if h, _, _ := d.WebhookByID(hid); h.Enabled {
		t.Fatal("the test switched the webhook on")
	}
	if b := e.do(t, "dora", "GET", "/admin/webhooks?hook="+id, nil, nil).Body.String(); !strings.Contains(b, `<button class="btn secondary sm w112" disabled>Send test</button>`) {
		t.Fatal("Send test is not disabled for a webhook that is off")
	}
}
