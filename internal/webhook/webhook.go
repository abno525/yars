// Package webhook sends YARS events to outside services: each event a
// webhook takes is queued in the database (webhook_deliveries) and POSTed
// as JSON by a background worker, signed with the webhook's secret
// (X-YARS-Signature: sha256=<HMAC-SHA256 of "timestamp.body">, the time in
// X-YARS-Timestamp). A failed try is retried with a growing wait, at most
// MaxTries times.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/outbound"
	"github.com/abno525/yars/internal/store"
)

// Events are the events a webhook can take.
var Events = []string{store.EventStatus, store.EventCreated, store.EventUpdated, store.EventChat, store.EventExport, store.EventCheck}

const (
	// MaxTries is how often a delivery is tried before it is given up: with
	// the waits of wait, about three and a half hours after the first try.
	MaxTries = 12
	// Backoff is the wait after the first failed try; it doubles each time,
	// up to MaxBackoff.
	Backoff = 10 * time.Second
	// MaxBackoff is the longest wait between two tries.
	MaxBackoff = time.Hour
	// DisableAfter is how many deliveries given up in a row switch a webhook
	// off.
	DisableAfter = 5
	// poll is how often the worker looks for due retries.
	poll = 5 * time.Second
)

// wait is the wait after a delivery's failed try number tries (1 = the
// first): 10 s, 20 s, 40 s, … doubling, an hour at most. The first waits are
// short, so a receiver's restart is bridged; the late ones cover an outage.
func wait(tries int) time.Duration {
	w := Backoff
	for i := 1; i < tries && w < MaxBackoff; i++ {
		w *= 2
	}
	return min(w, MaxBackoff)
}

// Sealer encrypts the stored secrets (secret.Box).
type Sealer interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

// Service queues and sends webhook deliveries.
type Service struct {
	DB      *db.DB
	Secrets func() (Sealer, error)
	Client  *http.Client     // default: outbound.Client, 10 s timeout
	Now     func() time.Time // default time.Now
	BaseURL func() string    // links in payloads ("" = paths)
	// Logger takes the service's log lines; nil writes none.
	Logger *slog.Logger
	// SwitchedOff is told of a webhook the service switched off after
	// DisableAfter deliveries given up in a row (the admins' notice); nil
	// tells nobody.
	SwitchedOff func(h db.Webhook)

	kickOnce sync.Once
	kick     chan struct{}
	runMu    sync.Mutex
}

func (s *Service) log() *slog.Logger { return logs.Or(s.Logger) }

func (s *Service) kicks() chan struct{} {
	s.kickOnce.Do(func() { s.kick = make(chan struct{}, 1) })
	return s.kick
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) wake() {
	select {
	case s.kicks() <- struct{}{}:
	default:
	}
}

// ValidURL accepts an absolute http or https address.
func ValidURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("URL must be an http or https address")
	}
	return nil
}

// ValidEvents accepts a non-empty list of known events.
func ValidEvents(ev []string) error {
	if len(ev) == 0 {
		return errors.New("pick at least one event")
	}
	for _, e := range ev {
		if !slices.Contains(Events, e) {
			return fmt.Errorf("unknown event %q", e)
		}
	}
	return nil
}

// Sign is the X-YARS-Signature of a body sent at ts (unix seconds, the
// X-YARS-Timestamp header): the HMAC-SHA256 of "<ts>.<body>". The time is
// digits only and joined with one dot, so the signed text reads one way.
func Sign(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// newEventID is the id of one event's payload: random, so it says nothing of
// the event, and the same for every webhook, retry and redelivery of it.
func newEventID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

// eventID reads the id out of a stored payload ("" for one queued before
// payloads had one).
func eventID(payload string) string {
	var p struct {
		ID string `json:"id"`
	}
	json.Unmarshal([]byte(payload), &p)
	return p.ID
}

// Create adds a webhook and returns its id and its secret (shown once).
func (s *Service) Create(rawURL string, events []string, by string) (int64, string, error) {
	if err := ValidURL(rawURL); err != nil {
		return 0, "", err
	}
	if err := ValidEvents(events); err != nil {
		return 0, "", err
	}
	box, err := s.Secrets()
	if err != nil {
		return 0, "", err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return 0, "", err
	}
	sec := "whsec_" + hex.EncodeToString(b)
	enc, err := box.Encrypt(sec)
	if err != nil {
		return 0, "", err
	}
	id, err := s.DB.AddWebhook(db.Webhook{URL: rawURL, Events: events, SecretEnc: enc, Last4: sec[len(sec)-4:], Enabled: true, CreatedBy: by})
	return id, sec, err
}

type findingJSON struct {
	ID       string `json:"id"`
	Dir      string `json:"dir"`
	Title    string `json:"title"`
	Severity string `json:"severity,omitempty"`
	Author   string `json:"author"`
}

type messageJSON struct {
	ID      string `json:"id"`
	Text    string `json:"text"`
	Section string `json:"section,omitempty"`
	Reply   string `json:"reply,omitempty"`
}

type payload struct {
	ID         string       `json:"id"`
	Event      string       `json:"event"`
	At         string       `json:"at"`
	Actor      string       `json:"actor"`
	Engagement string       `json:"engagement"`
	Finding    *findingJSON `json:"finding,omitempty"`
	// finding.status_changed
	Action string `json:"action,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Reason string `json:"reason,omitempty"`
	// finding.updated
	Changed []string `json:"changed,omitempty"`
	// chat.posted
	Message *messageJSON `json:"message,omitempty"`
	// export.sent
	Destination string   `json:"destination,omitempty"`
	OK          *bool    `json:"ok,omitempty"`
	Error       string   `json:"error,omitempty"`
	ExportURL   string   `json:"export_url,omitempty"`
	Findings    []string `json:"findings,omitempty"`
	// check.finished
	State    string `json:"state,omitempty"`
	Errors   *int   `json:"errors,omitempty"`
	Warnings *int   `json:"warnings,omitempty"`
	URL      string `json:"url"`
}

// Payload is the JSON body sent for e.
func (s *Service) Payload(e store.Event) []byte {
	base := ""
	if s.BaseURL != nil {
		base = s.BaseURL()
	}
	p := payload{ID: newEventID(), Event: e.Kind, At: e.At.UTC().Format(time.RFC3339), Actor: e.Actor, Engagement: e.Eng, URL: base + "/e/" + e.Eng}
	if e.Fid != "" {
		p.Finding = &findingJSON{ID: e.Fid, Dir: e.Dir, Title: e.Title, Severity: e.Severity, Author: e.Author}
		p.URL = base + "/e/" + e.Eng + "/f/" + store.ShortID(e.Dir)
	}
	switch e.Kind {
	case store.EventStatus:
		p.Action, p.From, p.To, p.Reason = e.Action, e.From, e.To, e.Reason
		p.Destination = e.Destination
	case store.EventUpdated:
		p.Changed = e.Changed
	case store.EventChat:
		p.Message = &messageJSON{ID: e.MsgID, Text: e.Text, Section: e.Section, Reply: e.Reply}
	case store.EventExport:
		ok := e.OK
		p.Destination, p.OK, p.Error, p.ExportURL, p.Findings = e.Destination, &ok, e.Error, e.URL, e.Findings
	case store.EventCheck:
		er, wa := e.Errors, e.Warnings
		p.State, p.Errors, p.Warnings = e.State, &er, &wa
	}
	b, _ := json.Marshal(p)
	return b
}

// Handle queues e for every enabled webhook that takes it (a store
// OnEvent subscriber).
func (s *Service) Handle(e store.Event) {
	if !slices.Contains(Events, e.Kind) {
		return
	}
	hooks, err := s.DB.HooksFor(e.Kind)
	if err != nil {
		s.log().Error("webhooks: the webhooks of an event are not read", "event", e.Kind, "err", err)
		return
	}
	if len(hooks) == 0 {
		return
	}
	body := string(s.Payload(e))
	for _, h := range hooks {
		if _, err := s.DB.EnqueueDelivery(h.ID, e.Kind, body, s.now()); err != nil {
			s.log().Error("webhooks: a delivery is not queued", "webhook", h.ID, "event", e.Kind, "err", err)
		}
	}
	s.wake()
}

// Redeliver queues delivery id again, due now.
func (s *Service) Redeliver(id int64) error {
	if _, err := s.DB.Redeliver(id, s.now()); err != nil {
		return err
	}
	s.wake()
	return nil
}

// RunDue sends every delivery that is due and returns how many it tried.
// Calls take turns, so a delivery is never sent twice at once.
func (s *Service) RunDue() (int, error) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	n := 0
	for {
		due, err := s.DB.DueDeliveries(s.now(), 50)
		if err != nil || len(due) == 0 {
			return n, err
		}
		for _, d := range due {
			n++
			// unrecorded, it would stay due: stop until the next pass
			if err := s.attempt(d); err != nil {
				return n, fmt.Errorf("webhook delivery %d: %w", d.ID, err)
			}
		}
	}
}

// attempt sends one delivery and records the result.
func (s *Service) attempt(d db.Delivery) error {
	start := time.Now()
	status, errText, why := s.send(d)
	next := time.Time{}
	if errText != "" && errText != errDisabled && d.Attempts+1 < MaxTries {
		next = s.now().Add(wait(d.Attempts + 1))
	}
	// the try's one line: IDs, the event, the status and the try's number.
	// Never the address (its path can hold a secret), the payload or the
	// answer's words. A try without an answer says why in err, as one of
	// the fixed words of send
	attrs := []any{"webhook", d.HookID, "delivery", d.ID, "event", d.Event, "status", status, "try", d.Attempts + 1, "ms", time.Since(start).Milliseconds()}
	if why != "" {
		attrs = append(attrs, "err", why)
	}
	switch {
	case errText == "":
		s.log().Info("webhook delivered", attrs...)
	case errText == errDisabled:
		// no fault: an admin turned the webhook off with this in the queue
		s.log().Info("webhook delivery dropped", attrs...)
	case !next.IsZero():
		s.log().Warn("webhook delivery failed; it is tried again", attrs...)
	default:
		s.log().Warn("webhook delivery given up", attrs...)
	}
	// a delivery given up counts towards the switch-off when its webhook was
	// there and on, and it is no test delivery (a test of a dead address must
	// not switch the webhook off)
	counts := errText != errDisabled && why != whyRemoved && why != whyDatabase && d.Event != EventPing
	off, h, err := s.DB.FinishCounted(d.ID, status, errText, next, s.now(), counts, DisableAfter)
	if errors.Is(err, db.ErrNotFound) { // its webhook was deleted meanwhile
		return nil
	}
	if err != nil || !off {
		return err
	}
	// switched off: one line, one audit row, one notice to the admins. What is
	// still queued for it is dropped by send, at info. The line names no
	// address; the audit log holds the address of every webhook change.
	s.log().Warn("webhook switched off after failed deliveries", "webhook", h.ID, "failures", h.Failures)
	if err := s.DB.Audit("yars", "webhook.disable", h.URL, strconv.Itoa(h.Failures)+" deliveries given up in a row"); err != nil {
		s.log().Error("webhooks: the switch-off is not in the audit log", "webhook", h.ID, "err", err)
	}
	if s.SwitchedOff != nil {
		s.SwitchedOff(h)
	}
	return nil
}

// EventPing is the event of a test delivery (Admin › Webhooks › Test): no
// webhook subscribes to it, and it is no event of the store.
const EventPing = "ping"

// errDisabled is the error of a delivery whose webhook was turned off.
const errDisabled = "webhook disabled"

// The words a log line gives for a try that got no HTTP answer. They are
// fixed: the stored error can name a host or a path, the log never does.
const (
	whyDatabase = "database"
	whyRemoved  = "removed"
	whyDisabled = "disabled"
	whySecret   = "secret"
	whyAddress  = "address"
	whyRedirect = "redirect refused"
	whyNoAnswer = "no answer"
	whyTimeout  = "timeout"
	whyDNS      = "DNS"
	whyRefused  = "connection refused"
	whyTLS      = "TLS"
)

// noAnswer is the word for a request that got no HTTP answer: the kind of
// failure, never the error's own text (it quotes the whole address, whose
// path or query can hold a secret). The word is what the delivery's row and
// the log both say.
func noAnswer(err error) string {
	var (
		dns     *net.DNSError
		cert    *tls.CertificateVerificationError
		record  tls.RecordHeaderError
		alert   tls.AlertError
		host    x509.HostnameError
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
		timeout interface{ Timeout() bool }
	)
	switch {
	case errors.As(err, &dns):
		// before the timeout test: a name that is not answered in time is a
		// DNS failure first
		return whyDNS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return whyTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return whyRefused
	case errors.As(err, &cert), errors.As(err, &record), errors.As(err, &alert), errors.As(err, &host), errors.As(err, &unknown), errors.As(err, &invalid):
		return whyTLS
	}
	return whyNoAnswer
}

// send POSTs a delivery; it returns the HTTP status, "" or what failed (kept
// with the delivery) and, for a try without an answer, the log's word for it.
func (s *Service) send(d db.Delivery) (int, string, string) {
	h, ok, err := s.DB.WebhookByID(d.HookID)
	if err != nil {
		return 0, "webhook removed", whyDatabase
	}
	if !ok {
		return 0, "webhook removed", whyRemoved
	}
	if !h.Enabled {
		return 0, errDisabled, whyDisabled // turned off after this was queued: given up
	}
	box, err := s.Secrets()
	if err != nil {
		return 0, "secret: " + err.Error(), whySecret
	}
	sec, err := box.Decrypt(h.SecretEnc)
	if err != nil {
		return 0, "secret unreadable", whySecret
	}
	body := []byte(d.Payload)
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error(), whyAddress
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "YARS-Webhook")
	req.Header.Set("X-YARS-Event", d.Event)
	req.Header.Set("X-YARS-Delivery", strconv.FormatInt(d.ID, 10))
	if id := eventID(d.Payload); id != "" && !strings.ContainsAny(id, "\r\n") {
		req.Header.Set("X-YARS-Event-ID", id)
	}
	// the time of this try, not of the event: a late retry is still fresh
	ts := s.now().Unix()
	req.Header.Set("X-YARS-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-YARS-Signature", Sign(sec, ts, body))
	c := s.Client
	if c == nil {
		// the signed payload goes to the webhook's own address only
		c = outbound.Client(10 * time.Second)
	}
	resp, err := c.Do(req)
	if err != nil {
		var moved *outbound.Refused
		if errors.As(err, &moved) {
			return 0, moved.Error(), whyRedirect
		}
		why := noAnswer(err)
		return 0, why, why
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, resp.Status, "" // the status says it
	}
	return resp.StatusCode, "", ""
}

// Run sends due deliveries until stop closes: right after an event is
// queued, and every few seconds for retries.
func (s *Service) Run(stop <-chan struct{}) {
	kick := s.kicks()
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if _, err := s.RunDue(); err != nil {
			s.log().Error("webhooks: sending stopped until the next pass", "err", err)
		}
		select {
		case <-stop:
			return
		case <-kick:
		case <-t.C:
		}
	}
}
