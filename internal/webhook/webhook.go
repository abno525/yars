// Package webhook sends YARS events to outside services: each event a
// webhook takes is queued in the database (webhook_deliveries) and POSTed
// as JSON by a background worker, signed with the webhook's secret
// (X-YARS-Signature: sha256=<HMAC-SHA256 of the body>). A failed try is
// retried with exponential backoff, at most MaxTries times.
package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/outbound"
	"github.com/abno525/yars/internal/store"
)

// Events are the events a webhook can take.
var Events = []string{store.EventStatus, store.EventCreated, store.EventUpdated, store.EventChat, store.EventExport, store.EventCheck}

const (
	// MaxTries is how often a delivery is tried before it is given up.
	MaxTries = 6
	// Backoff is the wait after the first failed try; it doubles each time.
	Backoff = 10 * time.Second
	// poll is how often the worker looks for due retries.
	poll = 5 * time.Second
)

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

// Sign is the X-YARS-Signature of body.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
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
	p := payload{Event: e.Kind, At: e.At.UTC().Format(time.RFC3339), Actor: e.Actor, Engagement: e.Eng, URL: base + "/e/" + e.Eng}
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
	status, errText := s.send(d)
	next := time.Time{}
	if errText != "" && errText != errDisabled && d.Attempts+1 < MaxTries {
		next = s.now().Add(Backoff << d.Attempts) // 10 s, 20 s, 40 s, …
	}
	// the try's one line: IDs, the event, the status and the try's number.
	// Never the address (its path can hold a secret), the payload or the
	// answer's words
	attrs := []any{"webhook", d.HookID, "delivery", d.ID, "event", d.Event, "status", status, "try", d.Attempts + 1, "ms", time.Since(start).Milliseconds()}
	switch {
	case errText == "":
		s.log().Info("webhook delivered", attrs...)
	case !next.IsZero():
		s.log().Warn("webhook delivery failed; it is tried again", attrs...)
	default:
		s.log().Warn("webhook delivery given up", attrs...)
	}
	err := s.DB.FinishAttempt(d.ID, status, errText, next, s.now())
	if errors.Is(err, db.ErrNotFound) { // its webhook was deleted meanwhile
		return nil
	}
	return err
}

// errDisabled is the error of a delivery whose webhook was turned off.
const errDisabled = "webhook disabled"

// send POSTs a delivery; it returns the HTTP status and "" or what failed.
func (s *Service) send(d db.Delivery) (int, string) {
	h, ok, err := s.DB.WebhookByID(d.HookID)
	if err != nil || !ok {
		return 0, "webhook removed"
	}
	if !h.Enabled {
		return 0, errDisabled // turned off after this was queued: given up
	}
	box, err := s.Secrets()
	if err != nil {
		return 0, "secret: " + err.Error()
	}
	sec, err := box.Decrypt(h.SecretEnc)
	if err != nil {
		return 0, "secret unreadable"
	}
	body := []byte(d.Payload)
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "YARS-Webhook")
	req.Header.Set("X-YARS-Event", d.Event)
	req.Header.Set("X-YARS-Delivery", strconv.FormatInt(d.ID, 10))
	req.Header.Set("X-YARS-Signature", Sign(sec, body))
	c := s.Client
	if c == nil {
		// the signed payload goes to the webhook's own address only
		c = outbound.Client(10 * time.Second)
	}
	resp, err := c.Do(req)
	if err != nil {
		var moved *outbound.Refused
		if errors.As(err, &moved) {
			return 0, moved.Error()
		}
		return 0, "no answer"
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, resp.Status
	}
	return resp.StatusCode, ""
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
