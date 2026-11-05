package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/db"
	"yars/internal/webhook"
)

// hooksAdmin is Admin › Webhooks: the list, the add/edit form, the secret
// of a webhook just added (once) and the deliveries of the selected one.
type hooksAdmin struct {
	Rows     []hookRow
	Events   []option // the add/edit form's event choices
	Form     hookForm
	Secret   string // a new webhook's secret, shown once
	Selected int64  // the webhook whose deliveries are listed
	SelURL   string
	Log      []deliveryRow
}

type hookRow struct {
	ID                  int64
	URL, Events, Ending string
	Enabled             bool
	Last                string // last delivery: "204", "500 · retrying", "—"
	LastState           string // ok | pending | failed | ""
	LastAt              string
}

type hookForm struct {
	ID      int64 // 0 = new
	URL     string
	Enabled bool
	Error   string
}

type deliveryRow struct {
	ID                              int64
	Event, At, State, Status, Tries string
	Error                           string
}

func (s *Server) routesAdminWebhooks(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/webhooks", s.adminOnly(s.hooksPage))
	mux.HandleFunc("POST /admin/webhooks", s.adminOnly(s.hookCreate))
	mux.HandleFunc("POST /admin/webhooks/{id}", s.adminOnly(s.hookUpdate))
	mux.HandleFunc("POST /admin/webhooks/{id}/toggle", s.adminOnly(s.hookToggle))
	mux.HandleFunc("POST /admin/webhooks/{id}/delete", s.adminOnly(s.hookDelete))
	mux.HandleFunc("POST /admin/webhooks/deliveries/{id}/redeliver", s.adminOnly(s.hookRedeliver))
}

func deliveryStatus(d db.Delivery) string {
	st := "—"
	if d.Status > 0 {
		st = strconv.Itoa(d.Status)
	} else if d.Attempts > 0 {
		st = "no answer"
	}
	return st
}

// hooksFill fills the page; picked are the form's ticked events.
func (s *Server) hooksFill(p *page, sel int64, f hookForm, picked []string) error {
	d := s.Store.DB()
	hs, err := d.Webhooks()
	if err != nil {
		return err
	}
	last, err := d.LastDeliveries()
	if err != nil {
		return err
	}
	v := &p.Admin.Hooks
	for _, h := range hs {
		r := hookRow{ID: h.ID, URL: h.URL, Events: strings.Join(h.Events, " · "), Ending: "…" + h.Last4, Enabled: h.Enabled, Last: "—"}
		if l, ok := last[h.ID]; ok {
			r.Last, r.LastState, r.LastAt = deliveryStatus(l), l.State, when(l.Created)
		}
		v.Rows = append(v.Rows, r)
		if h.ID == sel {
			v.Selected, v.SelURL = h.ID, h.URL
		}
	}
	if v.Selected != 0 {
		l, err := d.Deliveries(v.Selected, 50)
		if err != nil {
			return err
		}
		for _, x := range l {
			code := "—" // the Error column says why there is none
			if x.Status > 0 {
				code = strconv.Itoa(x.Status)
			}
			v.Log = append(v.Log, deliveryRow{ID: x.ID, Event: x.Event, At: when(x.Created), State: x.State, Status: code,
				Tries: strconv.Itoa(x.Attempts) + "/" + strconv.Itoa(webhook.MaxTries), Error: x.Error})
		}
	}
	for _, e := range webhook.Events {
		v.Events = append(v.Events, option{Value: e, Label: e, On: slices.Contains(picked, e)})
	}
	v.Form = f
	return nil
}

func hookID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *Server) hooksPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sel, _ := strconv.ParseInt(q.Get("hook"), 10, 64)
	f, picked := hookForm{Enabled: true}, []string(nil)
	if id, _ := strconv.ParseInt(q.Get("edit"), 10, 64); id > 0 {
		h, ok, err := s.Store.DB().WebhookByID(id)
		if err != nil {
			s.fail(w, err)
			return
		}
		if ok {
			f, picked = hookForm{ID: h.ID, URL: h.URL, Enabled: h.Enabled}, h.Events
		}
	}
	s.adminPage(w, r, "webhooks", http.StatusOK, func(p *page) error { return s.hooksFill(p, sel, f, picked) })
}

// hookInput reads the form's URL and events.
func hookInput(r *http.Request) (string, []string, string) {
	r.ParseForm()
	u := strings.TrimSpace(r.PostForm.Get("url"))
	var ev []string
	for _, e := range webhook.Events { // in the list's order
		if slices.Contains(r.PostForm["event"], e) {
			ev = append(ev, e)
		}
	}
	if err := webhook.ValidURL(u); err != nil {
		return u, ev, err.Error()
	}
	if err := webhook.ValidEvents(ev); err != nil {
		return u, ev, "Pick at least one event"
	}
	return u, ev, ""
}

func (s *Server) hookCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	url, ev, msg := hookInput(r)
	if msg != "" {
		s.adminPage(w, r, "webhooks", http.StatusBadRequest, func(p *page) error {
			return s.hooksFill(p, 0, hookForm{URL: url, Enabled: true, Error: msg}, ev)
		})
		return
	}
	id, sec, err := s.Webhooks.Create(url, ev, u.Username)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "webhook.add", url, strings.Join(ev, ","))
	s.startHooks()
	w.Header().Set("Cache-Control", "no-store")
	s.adminPage(w, r, "webhooks", http.StatusOK, func(p *page) error {
		p.Admin.Hooks.Secret = sec
		return s.hooksFill(p, id, hookForm{Enabled: true}, nil)
	})
}

func (s *Server) hookUpdate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, ok := hookID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	url, ev, msg := hookInput(r)
	on := r.PostForm.Get("enabled") == "1"
	if msg != "" {
		s.adminPage(w, r, "webhooks", http.StatusBadRequest, func(p *page) error {
			return s.hooksFill(p, id, hookForm{ID: id, URL: url, Enabled: on, Error: msg}, ev)
		})
		return
	}
	if err := s.Store.DB().UpdateWebhook(id, url, ev, on); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "webhook.edit", url, strings.Join(ev, ","))
	http.Redirect(w, r, "/admin/webhooks?hook="+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *Server) hookToggle(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, ok := hookID(r)
	h, found, err := s.Store.DB().WebhookByID(id)
	if !ok || err != nil || !found {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DB().SetWebhookEnabled(id, !h.Enabled); err != nil {
		s.fail(w, err)
		return
	}
	act := "webhook.enable"
	if h.Enabled {
		act = "webhook.disable"
	}
	s.Store.DB().Audit(u.Username, act, h.URL, "")
	http.Redirect(w, r, "/admin/webhooks", http.StatusSeeOther)
}

func (s *Server) hookDelete(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, ok := hookID(r)
	h, found, err := s.Store.DB().WebhookByID(id)
	if !ok || err != nil || !found {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DB().DeleteWebhook(id); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "webhook.delete", h.URL, "")
	http.Redirect(w, r, "/admin/webhooks", http.StatusSeeOther)
}

func (s *Server) hookRedeliver(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, ok := hookID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	x, err := s.Store.DB().Delivery(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Webhooks.Redeliver(id); err != nil {
		s.fail(w, err)
		return
	}
	s.startHooks()
	s.Store.DB().Audit(u.Username, "webhook.redeliver", strconv.FormatInt(x.HookID, 10), x.Event)
	http.Redirect(w, r, "/admin/webhooks?hook="+strconv.FormatInt(x.HookID, 10), http.StatusSeeOther)
}
