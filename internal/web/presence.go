package web

import (
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/events"
	"github.com/abno525/yars/internal/store"
)

// presenceTTL is how long an editor counts as open without a heartbeat.
// The editor sends one every 20 s; in a hidden tab the browser runs timers
// once a minute at most, so the wait covers two such beats and one may be
// lost. An editor closed without Cancel or Save is shown that long.
const presenceTTL = 150 * time.Second

// presence remembers who has which section open in an editor: a soft lock
// shown to everyone else. In memory only; it is lost on a restart.
type presence struct {
	mu   sync.Mutex
	m    map[presKey]map[string]time.Time // user -> last heartbeat
	now  func() time.Time
	hub  func() *events.Hub
	ttl  time.Duration
	tick func(d time.Duration, f func()) // time.AfterFunc
}

type presKey struct{ eng, fid, section string }

func newPresence(hub func() *events.Hub) *presence {
	return &presence{m: map[presKey]map[string]time.Time{}, now: time.Now, hub: hub, ttl: presenceTTL,
		tick: func(d time.Duration, f func()) { time.AfterFunc(d, f) }}
}

func (p *presence) publish(k presKey) {
	if h := p.hub(); h != nil {
		h.Publish(events.Event{Eng: k.eng, Fid: k.fid, Kind: events.Presence})
	}
}

// touch marks user as editing; a newcomer is announced at once, and a
// check after the TTL announces an editor that went quiet.
func (p *presence) touch(k presKey, user string) {
	p.mu.Lock()
	users := p.m[k]
	if users == nil {
		users = map[string]time.Time{}
		p.m[k] = users
	}
	_, known := users[user]
	users[user] = p.now()
	p.mu.Unlock()
	if !known {
		p.publish(k)
	}
	p.tick(p.ttl+time.Second, func() {
		if p.prune(k) {
			p.publish(k)
		}
	})
}

// leave ends user's presence in a section.
func (p *presence) leave(k presKey, user string) {
	p.mu.Lock()
	_, ok := p.m[k][user]
	delete(p.m[k], user)
	if len(p.m[k]) == 0 {
		delete(p.m, k)
	}
	p.mu.Unlock()
	if ok {
		p.publish(k)
	}
}

// prune drops expired editors of k and reports whether any went.
func (p *presence) prune(k presKey) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	gone := false
	for u, at := range p.m[k] {
		if p.now().Sub(at) > p.ttl {
			delete(p.m[k], u)
			gone = true
		}
	}
	if len(p.m[k]) == 0 {
		delete(p.m, k)
	}
	return gone
}

// who lists the users other than me editing k, sorted, with the time the
// first of them was last seen.
func (p *presence) who(k presKey, me string) ([]string, time.Time) {
	p.prune(k)
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	var at time.Time
	for u, t := range p.m[k] {
		if u != me {
			out = append(out, u)
			if t.After(at) {
				at = t
			}
		}
	}
	sort.Strings(out)
	return out, at
}

// presView is the slot that says who else is editing a section.
type presView struct {
	URL, Who string
	More     int
	Time     string
}

func presURL(ref store.FindingRef, section string) string {
	return findingURL(ref.EngID, ref.Dir) + "/s/" + url.PathEscape(section) + "/presence"
}

func (s *Server) presenceFor(r *http.Request, ref store.FindingRef, section string) presView {
	v := presView{URL: presURL(ref, section)}
	users, at := s.presence.who(presKey{ref.EngID, ref.F.Meta.ID, section}, auth.UserFrom(r.Context()).Username)
	if len(users) > 0 {
		v.Who, v.More, v.Time = users[0], len(users)-1, at.Local().Format("15:04")
	}
	return v
}

func (s *Server) presenceGet(w http.ResponseWriter, r *http.Request) {
	if ref, name, ok := s.sectionRef(w, r); ok {
		s.exec(w, "finding.html", "presence", s.presenceFor(r, ref, name))
	}
}

// presenceBeat is the editor's heartbeat.
func (s *Server) presenceBeat(w http.ResponseWriter, r *http.Request) {
	if ref, name, ok := s.sectionRef(w, r); ok {
		s.presence.touch(presKey{ref.EngID, ref.F.Meta.ID, name}, auth.UserFrom(r.Context()).Username)
		w.WriteHeader(http.StatusNoContent)
	}
}
