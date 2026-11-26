package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/abno525/yars/internal/auth"
)

// flashTTL is how long a one-time secret waits for the page after the
// redirect.
const flashTTL = 5 * time.Minute

// flashes holds one-time values (a new token or webhook secret) for the
// page a POST redirects to, keyed by the browser's session: the secret
// never goes into a URL, and reading it removes it.
type flashes struct {
	mu sync.Mutex
	m  map[string]flashEntry
}

type flashEntry struct {
	value   string
	expires time.Time
}

func flashKey(r *http.Request, kind string) string {
	c, err := r.Cookie(auth.CookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return kind + "\x00" + c.Value
}

// put keeps value for the next take of kind by the same session.
func (f *flashes) put(r *http.Request, kind, value string) {
	k := flashKey(r, kind)
	if k == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.m == nil {
		f.m = map[string]flashEntry{}
	}
	for key, e := range f.m { // drop what nobody came back for
		if now.After(e.expires) {
			delete(f.m, key)
		}
	}
	f.m[k] = flashEntry{value: value, expires: now.Add(flashTTL)}
}

// take returns the session's value of kind once ("" when there is none).
func (f *flashes) take(r *http.Request, kind string) string {
	k := flashKey(r, kind)
	if k == "" {
		return ""
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[k]
	if !ok {
		return ""
	}
	delete(f.m, k)
	if time.Now().After(e.expires) {
		return ""
	}
	return e.value
}
