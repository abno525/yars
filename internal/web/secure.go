package web

import "net/http"

// pagePolicy is the Content-Security-Policy of every page: scripts, styles,
// fonts and fetches only from this site; no inline code (templates and
// app.js keep none); no framing.
const pagePolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; " +
	"font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// secureHeaders sets the security headers on every response; hsts adds
// Strict-Transport-Security. A handler that sets its own policy afterwards
// (an attachment's sandbox) overrides pagePolicy.
func secureHeaders(hsts bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", pagePolicy)
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
