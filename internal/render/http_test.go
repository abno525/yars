package render

import (
	"strings"
	"testing"
)

func TestHTTPBlocks(t *testing.T) {
	m := New(10)
	src := "Steps:\n\n```http\nGET /reports?sort=<x> HTTP/1.1\nHost: app.example\nCookie: a=b\n\n{\"q\":1}\n```\n\n```http-response\nHTTP/1.1 404 Not Found\nContent-Type: text/html\n\n<b>no</b>\n```\n\n```go\nfunc x() {}\n```\n"
	h := string(m.HTML(src))
	for _, want := range []string{
		`<pre class="http"><code>`,
		`<span class="h-m">GET</span> <span class="h-u">/reports?sort=&lt;x&gt;</span> <span class="h-v">HTTP/1.1</span>`,
		`<span class="h-k">Host</span>: <span class="h-x">app.example</span>`,
		"\n\n{&#34;q&#34;:1}",
		`<span class="h-v">HTTP/1.1</span> <span class="h-s h-s4">404</span> <span class="h-r">Not Found</span>`,
		`&lt;b&gt;no&lt;/b&gt;`,
		`<code class="language-go">`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %q in\n%s", want, h)
		}
	}
	if strings.Contains(h, "<b>") {
		t.Fatal("body not escaped")
	}
}

// A request and its response in one block: the status line after a blank
// line starts the second message.
func TestHTTPRequestAndResponse(t *testing.T) {
	h := HighlightHTTP("POST /login HTTP/1.1\nHost: x\n\nuser=a\n\nHTTP/1.1 302 Found\nLocation: /home\n")
	for _, want := range []string{`<span class="h-m">POST</span>`, "user=a", `<span class="h-s h-s3">302</span>`, `<span class="h-k">Location</span>`} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %q in\n%s", want, h)
		}
	}
}
