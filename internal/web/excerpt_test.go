package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
)

// The excerpt drops Markdown structure only, never the text's own
// characters.
func TestExcerptKeepsText(t *testing.T) {
	for in, want := range map[string]string{
		"<script>alert(1)</script>":    "<script>alert(1)</script>",
		"C# and #12 and 2*3 and a__b":  "C# and #12 and 2*3 and a__b",
		"x > y, then y >= z":           "x > y, then y >= z",
		"Spell out SQL\n\n> SQL":       "Spell out SQL SQL",
		"> quoted\n>> nested":          "quoted nested",
		"## Heading\ntext":             "Heading text",
		"**bold** and `code` and *em*": "bold and code and em",
		"__under__ line":               "under line",
		"keep `a > b` as text":         "keep a > b as text",
		"a*b*c stays":                  "a*b*c stays",
		"run\n```sh\ncurl -i x\n```":   "run curl -i x",
		"**a** **b** and *c* *d*":      "a b and c d",
	} {
		if got := excerpt(in); got != want {
			t.Errorf("excerpt(%q) = %q, want %q", in, got, want)
		}
	}
}

// The resolved-thread summary shows a message with ">" correctly escaped
// (it used to show "<scriptalert(1)</script"), and so do the inbox's
// thread and returned rows, which use the same excerpt.
func TestResolvedExcerptEscaped(t *testing.T) {
	e := setup(t)
	text := "<script>alert(1)</script> breaks the page"
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {text}}, nil)
	b := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {e.chatIDs(t)[0]}}, nil).Body.String()
	row := b[strings.Index(b, `class="rrow"`):]
	sum := row[:strings.Index(row, "</button>")]
	if !strings.Contains(sum, "&lt;script&gt;alert(1)&lt;/script&gt; breaks the page") || strings.Contains(sum, "<script>") {
		t.Fatalf("resolved summary:\n%s", sum)
	}
	// the inbox's open threads queue (alice wrote the finding)
	if _, err := e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "see a > b and <b>x</b>", Section: "Impact"}, wBob); err != nil {
		t.Fatal(err)
	}
	q := queue(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), "threads")
	if !strings.Contains(q, "see a &gt; b and &lt;b&gt;x&lt;/b&gt;") || strings.Contains(q, "<b>x</b>") {
		t.Fatalf("threads queue:\n%s", q)
	}
}
