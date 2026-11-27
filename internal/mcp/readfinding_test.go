package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// pre1 6.4: read_finding sends the finding's text once: each section's body,
// and the front matter as fields (id, author, severity and cvss; the title,
// the details rows and the CVSS reasons under untrusted). The raw file comes
// only with raw: true.
func TestReadFindingSendsTextOnce(t *testing.T) {
	f := newFx(t)
	const once = "ONLY-ONCE-MARKER"
	for _, kv := range [][2]string{{"title", "SQL injection in login"}, {"details.Location", "POST /login"},
		{"cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"}, {"cvss_reason.AC", "needs a race"}} {
		f.ok(alice, "set_field", f001("field", kv[0], "value", kv[1]))
	}
	f.ok(alice, "update_section", f001("section", "Impact", "body", "Every row is read. "+once))
	text, isErr := f.wire(alice, "read_finding", f001())
	if isErr || strings.Count(text, once) != 1 || strings.Contains(text, "finding_md") {
		t.Fatalf("the text is there %d times, finding_md %v: %s", strings.Count(text, once), strings.Contains(text, "finding_md"), text)
	}
	var rd struct {
		ID, Author, Severity, CVSS string
		Untrusted                  struct {
			Title       string
			Details     map[string]string
			CVSSReasons map[string]string `json:"cvss_reasons"`
		}
	}
	if err := json.Unmarshal([]byte(text), &rd); err != nil {
		t.Fatal(err)
	}
	if rd.ID != "F-001" || rd.Author != "alice" || rd.Severity != "high" || !strings.HasPrefix(rd.CVSS, "CVSS:3.1/AV:N/AC:H") ||
		rd.Untrusted.Title != "SQL injection in login" || rd.Untrusted.Details["Location"] != "POST /login" || rd.Untrusted.CVSSReasons["AC"] != "needs a race" {
		t.Fatalf("the front matter as fields: %+v", rd)
	}
	raw := f001()
	raw["raw"] = true
	text, isErr = f.wire(alice, "read_finding", raw)
	var whole struct {
		Untrusted struct {
			Markdown string `json:"finding_md"`
		}
	}
	json.Unmarshal([]byte(text), &whole)
	if isErr || strings.Count(text, once) != 2 || !strings.Contains(whole.Untrusted.Markdown, "title: SQL injection in login") {
		t.Fatalf("raw: %s", text)
	}
	raw["raw"] = "true"
	if text, isErr := f.wire(alice, "read_finding", raw); !isErr || message(t, text) != `argument "raw" must be a boolean` {
		t.Fatalf("raw as a string: %s", text)
	}
}

// pre1 6.4: a chat that cannot be read fails read_finding (server_error,
// "internal error", a line in the log); it is not answered as a finding
// without open threads.
func TestReadFindingChatErrorFails(t *testing.T) {
	f := newFx(t)
	f.ok(bob, "add_chat_message", f001("text", "an objection"))
	logged := serverLog(f.s)
	if _, err := f.s.Store.DB().Exec("ALTER TABLE chat RENAME TO chat_away"); err != nil {
		t.Fatal(err)
	}
	text, isErr := f.wire(alice, "read_finding", f001())
	if m := object(t, "read_finding", text); !isErr || m["code"] != "server_error" || m["message"] != "internal error" {
		t.Fatalf("read_finding with the chat unreadable: %.300s", text)
	}
	if _, ok := failure(logged, "mcp: a tool failed", "read_finding", "alice"); !ok {
		t.Fatalf("the log lacks the failure: %q", logged.Text())
	}
}

// pre1 6.4: read_finding gives at most maxOpenThreads open threads, the
// oldest first, and of each the last maxThreadReplies replies, and counts
// what it left out; read_chat has all of them.
func TestReadFindingCapsThreads(t *testing.T) {
	f := newFx(t)
	const extra = 3
	first := object(t, "chat", f.ok(alice, "add_chat_message", f001("text", "thread 0")))["id"].(string)
	for i := 1; i < maxOpenThreads+extra; i++ {
		f.ok(alice, "add_chat_message", f001("text", fmt.Sprint("thread ", i)))
	}
	for i := range maxThreadReplies + 2 {
		f.ok(bob, "add_chat_message", f001("text", fmt.Sprint("reply ", i), "reply", first))
	}
	var rd struct {
		Threads []struct {
			ID, Text string
			Replies  []struct{ Text string }
			More     int `json:"replies_more"`
		} `json:"open_threads"`
		More int `json:"open_threads_more"`
	}
	if err := json.Unmarshal([]byte(f.ok(alice, "read_finding", f001())), &rd); err != nil {
		t.Fatal(err)
	}
	if len(rd.Threads) != maxOpenThreads || rd.More != extra || rd.Threads[0].ID != first || rd.Threads[1].Text != "thread 1" {
		t.Fatalf("%d threads, %d more", len(rd.Threads), rd.More)
	}
	if r := rd.Threads[0].Replies; len(r) != maxThreadReplies || rd.Threads[0].More != 2 || r[0].Text != "reply 2" || r[len(r)-1].Text != fmt.Sprint("reply ", maxThreadReplies+1) {
		t.Fatalf("%d replies, %d more", len(r), rd.Threads[0].More)
	}
	if rd.Threads[1].More != 0 {
		t.Fatalf("a thread without replies counts %d more", rd.Threads[1].More)
	}
	// read_chat pages them all, with every reply
	var all []struct {
		ID      string
		Replies []any
	}
	itemsOf(t, f.ok(alice, "read_chat", f001("limit", "200")), &all)
	if len(all) != maxOpenThreads+extra || len(all[0].Replies) != maxThreadReplies+2 {
		t.Fatalf("read_chat: %d threads, %d replies", len(all), len(all[0].Replies))
	}
	// the tools say where the rest is
	for _, d := range []string{toolByName["read_finding"].desc, toolByName["read_finding"].simple.desc} {
		if !strings.Contains(d, "open_threads_more") || !strings.Contains(d, "read_chat") || strings.Contains(d, "the raw finding.md content (") ||
			!strings.Contains(d, fmt.Sprintf("at most %d,", maxOpenThreads)) || !strings.Contains(d, fmt.Sprintf("its last %d replies", maxThreadReplies)) {
			t.Errorf("read_finding says: %s", d)
		}
	}
}
