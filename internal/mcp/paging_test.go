package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// pageOf calls a list tool and returns its ids and next.
func pageOf(t *testing.T, f *fx, tool string, a map[string]any) ([]string, string) {
	t.Helper()
	text := f.ok(alice, tool, a)
	var items []struct {
		ID string `json:"id"`
	}
	itemsOf(t, text, &items)
	next, _ := object(t, tool, text)["next"].(string)
	var ids []string
	for _, it := range items {
		ids = append(ids, it.ID)
	}
	return ids, next
}

// 120 findings: three pages of 50, 50 and 20, each next leading on, the
// last one empty; every finding once.
func TestPagingWalksAll(t *testing.T) {
	f := newFx(t)
	for i := 2; i <= 120; i++ {
		if _, err := f.s.Store.CreateFinding("acme", fmt.Sprintf("Finding %d", i), alice.GitAuthor()); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	var sizes []int
	cursor := ""
	for range 5 {
		a := map[string]any{"engagement": "acme"}
		if cursor != "" {
			a["cursor"] = cursor
		}
		ids, next := pageOf(t, f, "list_findings", a)
		sizes = append(sizes, len(ids))
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("%s twice", id)
			}
			seen[id] = true
		}
		if cursor = next; cursor == "" {
			break
		}
	}
	if fmt.Sprint(sizes) != "[50 50 20]" || len(seen) != 120 {
		t.Fatalf("pages %v, %d findings", sizes, len(seen))
	}
	// a smaller limit
	if ids, next := pageOf(t, f, "list_findings", map[string]any{"engagement": "acme", "limit": "7"}); len(ids) != 7 || next != "7" {
		t.Fatalf("limit 7: %d, next %q", len(ids), next)
	}
}

func TestPagingBadCursor(t *testing.T) {
	f := newFx(t)
	for _, c := range []string{"abc", "-1", "1.5", "0x10"} {
		text, isErr := f.call(alice, "list_findings", map[string]any{"engagement": "acme", "cursor": c})
		if m := object(t, c, text); !isErr || m["code"] != "invalid" || !strings.Contains(m["message"].(string), "cursor") {
			t.Errorf("cursor %q: %s", c, text)
		}
	}
	// past the end: an empty page, nothing after it
	if ids, next := pageOf(t, f, "list_findings", map[string]any{"engagement": "acme", "cursor": "500"}); len(ids) != 0 || next != "" {
		t.Fatalf("past the end: %v %q", ids, next)
	}
}

func TestPagingBadLimit(t *testing.T) {
	f := newFx(t)
	for _, tool := range []string{"list_findings", "list_engagements", "list_templates", "list_notifications"} {
		for _, l := range []string{"0", "201", "x", "-5"} {
			text, isErr := f.call(alice, tool, map[string]any{"engagement": "acme", "limit": l})
			if m := object(t, l, text); !isErr || m["code"] != "invalid" || !strings.Contains(m["message"].(string), "1 to 200") {
				t.Errorf("%s limit %q: %s", tool, l, text)
			}
		}
		f.ok(alice, tool, map[string]any{"engagement": "acme", "limit": "200"})
	}
}

// Notifications page by id: marking a page read before asking for the
// next (unread) skips none, and a token's engagements are filtered before
// the page is cut, so every page is full.
func TestNotificationsPageByID(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	d.AddMembers("beta", "alice")
	for i := range 120 {
		d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: fmt.Sprint("acme ", i)})
		d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "beta", Fid: "F-001", Actor: "bob", Text: fmt.Sprint("beta ", i)})
	}
	only := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}, Engagements: []string{"acme"}}
	type note struct {
		ID         int64  `json:"id"`
		Engagement string `json:"engagement"`
	}
	seen := map[int64]bool{}
	var sizes []int
	cursor := ""
	for range 5 {
		a := map[string]any{"unread": true}
		if cursor != "" {
			a["cursor"] = cursor
		}
		text, isErr := f.callTok(alice, only, "list_notifications", a)
		if isErr {
			t.Fatal(text)
		}
		var page []note
		itemsOf(t, text, &page)
		sizes = append(sizes, len(page))
		for _, n := range page {
			if n.Engagement != "acme" || seen[n.ID] {
				t.Fatalf("note %+v (seen %v)", n, seen[n.ID])
			}
			seen[n.ID] = true
			d.MarkRead("alice", n.ID) // read as it is shown
		}
		if cursor, _ = object(t, "page", text)["next"].(string); cursor == "" {
			break
		}
	}
	if fmt.Sprint(sizes) != "[50 50 20]" || len(seen) != 120 {
		t.Fatalf("pages %v, %d notes", sizes, len(seen))
	}
}

// q searches like the findings page: ID, title, an asset's host or URL.
func TestListFindingsSearch(t *testing.T) {
	f := newFx(t)
	f.s.Store.CreateFinding("acme", "Open redirect", alice.GitAuthor())
	if ids, _ := pageOf(t, f, "list_findings", map[string]any{"engagement": "acme", "q": "sql"}); fmt.Sprint(ids) != "[F-001]" {
		t.Fatalf("q sql: %v", ids)
	}
	if ids, _ := pageOf(t, f, "list_findings", map[string]any{"engagement": "acme", "q": "f-002"}); fmt.Sprint(ids) != "[F-002]" {
		t.Fatalf("q f-002: %v", ids)
	}
	if ids, _ := pageOf(t, f, "list_findings", map[string]any{"engagement": "acme", "q": "nothing like it"}); len(ids) != 0 {
		t.Fatalf("q nothing: %v", ids)
	}
}
