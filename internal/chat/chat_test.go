package chat

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func msg(id, user, text string) Message {
	return Message{ID: id, User: user, Text: text, TS: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)}
}

func TestRoundTrip(t *testing.T) {
	m := msg("a1", "alice", "hello\nworld")
	m.Section = "Impact"
	b, err := Line(m)
	if err != nil || !strings.HasSuffix(string(b), "}\n") || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("line %q %v", b, err)
	}
	got := Parse(b)
	if len(got) != 1 || !reflect.DeepEqual(got[0], m) {
		t.Fatalf("got %+v", got)
	}
	if len(NewID()) != 12 || NewID() == NewID() {
		t.Fatal("bad ids")
	}
}

func TestParseSkipsBadLines(t *testing.T) {
	a, _ := Line(msg("a1", "alice", "one"))
	b, _ := Line(msg("b2", "bob", "two"))
	in := string(a) + "{not json\n\n" + `{"id":"","text":"no id"}` + "\n" + string(b)
	got := Parse([]byte(in))
	if len(got) != 2 || got[0].ID != "a1" || got[1].ID != "b2" {
		t.Fatalf("got %+v", got)
	}
}

func TestTimelineThreads(t *testing.T) {
	ev := msg("e1", "bob", "needs PoC")
	ev.Event = "return"
	r1 := msg("r1", "bob", "reply")
	r1.Reply = "t1"
	r2 := msg("r2", "alice", "done")
	r2.Reply = "t1"
	res := msg("x1", "bob", "")
	res.Resolves = "t1"
	reo := msg("x2", "alice", "")
	reo.Reopens = "t1"
	res2 := msg("x3", "bob", "")
	res2.Resolves = "t2"
	orphan := msg("o1", "bob", "lost")
	orphan.Reply = "nope"
	msgs := []Message{msg("t1", "alice", "first"), ev, r1, r2, res, reo, msg("t2", "bob", "second"), res2, orphan}
	tl := Timeline(msgs)
	if len(tl) != 3 || tl[0].Thread == nil || tl[1].Event == nil || tl[2].Thread == nil {
		t.Fatalf("timeline %+v", tl)
	}
	t1, t2 := tl[0].Thread, tl[2].Thread
	if len(t1.Replies) != 2 || t1.Resolved {
		t.Fatalf("t1 %+v", t1)
	}
	if !t2.Resolved || t2.ResolvedBy != "bob" {
		t.Fatalf("t2 %+v", t2)
	}
}

func TestOpenCount(t *testing.T) {
	a := msg("t1", "alice", "x")
	a.Section = "Impact"
	b := msg("t2", "alice", "y")
	c := msg("t3", "alice", "z")
	c.Section = "Impact"
	res := msg("x", "bob", "")
	res.Resolves = "t3"
	total, by := OpenCount([]Message{a, b, c, res})
	if total != 2 || by["Impact"] != 1 || by[""] != 1 {
		t.Fatalf("total %d by %v", total, by)
	}
}

func TestValidate(t *testing.T) {
	root := msg("t1", "alice", "root")
	rep := msg("r1", "bob", "reply")
	rep.Reply = "t1"
	ev := msg("e1", "bob", "x")
	ev.Event = "submit"
	existing := []Message{root, rep, ev}

	bad := []Message{
		msg("n", "a", "   "),
		msg("n", "a", strings.Repeat("x", 10001)),
		{Text: "x", Reply: "r1"},
		{Text: "x", Reply: "e1"},
		{Resolves: "zz"},
		{Text: "x", Reply: "t1", Resolves: "t1"},
	}
	for i, m := range bad {
		if Validate(existing, m) == nil {
			t.Errorf("case %d accepted: %+v", i, m)
		}
	}
	ok := []Message{{Text: "new"}, {Text: "r", Reply: "t1"}, {Resolves: "t1"}, {Reopens: "t1"}}
	for i, m := range ok {
		if err := Validate(existing, m); err != nil {
			t.Errorf("ok case %d: %v", i, err)
		}
	}
}
