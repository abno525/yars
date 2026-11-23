package history

import "testing"

func TestWho(t *testing.T) {
	for _, c := range []struct {
		in, user string
		ai       bool
	}{
		{"alice", "alice", false},
		{"AI for alice", "alice", true},
		{"AI for ", "AI for ", false}, // no user: shown as it is
		{"ai for alice", "ai for alice", false},
	} {
		if u, ai := Who(c.in); u != c.user || ai != c.ai {
			t.Errorf("Who(%q) = %q, %v", c.in, u, ai)
		}
	}
}
