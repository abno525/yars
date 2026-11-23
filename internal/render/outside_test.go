package render

import (
	"strings"
	"testing"
)

// rangeOf is the byte range of part in s.
func rangeOf(t *testing.T, s, part string) [2]int {
	t.Helper()
	i := strings.Index(s, part)
	if i < 0 {
		t.Fatalf("%q not in %q", part, s)
	}
	return [2]int{i, i + len(part)}
}

// M31: a fix may change one paragraph; everything else must render as it
// did, in the same containers, with the same link definitions.
func TestSameOutside(t *testing.T) {
	cases := []struct {
		name                string
		old, oldP, nw, newP string
		want                bool
	}{
		{"plain paragraph", "a foo here\n\nsecond paragraph\n", "a foo here", "a bar here\n\nsecond paragraph\n", "a bar here", true},
		{"table cell", "intro\n\n| a | b |\n|---|---|\n| `x` | y |\n\nend\n", "| a | b |\n|---|---|\n| `x` | y |", "intro\n\n| a | b |\n|---|---|\n| x | y |\n\nend\n", "| a | b |\n|---|---|\n| x | y |", true},
		{"tight list item", "intro\n\n- a foo\n- b\n\nend\n", "- a foo\n- b", "intro\n\n- a bar\n- b\n\nend\n", "- a bar\n- b", true},
		{"link definition in a quote", "a foo here\n\nsee [the advisory]\n\n[the advisory]: https://good.example\n", "a foo here",
			"a bar here\n> [the advisory]: https://evil.example/x\n\nsee [the advisory]\n\n[the advisory]: https://good.example\n", "a bar here\n> [the advisory]: https://evil.example/x", false},
		{"link definition in a list", "a foo here\n\nsee [ref]\n", "a foo here",
			"a bar here\n- [ref]: https://evil.example\n\nsee [ref]\n", "a bar here\n- [ref]: https://evil.example", false},
		{"comment in a list item", "1. a foo here\n\n   continuation paragraph\n", "1. a foo here",
			"1. <!-- a bar here\n\n   continuation paragraph\n", "1. <!-- a bar here", false},
		{"fence in a list item", "- a foo here\n\n  continuation\n", "- a foo here",
			"- ```a bar\n\n  continuation\n", "- ```a bar", false},
		{"closer dropped", "<!--\nhidden\n\na foo here -->\n\nlast paragraph\n", "a foo here -->",
			"<!--\nhidden\n\na bar here\n\nlast paragraph\n", "a bar here", false},
		{"list made loose", "x foo\n\n- a\n- b\n", "x foo", "- x bar\n\n- a\n- b\n", "- x bar", false},
		// two loose lists made one: step b would show as 3, not 1
		{"lists merged", "1. a\n\n   a2\n\nACME note\n\n1. b\n\n   b2\n", "ACME note", "1. a\n\n   a2\n\n1. note\n\n1. b\n\n   b2\n", "1. note", false},
		{"list split", "1. a\n\n1. mid foo\n\n1. b\n", "1. mid foo", "1. a\n\nmid bar\n\n1. b\n", "mid bar", false},
		{"loose list middle item", "1. a\n\n1. mid foo\n\n1. b\n", "1. mid foo", "1. a\n\n1. mid bar\n\n1. b\n", "1. mid bar", true},
	}
	for _, c := range cases {
		if got := SameOutside(c.old, c.nw, rangeOf(t, c.old, c.oldP), rangeOf(t, c.nw, c.newP)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
