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
	}
	for _, c := range cases {
		if got := SameOutside(c.old, c.nw, rangeOf(t, c.old, c.oldP), rangeOf(t, c.nw, c.newP)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
