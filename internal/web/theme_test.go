package web

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The three token blocks of the stylesheet (M33): every colour is a token
// set here, so the later dark-mode remake changes values only.
var tokenBlocks = []string{
	":root {",
	"@media (prefers-color-scheme: dark) {\n  :root:not([data-theme=\"light\"]) {",
	":root[data-theme=\"dark\"] {",
}

// blockEnd is the index just past the brace that closes the block whose
// first brace is the first "{" at or after start.
func blockEnd(css string, start int) int {
	depth := 0
	for i := strings.Index(css[start:], "{") + start; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(css)
}

// stylesheet is the served style.css with its comments blanked (lengths and
// line breaks kept, so positions still give line numbers).
func stylesheet(t *testing.T) string {
	t.Helper()
	e := setup(t)
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	return regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllStringFunc(css, func(c string) string {
		return regexp.MustCompile(`[^\n]`).ReplaceAllString(c, " ")
	})
}

// tokenRanges are the three blocks' [start, end) in css, each found once.
func tokenRanges(t *testing.T, css string) [][2]int {
	t.Helper()
	var out [][2]int
	for _, open := range tokenBlocks {
		i := strings.Index(css, open)
		if i < 0 {
			t.Fatalf("no token block %q", open)
		}
		out = append(out, [2]int{i, blockEnd(css, i)})
	}
	return out
}

var (
	hexColour = regexp.MustCompile(`#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b`)
	colourFn  = regexp.MustCompile(`\b(?:rgba?|hsla?)\(`)
	ident     = regexp.MustCompile(`(?:^|[^\w-])([A-Za-z][\w-]*)`)
)

// namedColours are CSS's colour keywords (transparent, currentColor and
// inherit are allowed and left out).
var namedColours = strings.Fields(`aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue
blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue
darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid
darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink
deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold
goldenrod gray green greenyellow grey honeydew hotpink indianred indigo ivory khaki lavender lavenderblush
lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey
lightpink lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime
limegreen linen magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen
mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin
navajowhite navy oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise
palevioletred papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue
saddlebrown salmon sandybrown seagreen seashell sienna silver skyblue slateblue slategray slategrey snow
springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen`)

// inValue reports whether position i of css is inside a declaration's
// value: after the "{" or ";" that opens it (no "}" since) and its ":".
func inValue(css string, i int) bool {
	open := max(strings.LastIndex(css[:i], "{"), strings.LastIndex(css[:i], ";"))
	if open < 0 || strings.LastIndex(css[:i], "}") > open {
		return false
	}
	return strings.Contains(css[open:i], ":")
}

// M33 task 1 (Review focus 1): outside the three token blocks the
// stylesheet has no colour literal: no #hex, rgb(), rgba(), hsl(), and no
// colour keyword but transparent, currentColor and inherit.
func TestNoColourLiteralsOutsideTokens(t *testing.T) {
	css := stylesheet(t)
	ranges := tokenRanges(t, css)
	inBlock := func(i int) bool {
		return slices.ContainsFunc(ranges, func(r [2]int) bool { return i >= r[0] && i < r[1] })
	}
	var found []string
	report := func(i int, lit string) {
		if !inBlock(i) && inValue(css, i) {
			found = append(found, fmt.Sprintf("line %d: %s", strings.Count(css[:i], "\n")+1, lit))
		}
	}
	for _, m := range hexColour.FindAllStringIndex(css, -1) {
		report(m[0], css[m[0]:m[1]])
	}
	for _, m := range colourFn.FindAllStringIndex(css, -1) {
		report(m[0], css[m[0]:m[1]])
	}
	for _, m := range ident.FindAllStringSubmatchIndex(css, -1) {
		if w := css[m[2]:m[3]]; slices.Contains(namedColours, strings.ToLower(w)) {
			report(m[2], w)
		}
	}
	if len(found) > 0 {
		t.Fatalf("%d colour literals outside the token blocks:\n%s", len(found), strings.Join(found, "\n"))
	}
}

// tokens are the custom properties set in css[r[0]:r[1]], by name.
func tokens(css string, r [2]int) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(--[\w-]+)\s*:\s*([^;}]+)`).FindAllStringSubmatch(css[r[0]:r[1]], -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

// The two dark blocks (the system's dark and the toggle's) set the same
// tokens to the same values; every dark token is a light one too.
func TestBothDarkBlocksHaveSameTokens(t *testing.T) {
	css := stylesheet(t)
	r := tokenRanges(t, css)
	light, media, toggle := tokens(css, r[0]), tokens(css, r[1]), tokens(css, r[2])
	for k, v := range media {
		if toggle[k] != v {
			t.Errorf("%s: %q in the media block, %q in the toggle's", k, v, toggle[k])
		}
	}
	for k := range toggle {
		if _, ok := media[k]; !ok {
			t.Errorf("%s only in the toggle's dark block", k)
		}
		if _, ok := light[k]; !ok {
			t.Errorf("%s is dark only", k)
		}
	}
}
