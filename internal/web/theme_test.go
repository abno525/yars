package web

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The three token blocks of the stylesheet (M33): every colour is a token
// set here, so the later dark-mode remake changes values only.
var tokenBlocks = []string{
	":root, .preview-doc[data-theme=\"light\"] {",
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

// stylesheet is the served style.css.
func stylesheet(t *testing.T) string {
	t.Helper()
	e := setup(t)
	return e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
}

var (
	comment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
	notBreak = regexp.MustCompile(`[^\n]`)
)

// prepare blanks comments, and the braces and semicolons inside strings and
// url(…), so the rest can find declarations by "{", ";" and "}". Lengths and
// line breaks are kept: positions still give line numbers.
func prepare(css string) string {
	b := []byte(comment.ReplaceAllStringFunc(css, func(c string) string { return notBreak.ReplaceAllString(c, " ") }))
	var quote byte
	inURL := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '{' || c == '}' || c == ';' {
				b[i] = ' '
			}
		case c == '"' || c == '\'':
			quote = c
		case inURL:
			if c == ')' {
				inURL = false
			} else if c == '{' || c == '}' || c == ';' {
				b[i] = ' '
			}
		case len(b)-i >= 4 && strings.EqualFold(string(b[i:i+4]), "url("):
			inURL, i = true, i+3
		}
	}
	return string(b)
}

// tokenRanges are the three blocks' [start, end) in css. Each is written
// once, and the dark media query holds its block and nothing else.
func tokenRanges(css string) ([][2]int, error) {
	var out [][2]int
	for _, open := range tokenBlocks {
		if n := strings.Count(css, open); n != 1 {
			return nil, fmt.Errorf("token block %q is written %d times", open, n)
		}
		i := strings.Index(css, open)
		if strings.HasPrefix(open, "@media") {
			inner := i + strings.Index(open, ":root")
			if rest := css[blockEnd(css, inner) : blockEnd(css, i)-1]; strings.TrimSpace(rest) != "" {
				return nil, errors.New("the dark media query holds more than its token block")
			}
			i = inner
		}
		out = append(out, [2]int{i, blockEnd(css, i)})
	}
	return out, nil
}

func inRanges(ranges [][2]int, i int) bool {
	return slices.ContainsFunc(ranges, func(r [2]int) bool { return i >= r[0] && i < r[1] })
}

// declAt finds the declaration around position i: it starts just past the
// "{", ";" or "}" before i, and it is one when the next of those after i
// is ";" or "}" (a "{" means i is in a selector or an at-rule's prelude).
func declAt(css string, i int) (start int, ok bool) {
	next := strings.IndexAny(css[i:], "{;}")
	return strings.LastIndexAny(css[:i], "{;}") + 1, next >= 0 && css[i+next] != '{'
}

// inValue reports whether position i is in a declaration's value.
func inValue(css string, i int) bool {
	start, ok := declAt(css, i)
	return ok && strings.Contains(css[start:i], ":")
}

// customProp reports whether the declaration at i sets a custom property.
func customProp(css string, i int) bool {
	start, _ := declAt(css, i)
	return strings.HasPrefix(strings.TrimSpace(css[start:i]), "--")
}

func lineOf(css string, i int) int { return strings.Count(css[:i], "\n") + 1 }

var (
	hexColour = regexp.MustCompile(`#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b`)
	urlHex    = regexp.MustCompile(`%23(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b`)
	colourFn  = regexp.MustCompile(`(?i)\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color)\(`)
	ident     = regexp.MustCompile(`(?:^|[^\w-])([A-Za-z][\w-]*)`)
	setsProp  = regexp.MustCompile(`(--[\w-]+)\s*:`)
)

// namedColours are CSS's colour keywords and system colours, lower case
// (transparent, currentColor and inherit are allowed and left out).
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
springgreen steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen
accentcolor accentcolortext activetext buttonborder buttonface buttontext canvas canvastext field fieldtext
graytext highlight highlighttext linktext mark marktext selecteditem selecteditemtext visitedtext`)

// colourLiterals lists every colour literal of css that is not a token's
// value in one of the three token blocks, by line, or why the blocks
// cannot be told apart.
func colourLiterals(css string) []string {
	css = prepare(css)
	ranges, err := tokenRanges(css)
	if err != nil {
		return []string{err.Error()}
	}
	var found []string
	report := func(i int, lit string) {
		if inValue(css, i) && !(inRanges(ranges, i) && customProp(css, i)) {
			found = append(found, fmt.Sprintf("line %d: %s", lineOf(css, i), lit))
		}
	}
	for _, re := range []*regexp.Regexp{hexColour, urlHex, colourFn} {
		for _, m := range re.FindAllStringIndex(css, -1) {
			report(m[0], css[m[0]:m[1]])
		}
	}
	for _, m := range ident.FindAllStringSubmatchIndex(css, -1) {
		if w := css[m[2]:m[3]]; slices.Contains(namedColours, strings.ToLower(w)) {
			report(m[2], w)
		}
	}
	return found
}

// tokens are the custom properties set in css[r[0]:r[1]], by name.
func tokens(css string, r [2]int) map[string]string {
	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(--[\w-]+)\s*:\s*([^;}]+)`).FindAllStringSubmatch(css[r[0]:r[1]], -1) {
		out[m[1]] = strings.TrimSpace(m[2])
	}
	return out
}

// themeMismatches lists how the two dark blocks differ, dark tokens that
// are not light ones, and tokens set again outside the token blocks.
func themeMismatches(css string) []string {
	css = prepare(css)
	r, err := tokenRanges(css)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	light, media, toggle := tokens(css, r[0]), tokens(css, r[1]), tokens(css, r[2])
	for k, v := range media {
		if toggle[k] != v {
			out = append(out, fmt.Sprintf("%s: %q in the media block, %q in the toggle's", k, v, toggle[k]))
		}
	}
	for k := range toggle {
		if _, ok := media[k]; !ok {
			out = append(out, k+" only in the toggle's dark block")
		}
		if _, ok := light[k]; !ok {
			out = append(out, k+" is dark only")
		}
	}
	for _, m := range setsProp.FindAllStringSubmatchIndex(css, -1) {
		name := css[m[2]:m[3]]
		start, ok := declAt(css, m[0])
		if _, token := light[name]; token && ok && strings.TrimSpace(css[start:m[0]]) == "" && !inRanges(r, m[0]) {
			out = append(out, fmt.Sprintf("line %d: %s is set outside the token blocks", lineOf(css, m[0]), name))
		}
	}
	slices.Sort(out)
	return out
}

// M33 task 1 (Review focus 1): outside the three token blocks the
// stylesheet has no colour literal (#hex, also as %23 in a data URI, a
// colour function, a colour keyword but transparent, currentColor and
// inherit), and inside them only tokens' values are colours.
func TestNoColourLiteralsOutsideTokens(t *testing.T) {
	if found := colourLiterals(stylesheet(t)); len(found) > 0 {
		t.Fatalf("%d colour literals outside the token blocks:\n%s", len(found), strings.Join(found, "\n"))
	}
}

// The two dark blocks (the system's dark and the toggle's) set the same
// tokens to the same values; every dark token is a light one too; no rule
// outside the blocks sets a token again.
func TestBothDarkBlocksHaveSameTokens(t *testing.T) {
	if out := themeMismatches(stylesheet(t)); len(out) > 0 {
		t.Fatal(strings.Join(out, "\n"))
	}
}

// The two checks above catch a colour wherever it is written (the M33
// task 1 review's six gaps), and leave a stylesheet that keeps the rule
// alone.
func TestThemeChecksCatchEscapes(t *testing.T) {
	sheet := func(light, media, rest string) string {
		return ":root, .preview-doc[data-theme=\"light\"] {\n  --ink: #0F172A;\n  color-scheme: light;\n" + light + "}\n\n" +
			"@media (prefers-color-scheme: dark) {\n  :root:not([data-theme=\"light\"]) {\n    --ink: #EDEFF2;\n  }\n" + media + "}\n\n" +
			":root[data-theme=\"dark\"] {\n  --ink: #EDEFF2;\n}\n\n" +
			"#add, .x:hover #add { color: var(--ink); }\n" +
			"@font-face { font-family: \"Plex\"; src: url(\"fonts/a;b.woff2\") format(\"woff2\"); }\n" + rest
	}
	if found := colourLiterals(sheet("", "", "")); len(found) > 0 {
		t.Fatalf("a clean sheet: %v", found)
	}
	if out := themeMismatches(sheet("", "", "")); len(out) > 0 {
		t.Fatalf("a clean sheet: %v", out)
	}
	for name, css := range map[string]string{
		"a rule in the dark media query":      sheet("", "  .x { color: var(--ink); }\n", ""),
		"a second toggle block":               sheet("", "", ":root[data-theme=\"dark\"] {\n  --ink: #EDEFF2;\n}\n"),
		"a property, not a token, in a block": sheet("  background: #FFFFFF;\n", "", ""),
		"upper-case rgb":                      sheet("", "", ".x { color: RGB(1, 2, 3); }\n"),
		"oklch":                               sheet("", "", ".x { color: oklch(0.5 0.1 200); }\n"),
		"a system colour":                     sheet("", "", ".x { background: Canvas; }\n"),
		"a data URI's %23":                    sheet("", "", ".x { background: url(\"data:image/svg+xml,%3Csvg fill='%23B42318'/%3E\"); }\n"),
		"a keyword after a data URI's ;":      sheet("", "", ".x { background: url(\"data:image/svg+xml;utf8,<svg fill='red'/>\"); }\n"),
		"a nested rule before a declaration":  sheet("", "", ".a { .b { margin: 0; } color: red; }\n"),
		"an unquoted url with a ; and a #hex": sheet("", "", ".x { background: url(data:image/svg+xml;utf8,%3Csvg%20fill=%23ABC/%3E); }\n"),
	} {
		if len(colourLiterals(css)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	for name, css := range map[string]string{
		"a second toggle block that sets a token to a token": sheet("", "", ":root[data-theme=\"dark\"] {\n  --ink: var(--ink);\n}\n"),
		"a rule that sets a token again":                     sheet("", "", "html[data-theme=\"dark\"] { --ink: var(--ink); }\n"),
		"a dark media rule that sets a token":                sheet("", "  .x { --ink: var(--ink); }\n", ""),
	} {
		if len(themeMismatches(css)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
