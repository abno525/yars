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

// scan reads css once and gives two copies of it, the same length with the
// same line breaks (positions still give line numbers):
//   - structure has its comments blanked, and the braces and semicolons
//     inside strings and url(…), so blocks and declarations can be found by
//     "{", ";" and "}";
//   - code also has everything inside strings and url(…) blanked, so a name
//     or a "#" there is not taken for a colour.
//
// A backslash escapes the next character, in a string or out of one; "/*"
// starts a comment only outside strings and url(…).
func scan(css string) (structure, code string) {
	s, c := []byte(css), []byte(css)
	hide := func(i int) {
		if css[i] == '\n' {
			return
		}
		c[i] = ' '
		if css[i] == '{' || css[i] == '}' || css[i] == ';' {
			s[i] = ' '
		}
	}
	var quote byte
	inURL := false
	for i := 0; i < len(css); i++ {
		ch := css[i]
		switch {
		case quote != 0:
			hide(i)
			if ch == '\\' && i+1 < len(css) {
				i++
				hide(i)
			} else if ch == quote {
				quote = 0
			}
		case inURL && (ch == '"' || ch == '\''):
			quote = ch
			hide(i)
		case inURL:
			if ch == ')' {
				inURL = false
				continue
			}
			hide(i)
			if ch == '\\' && i+1 < len(css) {
				i++
				hide(i)
			}
		case ch == '\\':
			i++
		case ch == '/' && i+1 < len(css) && css[i+1] == '*':
			end := len(css)
			if j := strings.Index(css[i+2:], "*/"); j >= 0 {
				end = i + 2 + j + 2
			}
			for ; i < end; i++ {
				if css[i] != '\n' {
					s[i], c[i] = ' ', ' '
				}
			}
			i--
		case ch == '"' || ch == '\'':
			quote = ch
			hide(i)
		case len(css)-i >= 4 && strings.EqualFold(css[i:i+4], "url("):
			inURL, i = true, i+3
		}
	}
	return string(s), string(c)
}

// prepare is scan's structure.
func prepare(css string) string {
	s, _ := scan(css)
	return s
}

// tokenRanges are the three blocks' [start, end) in a scanned structure.
// Each is written once, holds declarations only (no nested rule), and the
// dark media query holds its block and nothing else.
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
		end := blockEnd(css, i)
		if body := css[i+strings.Index(css[i:], "{")+1 : end-1]; strings.ContainsAny(body, "{}") {
			return nil, fmt.Errorf("token block %q holds a nested rule", open)
		}
		out = append(out, [2]int{i, end})
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

// property is the name of the declaration at i, lower case.
func property(css string, i int) string {
	start, _ := declAt(css, i)
	name, _, _ := strings.Cut(css[start:i], ":")
	return strings.ToLower(strings.TrimSpace(name))
}

func lineOf(css string, i int) int { return strings.Count(css[:i], "\n") + 1 }

var (
	hexColour = regexp.MustCompile(`#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{4}|[0-9a-fA-F]{3})\b`)
	colourFn  = regexp.MustCompile(`(?i)\b(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch|color|light-dark)\(`)
	ident     = regexp.MustCompile(`(?:^|[^\w-])(-?[A-Za-z][\w-]*)`)
	dataURL   = regexp.MustCompile(`(?i)\burl\(\s*["']?\s*data:`)
	setsProp  = regexp.MustCompile(`(--[\w-]+)\s*:`)
)

// namedColours are CSS's colour keywords, its system colours (the
// deprecated ones too, but Background, which is also a property's name) and
// the common vendor ones, lower case. transparent, currentColor and inherit
// are allowed and left out.
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
graytext highlight highlighttext linktext mark marktext selecteditem selecteditemtext visitedtext
activeborder activecaption appworkspace buttonhighlight buttonshadow captiontext inactiveborder
inactivecaption inactivecaptiontext infobackground infotext menu menutext scrollbar threeddarkshadow
threedface threedhighlight threedlightshadow threedshadow window windowframe windowtext
-webkit-link -webkit-activelink -webkit-focus-ring-color -webkit-text -moz-hyperlinktext
-moz-activehyperlinktext -moz-visitedhyperlinktext -moz-field -moz-fieldtext -moz-dialog -moz-dialogtext
-moz-buttondefault -moz-cellhighlight -moz-cellhighlighttext -moz-default-color -moz-default-background-color`)

// nameProps take names a stylesheet makes up (an animation called
// "highlight", a grid area called "field"), not colours.
var nameProps = strings.Fields(`animation animation-name font-family transition transition-property will-change
counter-reset counter-increment counter-set grid-area grid-row grid-column grid-row-start grid-row-end
grid-column-start grid-column-end view-transition-name container-name anchor-name position-anchor`)

// colourLiterals lists every colour literal of css that is not a token's
// value in one of the three token blocks, by line, or why the blocks
// cannot be told apart. A data: URL is one too: an image's colours cannot
// be tokens.
func colourLiterals(css string) []string {
	structure, code := scan(css)
	ranges, err := tokenRanges(structure)
	if err != nil {
		return []string{err.Error()}
	}
	var found []string
	report := func(i int, lit string) {
		if inValue(structure, i) && !(inRanges(ranges, i) && strings.HasPrefix(property(structure, i), "--")) {
			found = append(found, fmt.Sprintf("line %d: %s", lineOf(css, i), lit))
		}
	}
	for _, m := range dataURL.FindAllStringIndex(structure, -1) {
		report(m[0], "a data: URL")
	}
	for _, re := range []*regexp.Regexp{hexColour, colourFn} {
		for _, m := range re.FindAllStringIndex(code, -1) {
			report(m[0], code[m[0]:m[1]])
		}
	}
	for _, m := range ident.FindAllStringSubmatchIndex(code, -1) {
		w := code[m[2]:m[3]]
		if slices.Contains(namedColours, strings.ToLower(w)) && !slices.Contains(nameProps, property(structure, m[2])) {
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
// are not light ones, tokens set again outside the token blocks, and any
// other way of styling one theme only: a theme selector or media query
// beyond the blocks' own, light-dark(), color-scheme set elsewhere.
func themeMismatches(css string) []string {
	structure, code := scan(css)
	r, err := tokenRanges(structure)
	if err != nil {
		return []string{err.Error()}
	}
	var out []string
	light, media, toggle := tokens(structure, r[0]), tokens(structure, r[1]), tokens(structure, r[2])
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
	for _, m := range setsProp.FindAllStringSubmatchIndex(structure, -1) {
		name := structure[m[2]:m[3]]
		start, ok := declAt(structure, m[0])
		if _, token := light[name]; token && ok && strings.TrimSpace(structure[start:m[0]]) == "" && !inRanges(r, m[0]) {
			out = append(out, fmt.Sprintf("line %d: %s is set outside the token blocks", lineOf(css, m[0]), name))
		}
	}
	lower := strings.ToLower(code)
	for word, n := range map[string]int{"prefers-color-scheme": 1, "data-theme": 3, "light-dark(": 0} {
		if got := strings.Count(lower, word); got != n {
			out = append(out, fmt.Sprintf("%s is written %d times; only the token blocks may use it", word, got))
		}
	}
	for i := 0; ; {
		j := strings.Index(lower[i:], "color-scheme")
		if j < 0 {
			break
		}
		i += j + 1
		if at := i - 1; property(structure, at+len("color-scheme")) == "color-scheme" && !inRanges(r, at) {
			out = append(out, fmt.Sprintf("line %d: color-scheme is set outside the token blocks", lineOf(css, at)))
		}
	}
	slices.Sort(out)
	return out
}

// M33 task 1 (Review focus 1): outside the three token blocks the
// stylesheet has no colour literal (#hex, a colour function, a colour
// keyword but transparent, currentColor and inherit, a data: URL), and
// inside them only tokens' values are colours.
func TestNoColourLiteralsOutsideTokens(t *testing.T) {
	if found := colourLiterals(stylesheet(t)); len(found) > 0 {
		t.Fatalf("%d colour literals outside the token blocks:\n%s", len(found), strings.Join(found, "\n"))
	}
}

// The two dark blocks (the system's dark and the toggle's) set the same
// tokens to the same values; every dark token is a light one too; nothing
// outside the blocks styles one theme only.
func TestBothDarkBlocksHaveSameTokens(t *testing.T) {
	if out := themeMismatches(stylesheet(t)); len(out) > 0 {
		t.Fatal(strings.Join(out, "\n"))
	}
}

// The two checks above catch a colour wherever it is written (the gaps
// the M33 task and branch reviews found), and leave alone a stylesheet
// that keeps the rule.
func TestThemeChecksCatchEscapes(t *testing.T) {
	sheet := func(light, media, toggle, rest string) string {
		return ":root, .preview-doc[data-theme=\"light\"] {\n  --ink: #0F172A;\n  color-scheme: light;\n" + light + "}\n\n" +
			"@media (prefers-color-scheme: dark) {\n  :root:not([data-theme=\"light\"]) {\n    --ink: #EDEFF2;\n  }\n" + media + "}\n\n" +
			":root[data-theme=\"dark\"] {\n  --ink: #EDEFF2;\n" + toggle + "}\n\n" +
			"#add, .x:hover #add { color: var(--ink); }\n" +
			"@font-face { font-family: \"Plex\", \"Arial Black\"; src: url(\"fonts/a;b.woff2\") format(\"woff2\"); }\n" +
			".a::before { content: \"Red\"; } .b { background: url(img/white.png); } .c { mask: url(#abc); }\n" +
			".d { grid-template-areas: \"label field\"; animation: highlight 1s; transition: background 0.2s; }\n" + rest
	}
	clean := sheet("", "", "", "")
	if found := colourLiterals(clean); len(found) > 0 {
		t.Fatalf("a clean sheet: %v", found)
	}
	if out := themeMismatches(clean); len(out) > 0 {
		t.Fatalf("a clean sheet: %v", out)
	}
	for name, css := range map[string]string{
		"a rule in the dark media query":           sheet("", "  .x { color: var(--ink); }\n", "", ""),
		"a second toggle block":                    sheet("", "", "", ":root[data-theme=\"dark\"] {\n  --ink: #EDEFF2;\n}\n"),
		"a property, not a token, in a block":      sheet("  background: #FFFFFF;\n", "", "", ""),
		"a rule nested in a block":                 sheet("  .x { --ink: #FF0000; }\n", "", "", ""),
		"upper-case rgb":                           sheet("", "", "", ".x { color: RGB(1, 2, 3); }\n"),
		"oklch":                                    sheet("", "", "", ".x { color: oklch(0.5 0.1 200); }\n"),
		"a system colour":                          sheet("", "", "", ".x { background: Canvas; }\n"),
		"a deprecated system colour":               sheet("", "", "", ".x { color: WindowText; }\n"),
		"a vendor colour":                          sheet("", "", "", ".x { color: -webkit-link; }\n"),
		"a data URI":                               sheet("", "", "", ".x { background: url(\"data:image/svg+xml,%3Csvg fill=%22red%22/%3E\"); }\n"),
		"an unquoted data URI":                     sheet("", "", "", ".x { background: url(data:image/svg+xml;utf8,%3Csvg%20fill=%23ABC/%3E); }\n"),
		"a nested rule before a declaration":       sheet("", "", "", ".a { .b { margin: 0; } color: red; }\n"),
		"a colour after an escaped quote":          sheet("", "", "", "q::before { content: \"\\\"\"; }\n.x { color: red; }\n"),
		"a colour after a /* in a string":          sheet("", "", "", ".a::before { content: \"/*\"; }\n.x { color: red; }\n"),
		"a colour after a /* in an unquoted url()": sheet("", "", "", ".a { background: url(a/*b.png); }\n.x { color: red; }\n"),
	} {
		if len(colourLiterals(css)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	for name, css := range map[string]string{
		"a second toggle block that sets a token to a token": sheet("", "", "", ":root[data-theme=\"dark\"] {\n  --ink: var(--ink);\n}\n"),
		"a rule that sets a token again":                     sheet("", "", "", "html[data-theme=\"dark\"] { --ink: var(--ink); }\n"),
		"a dark media rule that sets a token":                sheet("", "  .x { --ink: var(--ink); }\n", "", ""),
		"a dark-only rule with no colour":                    sheet("", "", "", ":root[data-theme=\"dark\"] .preview-doc { color: inherit; }\n"),
		"a second dark media query":                          sheet("", "", "", "@media (prefers-color-scheme: dark) { .x { background: var(--ink); } }\n"),
		"light-dark()":                                       sheet("", "", "", ".x { color: light-dark(var(--ink), var(--ink)); }\n"),
		"color-scheme set elsewhere":                         sheet("", "", "", ".x { color-scheme: dark; }\n"),
		"a rule nested in a dark block":                      sheet("", "", "  .preview-doc { --ink: #EDEFF2; }\n", ""),
	} {
		if len(themeMismatches(css)) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
}
