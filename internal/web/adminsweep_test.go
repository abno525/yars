package web

import (
	"slices"
	"strings"
	"testing"
)

// Graphite keeps no navy from the light theme. The light theme's navy
// (#13233F, #1E3A66, #2E4A78) was the old Navy dark theme's too, so the
// tokens that carry it and had no dark value (--navy, --navy-600,
// --head-field-line) kept it when Graphite replaced the dark values
// (5298530 changed the dark tokens only): the top bar's select, Go to and
// Log out had navy borders, the Pentest, Complete, AI and role tags, the
// done workflow steps, toasts and toggles navy fills on near-black. Every
// light token that holds one of them has a dark value, none of them a navy:
// --navy is Graphite's Complete (--bar-complete, which the light theme also
// gives the navy; the confirmed lead's tag already wears it under white
// text), --head-field-line Graphite's field border (--field-line), and
// --navy-600 the step between that Complete and Verification, as in light.
func TestGraphiteHasNoNavy(t *testing.T) {
	css, _ := scan(stylesheet(t))
	r, err := tokenRanges(css)
	if err != nil {
		t.Fatal(err)
	}
	light, dark := tokens(css, r[0]), tokens(css, r[1])
	navy := []string{"#13233F", "#1E3A66", "#2E4A78"}
	isNavy := func(v string) bool {
		return slices.ContainsFunc(navy, func(n string) bool { return strings.EqualFold(n, v) })
	}
	for k, v := range light {
		if !isNavy(v) {
			continue
		}
		if d, ok := dark[k]; !ok {
			t.Errorf("%s keeps the light theme's %s in dark", k, v)
		} else if isNavy(d) {
			t.Errorf("%s is %s in dark", k, d)
		}
	}
	for tok, like := range map[string]string{"--navy": "--bar-complete", "--head-field-line": "--field-line"} {
		if dark[tok] == "" || dark[tok] != dark[like] {
			t.Errorf("dark %s is %q, not %s's %q", tok, dark[tok], like, dark[like])
		}
	}
}
