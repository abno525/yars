package web

import (
	"regexp"
	"strconv"
	"testing"
)

// The checks tables (open and dismissed) leave the Message column at least
// 176px of the 632px table (1440x900): their fixed columns win over the
// shared .table widths and add up to at most 456px.
func TestChecktableMessageWidth(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	width := func(col string) int {
		t.Helper()
		m := regexp.MustCompile(`(?m)^\.table\.checktable th\.` + col + ` \{ width: (\d+)px; \}`).FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("no .table.checktable th.%s width", col)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	open := width("c-level") + width("c-quote") + width("c-where") + width("c-act")
	dismissed := width("c-level") + width("c-reason") + width("c-where") + width("c-act")
	if open > 456 || dismissed > 456 {
		t.Fatalf("fixed columns %dpx (open) and %dpx (dismissed) of 632px", open, dismissed)
	}
	if width("c-act") < 128 {
		t.Fatal("the Dismiss button (96px) and its padding do not fit")
	}
}
