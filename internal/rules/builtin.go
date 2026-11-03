package rules

import (
	"regexp"
	"strings"

	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
)

var delimRow = regexp.MustCompile(`^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$`)

func (r Rule) builtin(d Doc, cfg config.Config) []Violation {
	var vs []Violation
	add := func(target, detail, q string) {
		msg := detail
		if r.Message != "" {
			msg = r.Message + " (" + detail + ")"
		}
		vs = append(vs, r.v(target, msg, q))
	}
	switch r.Check {
	case "table-cells-no-backticks":
		for _, p := range parts(d, r.Target) {
			switch p.Kind {
			case "details":
				if strings.Contains(p.Text, "`") {
					add(p.Target, "backticks are not allowed in table fields", p.Text)
				}
			case "section":
				for _, line := range tableRows(p.Text) {
					if strings.Contains(line, "`") {
						add(p.Target, "backticks are not allowed in table cells", line)
					}
				}
			}
		}
	case "cvss-explained":
		v, err := cvss.Parse(d.CVSS)
		if err != nil {
			return nil
		}
		for _, mt := range cvss.Metrics {
			if cfg.NonStandard(mt.Key, v[mt.Key]) && strings.TrimSpace(d.CVSSReasons[mt.Key]) == "" {
				add("cvss", "non-standard CVSS value for "+mt.Name+" needs an explanation", mt.Key+":"+v[mt.Key])
			}
		}
	case "not-empty":
		for _, p := range parts(d, r.Target) {
			if strings.TrimSpace(p.Text) == "" {
				add(p.Target, p.Target+" is empty", "")
			}
		}
	}
	return vs
}

// tableRows returns the lines of GFM tables outside fenced code blocks.
func tableRows(body string) []string {
	lines := strings.Split(body, "\n")
	mask := finding.FenceMask(body)
	isTable := make([]bool, len(lines))
	for i, l := range lines {
		if mask[i] || !delimRow.MatchString(l) || !strings.Contains(l, "-") || !strings.Contains(l, "|") {
			continue
		}
		// a delimiter row: the header above and following pipe rows belong to the table
		if i > 0 && !mask[i-1] && strings.Contains(lines[i-1], "|") {
			isTable[i-1] = true
		}
		for j := i + 1; j < len(lines) && !mask[j] && strings.Contains(lines[j], "|") && strings.TrimSpace(lines[j]) != ""; j++ {
			isTable[j] = true
		}
	}
	var out []string
	for i, l := range lines {
		if isTable[i] {
			out = append(out, l)
		}
	}
	return out
}
