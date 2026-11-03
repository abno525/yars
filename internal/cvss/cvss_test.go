package cvss

import (
	"strings"
	"testing"
)

func TestScore(t *testing.T) {
	cases := map[string]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "9.8",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": "6.1",
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": "7.8",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N": "7.4",
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": "9.9",
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": "1.6",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": "0.0",
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N": "5.5",
	}
	for vec, want := range cases {
		v, err := Parse(vec)
		if err != nil {
			t.Fatalf("Parse(%s): %v", vec, err)
		}
		s, err := Score(v)
		if err != nil {
			t.Fatalf("Score(%s): %v", vec, err)
		}
		if got := FormatScore(s); got != want {
			t.Errorf("%s: got %s want %s", vec, got, want)
		}
	}
}

func TestRating(t *testing.T) {
	cases := map[float64]string{0: "info", 0.1: "low", 3.9: "low", 4.0: "medium", 6.9: "medium",
		7.0: "high", 8.9: "high", 9.0: "critical", 10: "critical"}
	for s, want := range cases {
		if got := Rating(s); got != want {
			t.Errorf("Rating(%v) = %s want %s", s, got, want)
		}
	}
}

func TestParse(t *testing.T) {
	ok := []string{
		"  cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h ",
		"CVSS:3.1/C:H/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H",
		"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	const canon = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	for _, s := range ok {
		v, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if v.String() != canon {
			t.Errorf("Parse(%q).String() = %s", s, v.String())
		}
	}
	bad := map[string]string{
		"8.1":                                               "prefix",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N":                 "prefix",
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":               "prefix",
		"CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H":           "AC",
		"CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "duplicate",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":      "AV",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P":  "E",
		"":                  "prefix",
		"CVSS:3.1/AV:N/ACL": "ACL",
	}
	for s, frag := range bad {
		_, err := Parse(s)
		if err == nil {
			t.Errorf("Parse(%q): expected error", s)
			continue
		}
		if !strings.Contains(err.Error(), frag) {
			t.Errorf("Parse(%q) error %q lacks %q", s, err, frag)
		}
	}
}

func TestParsePartial(t *testing.T) {
	v, err := ParsePartial("CVSS:3.1/AV:N/AC:L")
	if err != nil {
		t.Fatal(err)
	}
	if v.Complete() {
		t.Error("partial vector reported complete")
	}
	if _, err := Score(v); err == nil {
		t.Error("Score of partial vector should fail")
	}
	if v.String() != "CVSS:3.1/AV:N/AC:L" {
		t.Errorf("String = %s", v.String())
	}
}

func TestDerive(t *testing.T) {
	if got := Derive("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "low"); got != "critical" {
		t.Errorf("got %s", got)
	}
	if got := Derive("8.1", "medium"); got != "medium" {
		t.Errorf("got %s", got)
	}
	if got := Derive("", "high"); got != "high" {
		t.Errorf("got %s", got)
	}
}

func TestNames(t *testing.T) {
	if MetricName("AV") != "Attack Vector" || ValueName("AV", "N") != "Network" || ValueName("S", "C") != "Changed" {
		t.Error("names wrong")
	}
	if len(Metrics) != 8 || Metrics[0].Key != "AV" || Metrics[7].Key != "A" {
		t.Error("metric order wrong")
	}
}
