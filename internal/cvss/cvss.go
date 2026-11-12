// Package cvss parses and scores CVSS v3.1 base vectors (FIRST specification).
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Vector maps a base metric key (e.g. "AV") to its value code (e.g. "N").
type Vector map[string]string

type Value struct{ Code, Name string }

type Metric struct {
	Key, Name string
	Values    []Value
}

var cia = []Value{{"N", "None"}, {"L", "Low"}, {"H", "High"}}

// Metrics lists the base metrics in canonical vector order.
var Metrics = []Metric{
	{"AV", "Attack Vector", []Value{{"N", "Network"}, {"A", "Adjacent"}, {"L", "Local"}, {"P", "Physical"}}},
	{"AC", "Attack Complexity", []Value{{"L", "Low"}, {"H", "High"}}},
	{"PR", "Privileges Required", []Value{{"N", "None"}, {"L", "Low"}, {"H", "High"}}},
	{"UI", "User Interaction", []Value{{"N", "None"}, {"R", "Required"}}},
	{"S", "Scope", []Value{{"U", "Unchanged"}, {"C", "Changed"}}},
	{"C", "Confidentiality", cia},
	{"I", "Integrity", cia},
	{"A", "Availability", cia},
}

func metric(key string) (Metric, bool) {
	for _, m := range Metrics {
		if m.Key == key {
			return m, true
		}
	}
	return Metric{}, false
}

func MetricName(key string) string {
	if m, ok := metric(key); ok {
		return m.Name
	}
	return key
}

func ValueName(key, code string) string {
	m, _ := metric(key)
	for _, v := range m.Values {
		if v.Code == code {
			return v.Name
		}
	}
	return code
}

// Valid reports whether code is a legal value for metric key.
func Valid(key, code string) bool {
	m, ok := metric(key)
	if !ok {
		return false
	}
	for _, v := range m.Values {
		if v.Code == code {
			return true
		}
	}
	return false
}

// Parse parses a complete CVSS 3.0/3.1 base vector (any metric order, any case).
func Parse(s string) (Vector, error) {
	v, err := ParsePartial(s)
	if err != nil {
		return nil, err
	}
	for _, m := range Metrics {
		if _, ok := v[m.Key]; !ok {
			return nil, fmt.Errorf("missing metric %s (%s)", m.Key, m.Name)
		}
	}
	return v, nil
}

// codes lists a metric's values for a message: "N, L or H".
func (m Metric) codes() string {
	cs := make([]string, len(m.Values))
	for i, v := range m.Values {
		cs[i] = v.Code
	}
	return strings.Join(cs[:len(cs)-1], ", ") + " or " + cs[len(cs)-1]
}

// ParsePartial is Parse but allows missing metrics.
func ParsePartial(s string) (Vector, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	var rest string
	switch {
	case strings.HasPrefix(s, "CVSS:3.1/"):
		rest = s[len("CVSS:3.1/"):]
	case strings.HasPrefix(s, "CVSS:3.0/"):
		rest = s[len("CVSS:3.0/"):]
	default:
		return nil, fmt.Errorf("not a CVSS 3.x vector: missing CVSS:3.1/ prefix")
	}
	v := Vector{}
	for _, part := range strings.Split(rest, "/") {
		if part == "" {
			continue
		}
		k, val, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("invalid component %s", part)
		}
		if _, known := metric(k); !known {
			return nil, fmt.Errorf("unknown metric %s (only base metrics are supported)", k)
		}
		if _, dup := v[k]; dup {
			return nil, fmt.Errorf("duplicate metric %s", k)
		}
		if !Valid(k, val) {
			m, _ := metric(k)
			return nil, fmt.Errorf("invalid value %s for %s (%s): use %s", val, k, m.Name, m.codes())
		}
		v[k] = val
	}
	return v, nil
}

func (v Vector) Complete() bool {
	for _, m := range Metrics {
		if _, ok := v[m.Key]; !ok {
			return false
		}
	}
	return true
}

// String returns the canonical CVSS:3.1 form with the metrics present.
func (v Vector) String() string {
	var b strings.Builder
	b.WriteString("CVSS:3.1")
	for _, m := range Metrics {
		if val, ok := v[m.Key]; ok {
			b.WriteString("/" + m.Key + ":" + val)
		}
	}
	return b.String()
}

var weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

func roundup(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// Score computes the CVSS 3.1 base score.
func Score(v Vector) (float64, error) {
	if !v.Complete() {
		return 0, fmt.Errorf("incomplete vector")
	}
	changed := v["S"] == "C"
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[v["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[v["PR"]]
	}
	iss := 1 - (1-weights["C"][v["C"]])*(1-weights["I"][v["I"]])*(1-weights["A"][v["A"]])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	expl := 8.22 * weights["AV"][v["AV"]] * weights["AC"][v["AC"]] * pr * weights["UI"][v["UI"]]
	if impact <= 0 {
		return 0, nil
	}
	if changed {
		return roundup(math.Min(1.08*(impact+expl), 10)), nil
	}
	return roundup(math.Min(impact+expl, 10)), nil
}

// Rating maps a score to a severity name.
func Rating(score float64) string {
	switch {
	case score == 0:
		return "info"
	case score < 4.0:
		return "low"
	case score < 7.0:
		return "medium"
	case score < 9.0:
		return "high"
	}
	return "critical"
}

func FormatScore(f float64) string { return fmt.Sprintf("%.1f", f) }

// Derive returns the rating of vector when it is a complete valid base
// vector, otherwise the stored severity.
func Derive(vector, stored string) string {
	v, err := Parse(vector)
	if err != nil {
		return stored
	}
	s, _ := Score(v)
	return Rating(s)
}
