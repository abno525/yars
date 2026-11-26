package finding

import (
	"reflect"
	"strings"
	"testing"
)

const commented = "---\n" +
	"id: F-001\n" +
	"# owner note\n" +
	"title: SQLi\n" +
	"custom_key: keep me   # trailing comment\n" +
	"severity: high\n" +
	"---\n\n## Description\n\nbody text\n"

func TestSetMetaKeepsComments(t *testing.T) {
	f, err := Parse([]byte(commented))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetMeta("severity", "critical"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetMeta("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"); err != nil {
		t.Fatal(err)
	}
	out := string(f.Bytes())
	for _, want := range []string{"# owner note", "custom_key: keep me", "# trailing comment", "severity: critical"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	ti, ci, si, vi := strings.Index(out, "title:"), strings.Index(out, "custom_key"), strings.Index(out, "severity:"), strings.Index(out, "cvss:")
	if !(ti < ci && ci < si && si < vi) {
		t.Fatalf("order wrong:\n%s", out)
	}
	g, err := Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if g.Meta.Severity != "critical" || f.Meta.Severity != "critical" {
		t.Fatalf("severity %q %q", g.Meta.Severity, f.Meta.Severity)
	}
	if b, _ := g.Section("Description"); b != "\nbody text\n" {
		t.Fatalf("body %q", b)
	}
}

// Untouched front-matter lines must survive byte-for-byte.
func TestSetMetaByteIdentical(t *testing.T) {
	in := "---\n" +
		"id: F-001\n" +
		"title: SQLi\n" +
		"custom_key: keep me   # trailing comment\n" +
		"\n" +
		"# reviewers block\n" +
		"reviewers:\n" +
		"- bob\n" +
		"- carol\n" +
		"severity: high  # was medium\n" +
		"retest:\n" +
		"  source: old/F-001\n" +
		"  result: not_fixed\n" +
		"---\n\n## Description\n\nbody\n"
	f, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetMeta("severity", "critical"); err != nil {
		t.Fatal(err)
	}
	if err := f.SetMeta("details", OrderedMap([]string{"Location"}, map[string]string{"Location": "a\nb"})); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(in, "severity: high  # was medium\n", "severity: critical # was medium\n", 1)
	want = strings.Replace(want, "---\n\n## Description", "details:\n    Location: |-\n        a\n        b\n---\n\n## Description", 1)
	if got := string(f.Bytes()); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if err := f.SetMeta("reviewers", nil); err != nil {
		t.Fatal(err)
	}
	want2 := strings.Replace(want, "reviewers:\n- bob\n- carol\n", "", 1)
	if got := string(f.Bytes()); got != want2 {
		t.Fatalf("after delete got:\n%s\nwant:\n%s", got, want2)
	}
	l, _ := f.Legacy()
	if f.Meta.Severity != "critical" || l.Reviewers != nil || l.Retest == nil || l.Retest.Result != "not_fixed" {
		t.Fatalf("meta %+v legacy %+v", f.Meta, l)
	}
}

func TestSetMetaDelete(t *testing.T) {
	f, _ := Parse([]byte(commented))
	if err := f.SetMeta("severity", nil); err != nil {
		t.Fatal(err)
	}
	out := string(f.Bytes())
	if strings.Contains(out, "severity") || !strings.Contains(out, "custom_key: keep me") {
		t.Fatalf("got:\n%s", out)
	}
	if err := f.SetMeta("nonexistent", nil); err != nil {
		t.Fatal(err)
	}
}

func TestSetMetaCRLF(t *testing.T) {
	f, _ := Parse([]byte(strings.ReplaceAll(commented, "\n", "\r\n")))
	f.SetMeta("severity", "low")
	out := string(f.Bytes())
	if strings.Count(out, "\r\n") != strings.Count(out, "\n") {
		t.Fatalf("mixed line endings:\n%q", out)
	}
}

func TestSetMetaOnNew(t *testing.T) {
	f := New("F-001", "T", "a", []string{"Description"})
	if err := f.SetMeta("details", OrderedMap([]string{"Location"}, map[string]string{"Location": "x"})); err != nil {
		t.Fatal(err)
	}
	g, err := Parse(f.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if g.Meta.Details["Location"] != "x" || g.Meta.ID != "F-001" {
		t.Fatalf("meta %+v", g.Meta)
	}
}

// MetaProblem names every front matter Parse reads but SetMeta cannot
// edit, and no other: it is what a push is held to.
func TestMetaProblem(t *testing.T) {
	bad := []struct{ name, meta, key string }{
		{"flow mapping", "{id: F-001, title: X, author: alice}\n", "title"},
		{"indented keys", "  id: F-001\n  title: X\n", "title"},
		{"value closed at the first column", "id: F-001\nassets: [\n  {host: a}\n]\ntitle: X\n", "assets"},
		{"comment inside a value", "id: F-001\nassets:\n    - host: a\n# note\n    - host: b\ntitle: X\n", "assets"},
	}
	for _, c := range bad {
		f, err := Parse([]byte("---\n" + c.meta + "---\n\n## Description\n\nx\n"))
		if err != nil {
			t.Fatalf("%s: Parse: %v", c.name, err)
		}
		if p := f.MetaProblem(); p == "" {
			t.Errorf("%s: no problem named", c.name)
		}
		var v any = "Y"
		if c.key == "assets" {
			v = []Asset{{Host: "z"}}
		}
		if err := f.SetMeta(c.key, v); err == nil {
			// SetMeta did not refuse: then it wrote a file that reads otherwise
			g, perr := Parse(f.Bytes())
			if perr == nil && (c.key == "title" && g.Meta.Title == "Y" || c.key == "assets" && reflect.DeepEqual(g.Meta.Assets, []Asset{{Host: "z"}})) {
				t.Errorf("%s: SetMeta edits it; it is no problem", c.name)
			}
		}
	}
	good := []string{
		"",
		"id: F-001\n# owner note\ntitle: SQLi\ncustom_key: keep me   # trailing comment\nseverity: high\n",
		"id: F-001\ntitle: |\n    two\n\n    lines\nseverity: high\n",
		"id: F-001\nassets: [{host: a}, {host: b}]\ntitle: X\n",
		"id: F-001\nassets:\n- host: a\n  port: \"443\"\n- host: b\ntitle: X\n",
		"id: F-001\nassets:\n    - host: a\n    # note\n    - host: b\n\ntitle: X\n# end\n",
		"\"id\": F-001\ndetails:\n    Location: /x\n    CWE: \"89\"\n",
	}
	for _, meta := range good {
		f, err := Parse([]byte("---\n" + meta + "---\n\n## Description\n\nx\n"))
		if err != nil {
			t.Fatalf("Parse %q: %v", meta, err)
		}
		if p := f.MetaProblem(); p != "" {
			t.Errorf("%q: %s", meta, p)
		}
		if err := f.SetMeta("title", "Y"); err != nil {
			t.Errorf("%q: SetMeta: %v", meta, err)
		}
		if err := f.SetMeta("assets", []Asset{{Host: "z"}}); err != nil {
			t.Errorf("%q: SetMeta assets: %v", meta, err)
		}
		if g, err := Parse(f.Bytes()); err != nil || g.Meta.Title != "Y" || len(g.Meta.Assets) != 1 || g.Meta.Assets[0].Host != "z" {
			t.Errorf("%q: after SetMeta %v:\n%s", meta, err, f.Bytes())
		}
	}
	if New("F-001", "T", "a", nil).MetaProblem() != "" {
		t.Error("a new finding has a problem")
	}
}

func TestOrderedMapMultiline(t *testing.T) {
	m := map[string]string{"B": "a\nb", "A": "plain", "Z": "extra2", "Y": "extra1"}
	f := New("F-001", "T", "a", nil)
	f.SetMeta("details", OrderedMap([]string{"B", "A", "Missing"}, m))
	out := string(f.Bytes())
	g, err := Parse([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Meta.Details, m) {
		t.Fatalf("details %v\n%s", g.Meta.Details, out)
	}
	b, a, y, z := strings.Index(out, "B:"), strings.Index(out, "A:"), strings.Index(out, "Y:"), strings.Index(out, "Z:")
	if !(b < a && a < y && y < z) {
		t.Fatalf("order:\n%s", out)
	}
	if !strings.Contains(out, "B: |") {
		t.Fatalf("multiline not literal:\n%s", out)
	}
}
