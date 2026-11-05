package finding

import (
	"strings"
	"testing"
)

func TestAssetsParseAndSet(t *testing.T) {
	src := "---\nid: F-001\ntitle: XSS\n# keep me\nassets:\n    - host: app.example\n      url: https://app.example/search\n      port: 443\n      note: main box\n---\n\n## Impact\n\nx\n"
	f, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Meta.Assets) != 1 {
		t.Fatalf("assets %+v", f.Meta.Assets)
	}
	a := f.Meta.Assets[0]
	if a.Host != "app.example" || a.URL != "https://app.example/search" || a.Port != "443" || a.Note != "main box" {
		t.Fatalf("asset %+v", a)
	}
	if _, ok := f.Meta.Extra["assets"]; ok {
		t.Fatal("assets also in Extra")
	}
	// unchanged: byte-identical
	if string(f.Bytes()) != src {
		t.Fatalf("round trip changed:\n%s", f.Bytes())
	}
	if err := f.SetMeta("assets", []Asset{{Host: "a.example"}, {URL: "https://b.example/", Port: "8443"}}); err != nil {
		t.Fatal(err)
	}
	out := string(f.Bytes())
	if !strings.Contains(out, "# keep me") || !strings.Contains(out, "host: a.example") || strings.Contains(out, "note:") {
		t.Fatalf("set:\n%s", out)
	}
	g, err := Parse(f.Bytes())
	if err != nil || len(g.Meta.Assets) != 2 || g.Meta.Assets[1].Port != "8443" {
		t.Fatalf("reparse %+v %v", g.Meta.Assets, err)
	}
	if err := g.SetMeta("assets", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(g.Bytes()), "assets") {
		t.Fatalf("not removed:\n%s", g.Bytes())
	}
}

func TestAssetKey(t *testing.T) {
	a := Asset{Host: "App.Example ", URL: "https://app.example/x", Port: "443", Note: "n1"}
	b := Asset{Host: "app.example", URL: "https://app.example/x", Port: "443", Note: "other"}
	if a.Key() != b.Key() {
		t.Fatalf("%q != %q", a.Key(), b.Key())
	}
	if a.Key() == (Asset{Host: "app.example", Port: "80"}).Key() {
		t.Fatal("different assets share a key")
	}
}
