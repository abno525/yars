package index

import (
	"testing"

	"github.com/abno525/yars/internal/finding"
)

func TestTrigramSimilarity(t *testing.T) {
	a, b := Trigrams("Missing HSTS header"), Trigrams("missing  hsts-header!")
	if Similarity(a, b) != 1 {
		t.Fatalf("same words: %v", Similarity(a, b))
	}
	if s := Similarity(Trigrams("Missing HSTS header"), Trigrams("Missing HSTS headers")); s < 0.6 || s >= 1 {
		t.Fatalf("plural: %v", s)
	}
	if s := Similarity(Trigrams("Missing HSTS header"), Trigrams("SQL injection in login")); s >= 0.2 {
		t.Fatalf("unrelated: %v", s)
	}
	if Similarity(Trigrams(""), Trigrams("")) != 0 {
		t.Fatal("empty sets are not similar")
	}
}

func TestSimilar(t *testing.T) {
	ix, s := fixture(t)
	mk := func(eng, title string, assets ...finding.Asset) string {
		f, err := s.CreateFinding(eng, title, alice)
		if err != nil {
			t.Fatal(err)
		}
		if len(assets) > 0 {
			if err := s.UpdateAssets(eng, f.Dir, assets, "", alice); err != nil {
				t.Fatal(err)
			}
		}
		return f.F.Meta.ID
	}
	hsts := mk("acme", "Missing HSTS header", finding.Asset{Host: "app.acme.example"})
	mk("acme", "Missing HSTS headers")
	mk("acme", "SQL injection in login")
	mk("other", "Missing HSTS header") // another engagement
	got, err := ix.Similar("acme", "missing hsts header", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != hsts || got[0].Pct != 100 || got[1].Title != "Missing HSTS headers" {
		t.Fatalf("matches %+v", got)
	}
	// the finding itself is left out
	if got, _ := ix.Similar("acme", "Missing HSTS header", nil, hsts); len(got) != 1 || got[0].ID == hsts {
		t.Fatalf("exclude %+v", got)
	}
	// assets lift a weaker title match over the line
	weak := "HSTS header not set"
	if got, _ := ix.Similar("acme", weak, nil, ""); len(got) != 0 {
		t.Fatalf("weak title alone %+v", got)
	}
	if got, _ := ix.Similar("acme", weak, []finding.Asset{{Host: "app.acme.example"}}, ""); len(got) != 1 || got[0].ID != hsts {
		t.Fatalf("with assets %+v", got)
	}
	// at most five, best first
	for range 6 {
		mk("acme", "Open redirect in login")
	}
	if got, _ := ix.Similar("acme", "Open redirect in login", nil, ""); len(got) != 5 {
		t.Fatalf("top five: %d", len(got))
	}
}
