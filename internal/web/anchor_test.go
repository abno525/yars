package web

import "testing"

// A section's anchor keeps the letters of any script, so sections named in
// Cyrillic, Greek or CJK get anchors of their own; ASCII names keep the
// anchors they had (backlog, Core).
func TestAnchorsKeepLetters(t *testing.T) {
	seen := map[string]string{}
	for _, name := range []string{"Описание", "Шаги", "Ανάλυση", "影响", "复现步骤", "Impact"} {
		a := anchor(name)
		if a == "" || a == "finding" {
			t.Errorf("%s: anchor %q", name, a)
		}
		if other, ok := seen[a]; ok {
			t.Errorf("%s and %s share the anchor %q", name, other, a)
		}
		seen[a] = name
	}
	for name, want := range map[string]string{"Impact": "impact", "Steps to reproduce": "steps-to-reproduce", "CVSS (3.1)": "cvss-3-1", "Описание уязвимости": "описание-уязвимости"} {
		if got := anchor(name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	long := "A section whose name is longer than forty characters, one"
	if anchor(long) == anchor(long[:len(long)-3]+"two") {
		t.Error("two long names share an anchor")
	}
}
