package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/rules"
)

func (e *env) rules(t *testing.T, yaml string, scripts map[string]string) {
	t.Helper()
	rd := filepath.Join(e.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(yaml), 0o644)
	for name, body := range scripts {
		os.WriteFile(filepath.Join(rd, name), []byte("#!/bin/sh\n"+body), 0o755)
	}
	eng := rules.NewEngine(rd, e.srv.Cfg)
	e.srv.Rules = eng
	e.srv.Store.Linter = eng
}

func TestChecksPanel(t *testing.T) {
	e := setup(t)
	e.rules(t, `
- id: title-word
  target: title
  regex_forbid: 'injection'
  message: Avoid the word injection
- id: scripted
  script: check.sh
  level: warning
`, map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"script says hi"}]'` + "\n"})
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `id="checks"`) || !strings.Contains(b, "Avoid the word injection") || strings.Contains(b, "script says hi") {
		t.Fatalf("checks panel (fast only):\n%s", b)
	}
	if !strings.Contains(b, "Avoid the word injection") || !strings.Contains(b[strings.Index(b, `id="workflow"`):], "Avoid the word injection") {
		t.Fatal("workflow bar doesn't list rule errors")
	}
	rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "script says hi") {
		t.Fatalf("full run code %d:\n%s", rec.Code, rec.Body.String())
	}
}

func TestPreviewShowsHints(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: impact-bt\n  target: section:Impact\n  regex_forbid: '`'\n  message: No backticks in Impact\n", nil)
	edit := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	i := strings.Index(edit, `hx-post="`)
	j := strings.Index(edit[i+9:], `"`)
	_ = j
	var pv string
	for _, part := range strings.Split(edit, `hx-post="`)[1:] {
		u := part[:strings.Index(part, `"`)]
		if strings.Contains(u, "/preview") {
			pv = strings.ReplaceAll(u, "&amp;", "&")
		}
	}
	if pv == "" || !strings.Contains(pv, "s=Impact") {
		t.Fatalf("preview url %q", pv)
	}
	b := e.do(t, "alice", "POST", pv, url.Values{"body": {"uses `x`"}}, nil).Body.String()
	if !strings.Contains(b, "No backticks in Impact") {
		t.Fatalf("no hint:\n%s", b)
	}
}
