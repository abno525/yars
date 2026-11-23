package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D3: one count. These pin the bar's count, the strip's Errors and the
// disabled Submit, Sign off and Approve to one source in the states where
// they used to drift apart.

var (
	stripErrors = regexp.MustCompile(`Errors <span class="badge0?">(\d+)</span>`)
	barState    = regexp.MustCompile(`id="wf-state"[^>]*>([^<]*)<`)
)

// shown is what a viewer reads on the finding page: the strip's Errors, the
// bar's state and which actions are disabled.
type shown struct {
	errors, state string
	disabled      map[string]bool
}

func (e *env) shown(t *testing.T, who string) shown {
	t.Helper()
	b := e.do(t, who, "GET", fpath, nil, nil).Body.String()
	var s shown
	if m := stripErrors.FindStringSubmatch(checksPanel(t, b)); m != nil {
		s.errors = m[1]
	}
	wf := wfBar(t, b)
	if m := barState.FindStringSubmatch(wf); m != nil {
		s.state = m[1]
	}
	s.disabled = map[string]bool{}
	for _, act := range []string{"submit", "clear", "approve"} {
		if i := strings.Index(wf, `data-action="`+act+`"`); i >= 0 {
			s.disabled[act] = strings.Contains(wf[i:i+strings.Index(wf[i:], ">")], "disabled")
		}
	}
	return s
}

// want checks a viewer's page: the strip's Errors, the bar's state and the
// actions that must be disabled.
func (e *env) want(t *testing.T, who, errors, state string, disabled ...string) {
	t.Helper()
	s := e.shown(t, who)
	if s.errors != errors || s.state != state {
		t.Errorf("%s: strip Errors %s, bar %q; want %s, %q", who, s.errors, s.state, errors, state)
	}
	for _, act := range disabled {
		if !s.disabled[act] {
			t.Errorf("%s: %s is not disabled", who, act)
		}
	}
}

const scriptSaysNo = `cat >/dev/null; echo '[{"message":"script says no","target":"section:Impact"}]'` + "\n"

// The rules change after a run found a script error on this content: the
// store's open checks still hold the error, so the strip lists it too.
func TestOneCountStaleByRules(t *testing.T) {
	e := setupSerial(t)
	e.toVerification(t)
	script := map[string]string{"check.sh": scriptSaysNo}
	e.rules(t, "- id: scr\n  script: check.sh\n", script)
	e.do(t, "bob", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	e.rules(t, "- id: scr\n  script: check.sh\n- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", script)
	e.want(t, "bob", "1", "1 error open", "clear")
	e.want(t, "dora", "1", "1 error open", "approve") // Approve waits for a sign-off too
}

// A run cut off (no results): the fast rules' error is still listed,
// counted and holds Submit.
func TestOneCountInterruptedRun(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	ref, err := e.srv.Store.Finding("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	d := e.srv.Store.DB()
	id, err := d.StartRun("acme", ref.F.Meta.ID, ref.Hash, "alice", e.srv.Store.RulesVersion())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.FailRun(id, "interrupted"); err != nil {
		t.Fatal(err)
	}
	e.want(t, "alice", "1", "1 error to fix", "submit")
}

// A broken rule file blocks Submit (the store refuses it): it is counted.
func TestOneCountRuleFileError(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: bad\n  target: title\n  regex_forbid: '('\n", nil)
	e.want(t, "alice", "1", "1 error to fix", "submit")
}

// While a check runs again, the last finished run's error on this content
// still counts (the store's open checks hold it).
func TestOneCountWhileRunningAgain(t *testing.T) {
	for _, status := range []string{"verification", "draft"} {
		t.Run(status, func(t *testing.T) {
			e := setupSerial(t)
			if status == "verification" {
				e.toVerification(t)
			} else {
				e.gateClean(t)
			}
			block, goOn := filepath.Join(e.dir, "block"), filepath.Join(e.dir, "go-on")
			e.rules(t, "- id: scr\n  script: check.sh\n", map[string]string{"check.sh": "cat >/dev/null; if [ -e " + block + " ]; then while [ ! -e " + goOn + " ]; do sleep 0.05; done; fi; echo '[{\"message\":\"script says no\",\"target\":\"section:Impact\"}]'\n"})
			t.Cleanup(func() {
				os.WriteFile(goOn, nil, 0o644)
				e.srv.Store.WaitChecks()
			})
			e.do(t, "bob", "POST", fpath+"/checks", url.Values{}, nil)
			e.srv.Store.WaitChecks()
			os.WriteFile(block, nil, 0o644)
			e.do(t, "bob", "POST", fpath+"/checks", url.Values{}, nil)
			if status == "verification" {
				e.want(t, "dora", "1", "1 error open", "approve")
				e.want(t, "bob", "1", "1 error open", "clear")
			} else {
				e.want(t, "alice", "1", "1 error to fix", "submit")
			}
		})
	}
}
