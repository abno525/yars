package web

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/finding"
)

// A thread on a section that is gone from the file and is not configured is
// shown as a general one: it has no link to a panel that does not exist, the
// inbox row leads to the chat, and it is still counted.
func TestThreadOnRemovedSection(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if err := st.UpdateSection("acme", fdir, "Extra", "Only in this file.", "", wAlice); err != nil {
		t.Fatal(err)
	}
	hx := map[string]string{"HX-Request": "true"}
	if rec := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"what is this section for?"}, "section": {"Extra"}}, hx); rec.Code != 200 {
		t.Fatalf("chat %d %s", rec.Code, rec.Body)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Impact overstated?"}, "section": {"Impact"}}, hx)
	// while the section is there the thread links to its panel
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `<a class="ref" href="#s-extra" title="Extra">Extra</a>`) || !strings.Contains(b, `id="s-extra"`) {
		t.Fatal("the thread does not link to its section")
	}
	if b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(b, `/e/acme/f/001#s-extra"`) {
		t.Fatal("the inbox row does not lead to the section")
	}

	// a push takes the heading out of the file
	ed := filepath.Join(st.Repo().Dir, "engagements", "acme")
	p := filepath.Join(ed, "findings", fdir, "finding.md")
	st.ReceivePush("acme", wAlice, func() {
		b, _ := os.ReadFile(p)
		f, err := finding.Parse(b)
		if err != nil {
			t.Error(err)
			return
		}
		for i, sec := range f.Sections {
			if sec.Name == "Extra" {
				f.Sections = append(f.Sections[:i], f.Sections[i+1:]...)
				break
			}
		}
		os.WriteFile(p, f.Bytes(), 0o644)
		for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=alice", "-c", "user.email=alice@acme.example", "commit", "-q", "-m", "F-001: drop Extra"}} {
			if out, err := exec.Command("git", append([]string{"-C", ed}, args...)...).CombinedOutput(); err != nil {
				t.Errorf("git %v: %v\n%s", args, err, out)
			}
		}
	})
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if strings.Contains(b, `id="s-extra"`) {
		t.Fatal("the section is still on the page")
	}
	list := chatList(t, b)
	if !strings.Contains(list, "what is this section for?") {
		t.Fatalf("the thread is gone from the chat:\n%s", list)
	}
	if strings.Contains(b, `href="#s-extra"`) {
		t.Fatalf("the thread links to a panel that is not there:\n%s", list)
	}
	// the other thread keeps its link, and both are counted
	if !strings.Contains(list, `<a class="ref" href="#s-impact" title="Impact">Impact</a>`) || !strings.Contains(b, `<span class="threads">2 open</span>`) {
		t.Fatalf("the other thread or the count:\n%s", list)
	}
	inbox := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	if strings.Contains(inbox, "#s-extra") || !strings.Contains(inbox, `/e/acme/f/001#chat"`) || !strings.Contains(inbox, `/e/acme/f/001#s-impact"`) {
		t.Fatal("the inbox row of the thread does not lead to the chat")
	}
	// resolved, its row names no section either
	msgs, _ := st.DB().Messages("acme", "F-001")
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {msgs[0].ID}}, hx)
	if l := chatList(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); strings.Contains(l, "· Extra ·") {
		t.Fatalf("the resolved row names the removed section:\n%s", l)
	}
}
