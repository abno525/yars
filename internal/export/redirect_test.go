package export

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/outbound"
)

// A Jira or Confluence address that redirects to another host gets nothing
// more: no request reaches the other host, so neither the key nor the
// finding text does, and the send fails naming the host (pre1 2.26).
func TestSendRefusesRedirectToAnotherHost(t *testing.T) {
	var mu sync.Mutex
	var leaked []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		leaked = append(leaked, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 307: the method and the body would follow
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	r, _ := runner(t, "")
	r.HTTP = outbound.Client(5 * time.Second) // as yars serve and yars export build it
	r.Getenv = func(k string) string {
		return map[string]string{"JIRA_USER": "bot", "JIRA_TOKEN": "server", "CONFLUENCE_USER": "bot", "CONFLUENCE_TOKEN": "server"}[k]
	}
	host := strings.TrimPrefix(other.URL, "http://")
	for name, e := range map[string]Exporter{
		"jira":       {ID: "j", Type: "jira", Jira: &JiraConf{BaseURL: first.URL, Project: "PEN", IssueType: "Bug", UserEnv: "JIRA_USER", TokenEnv: "JIRA_TOKEN"}},
		"confluence": {ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: first.URL, Space: "SEC", UserEnv: "CONFLUENCE_USER", TokenEnv: "CONFLUENCE_TOKEN"}},
	} {
		res, err := r.Run(context.Background(), e, oneFinding(t))
		if err == nil || !strings.Contains(err.Error(), "redirect to "+host+" refused") || len(res.Items) != 0 {
			t.Errorf("%s: err %v, result %+v", name, err, res)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leaked) != 0 {
		t.Fatalf("the other host got %v", leaked)
	}
}
