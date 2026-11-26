package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The client yars serve and yars export send to Confluence and Jira with
// follows no redirect to another host: the request's body (finding text,
// attachments) and its credentials go only to the configured address
// (pre1 2.26).
func TestExportClientRefusesOtherHosts(t *testing.T) {
	var got []string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Method+" "+r.URL.Path+" auth="+r.Header.Get("Authorization"))
	}))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer first.Close()
	req, _ := http.NewRequest("POST", first.URL+"/rest/api/2/issue", strings.NewReader(`{"fields":{"summary":"SQL injection"}}`))
	req.SetBasicAuth("bot", "secret")
	c, ok := exportRunner(t.TempDir()).HTTP.(*http.Client)
	if !ok {
		t.Fatal("the export client is no *http.Client")
	}
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	host := strings.TrimPrefix(other.URL, "http://")
	if len(got) != 0 || err == nil || !strings.Contains(err.Error(), "redirect to "+host+" refused") {
		t.Fatalf("err %v; the other host got %v", err, got)
	}
}
