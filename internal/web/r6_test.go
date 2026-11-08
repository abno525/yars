package web

import (
	"net/url"
	"testing"
)

// R6 (Q6): on the website the author can still edit a finding in
// Verification (git refuses it: TestPolicyEditDuringReview).
func TestAuthorEditsInVerificationOnWebsite(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"Fixed what the reviewer asked."}}, nil)
	if rec.Code != 200 || e.lastCommit(t) != "alice|F-001: edit Impact" {
		t.Fatalf("author's edit in verification: %d %q\n%s", rec.Code, e.lastCommit(t), rec.Body.String())
	}
}
