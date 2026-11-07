package web

import (
	"strings"
	"testing"
)

// A reviewer's last button ends at the bar's right edge, under the header's
// Export (board 3.5): the slots a reviewer never fills (Approve, Withdraw)
// are not held empty after it.
func TestWorkflowReviewerFlushRight(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	for _, u := range []string{"bob", "dora"} {
		b := e.do(t, u, "GET", fpath, nil, nil).Body.String()
		i := strings.Index(b, `<div class="wf-actions">`)
		if i < 0 {
			t.Fatalf("%s: no actions:\n%s", u, b)
		}
		acts := b[i:]
		acts = acts[:strings.Index(acts, "</div>")]
		if strings.Contains(acts, `<span class="slot`) {
			t.Errorf("%s: empty slots in the actions:\n%s", u, acts)
		}
		if !strings.Contains(acts, `data-slot="return"`) || !strings.Contains(acts, `data-slot="clear"`) {
			t.Errorf("%s: lacks Return or Sign off:\n%s", u, acts)
		}
	}
}
