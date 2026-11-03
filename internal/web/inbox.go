package web

import (
	"net/http"

	"yars/internal/config"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

type inboxRow struct {
	EngName string
	index.Row
}

type inboxView struct {
	Review, Approve, Returned []inboxRow
}

func (v inboxView) Count() int { return len(v.Review) + len(v.Approve) + len(v.Returned) }

// inboxFor classifies every finding across engagements for u.
func (s *Server) inboxFor(u config.User, engs []store.Engagement) (inboxView, error) {
	rows, err := s.Index.Rows(index.Query{Sort: "severity"})
	if err != nil {
		return inboxView{}, err
	}
	names := map[string]string{}
	for _, e := range engs {
		names[e.ID] = e.Name
	}
	var v inboxView
	for _, r := range rows {
		ir := inboxRow{EngName: names[r.EngID], Row: r}
		switch workflow.Pending(u, r.Meta) {
		case workflow.InboxReview:
			v.Review = append(v.Review, ir)
		case workflow.InboxApprove:
			v.Approve = append(v.Approve, ir)
		case workflow.InboxReturned:
			v.Returned = append(v.Returned, ir)
		}
	}
	return v, nil
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "inbox.html", p)
}
