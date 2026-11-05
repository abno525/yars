package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/store"
	"yars/internal/workflow"
)

// bulkItem is the outcome for one selected finding. Key is "eng/ID" (the
// selected id as sent when it names no finding).
type bulkItem struct {
	Key, Eng, ID, Title string
	OK                  bool
	Reason              string // why it was refused
}

type bulkView struct {
	Action     string // approve | report | reviewers
	Items      []bulkItem
	OK, Denied int
}

// bulkActions are what a selection can do at once.
var bulkActions = []string{"approve", "report", "reviewers"}

// bulkDone labels a finding the action succeeded on.
var bulkDone = map[string]string{"approve": "Approved", "report": "Reported", "reviewers": "Assigned"}

// bulkBad refuses a malformed bulk request with 400. htmx swaps 400
// answers, so from the inbox it answers 422 instead: htmx then leaves the
// lists alone and the message shows as a toast.
func bulkBad(w http.ResponseWriter, r *http.Request, msg string) {
	code := http.StatusBadRequest
	if r.Header.Get("HX-Request") == "true" {
		code = http.StatusUnprocessableEntity
	}
	http.Error(w, msg, code)
}

func (s *Server) routesBulk(mux *http.ServeMux) {
	mux.HandleFunc("POST /e/{eng}/bulk", s.bulk)
	mux.HandleFunc("POST /inbox/bulk", s.bulk)
}

// bulk applies one action to selected findings, each through the same store
// call (and checks) as on the finding page, and answers with a result per
// finding. In an engagement ids are finding numbers or folders; on the inbox
// they are "eng/fid".
func (s *Server) bulk(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	r.ParseForm()
	action, ids := r.PostForm.Get("action"), r.PostForm["id"]
	if !slices.Contains(bulkActions, action) {
		bulkBad(w, r, "unknown bulk action")
		return
	}
	if len(ids) == 0 {
		bulkBad(w, r, "select at least one finding")
		return
	}
	if action != "reviewers" && !canManage(u) {
		http.Error(w, "only a director can "+action+" findings", http.StatusForbidden)
		return
	}
	var names []string
	for _, n := range r.PostForm["reviewer"] {
		if n = strings.TrimSpace(n); n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	if action == "reviewers" && len(names) == 0 {
		bulkBad(w, r, "choose at least one reviewer")
		return
	}
	users := s.Auth.Users()
	eng := r.PathValue("eng")
	// from the inbox, the lists as the user saw them, to show results in place
	inPlace := eng == "" && r.Header.Get("HX-Request") == "true"
	var before inboxView
	if inPlace {
		p, err := s.base(r, "")
		if err != nil {
			s.fail(w, err)
			return
		}
		before = p.Inbox
	}
	v := bulkView{Action: action}
	for _, id := range ids {
		it := bulkItem{Key: id}
		e, fid := eng, id
		if eng == "" {
			e, fid, _ = strings.Cut(id, "/")
		} else {
			it.Key = eng + "/" + id
		}
		ref, err := s.bulkRef(e, fid)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.fail(w, err)
				return
			}
			it.Reason = "unknown finding"
			v.Items, v.Denied = append(v.Items, it), v.Denied+1
			continue
		}
		it.Key, it.Eng, it.ID, it.Title = e+"/"+ref.F.Meta.ID, e, ref.F.Meta.ID, ref.F.Meta.Title
		switch action {
		case "approve":
			err = s.Store.Transition(e, ref.Dir, workflow.Approve, "", u)
		case "report":
			err = s.Store.Transition(e, ref.Dir, workflow.Report, "", u)
		case "reviewers":
			err = s.bulkReviewers(ref, names, users, u)
		}
		var d *workflow.Denied
		switch {
		case err == nil:
			it.OK = true
			v.OK++
		case errors.As(err, &d):
			it.Reason = d.Reason
			v.Denied++
		default:
			s.fail(w, err)
			return
		}
		v.Items = append(v.Items, it)
	}
	if inPlace {
		l, err := s.inboxAfterBulk(before, v)
		if err != nil {
			s.fail(w, err)
			return
		}
		s.exec(w, "inbox.html", "inbox_lists", l)
		return
	}
	s.exec(w, "engagement.html", "bulk_result", v)
}

// bulkRef loads one selected finding; a malformed id is ErrNotFound.
func (s *Server) bulkRef(eng, fid string) (store.FindingRef, error) {
	if !store.ValidID(eng) || !store.ValidID(fid) {
		return store.FindingRef{}, store.ErrNotFound
	}
	return s.Store.Finding(eng, fid)
}

// bulkReviewers adds names to the finding's reviewers as u; every name must
// be an account that may review this finding (not its author).
func (s *Server) bulkReviewers(ref store.FindingRef, names []string, users []config.User, u config.User) error {
	m := ref.F.Meta
	for _, n := range names {
		ok := slices.ContainsFunc(users, func(c config.User) bool {
			return c.Username == n && workflow.ReviewerCandidate(c, m)
		})
		if !ok {
			return &workflow.Denied{Reason: n + " cannot review this finding"}
		}
	}
	next := slices.Clone(m.Reviewers)
	for _, n := range names {
		if !slices.Contains(next, n) {
			next = append(next, n)
		}
	}
	return s.Store.SetReviewers(ref.EngID, ref.Dir, next, u)
}
