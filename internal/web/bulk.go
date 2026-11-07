package web

import (
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// bulkItem is the outcome for one selected finding. Key is "eng/ID" (the
// selected id as sent when it names no finding).
type bulkItem struct {
	Key, Eng, ID, Dir, Title string
	OK                       bool
	Reason                   string // why it was refused
}

type bulkView struct {
	Action     string // a workflow action of the role's bulk menu, or reviewers
	Items      []bulkItem
	OK, Denied int
}

// A bulk run takes at most maxBulkIDs findings (each moved row sends its
// notifications) and a reason of at most maxBulkReason bytes (copied into
// every row's chat). It starts new rows for at most bulkTime (submit and
// approve run every rule, AI too, per row); the rows after that are skipped,
// to run again.
const (
	maxBulkIDs    = 500
	maxBulkReason = 4000
	bulkTime      = 2 * time.Minute
)

// bulkAction reads the posted action: "reviewers" or a workflow action on
// u's bulk menu. An unknown name is 400, one u's role may not run in bulk
// 403.
func bulkAction(u config.User, name string) (workflow.Action, int, string) {
	if name == "reviewers" {
		if !workflow.BulkAssign(u) {
			return "", http.StatusForbidden, "only a reviewer or a director can assign reviewers to several findings"
		}
		return "", 0, ""
	}
	a, ok := workflow.ParseAction(name)
	if !ok {
		return "", http.StatusBadRequest, "unknown bulk action"
	}
	if !workflow.BulkAllowed(u, a) {
		return "", http.StatusForbidden, "a " + u.Role + " cannot " + strings.ToLower(workflow.Label(a)) + " several findings"
	}
	return a, 0, ""
}

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
	// submit and approve run every rule, once per row
	mux.Handle("POST /e/{eng}/bulk", s.lintLived(http.HandlerFunc(s.bulk)))
	mux.Handle("POST /inbox/bulk", s.lintLived(http.HandlerFunc(s.bulk)))
}

// bulk applies one action to selected findings, each through the same store
// call (and checks) as on the finding page, and answers with a result per
// finding. In an engagement ids are finding numbers or folders; on the inbox
// they are "eng/fid". From the engagement's findings list (htmx) it answers
// with the list again, the run's outcome marked on it.
func (s *Server) bulk(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	r.ParseForm()
	action, ids := r.PostForm.Get("action"), r.PostForm["id"]
	act, code, msg := bulkAction(u, action)
	switch {
	case code == http.StatusBadRequest:
		bulkBad(w, r, msg)
		return
	case code != 0:
		http.Error(w, msg, code)
		return
	}
	switch {
	case len(ids) == 0:
		bulkBad(w, r, "select at least one finding")
		return
	case len(ids) > maxBulkIDs:
		bulkBad(w, r, "select at most "+strconv.Itoa(maxBulkIDs)+" findings")
		return
	}
	// one reason for every selected finding (Return, Withdraw)
	reason := strings.TrimSpace(r.PostForm.Get("reason"))
	switch {
	case act != "" && workflow.NeedsReason(act) && reason == "":
		bulkBad(w, r, "give a reason")
		return
	case len(reason) > maxBulkReason:
		bulkBad(w, r, "the reason is longer than "+strconv.Itoa(maxBulkReason)+" characters")
		return
	}
	eng := r.PathValue("eng")
	if eng != "" {
		// an engagement's run: its team only, and not once it is archived
		if !store.ValidID(eng) || !s.Store.CanSee(u, eng) {
			http.NotFound(w, r)
			return
		}
		if s.Store.Archived(eng) {
			http.Error(w, store.ErrArchived.Error(), http.StatusForbidden)
			return
		}
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
	seen := map[string]bool{} // a finding named twice runs once
	budget := s.bulkBudget
	if budget <= 0 {
		budget = bulkTime
	}
	start, late := time.Now(), false
	for _, id := range ids {
		it := bulkItem{Key: id}
		e, fid := eng, id
		if eng == "" {
			e, fid, _ = strings.Cut(id, "/")
		} else {
			it.Key = eng + "/" + id
		}
		ref, err := s.bulkRef(u, e, fid)
		if err == nil {
			if seen[e+"/"+ref.Dir] {
				continue
			}
			seen[e+"/"+ref.Dir] = true
			it.Key, it.Eng, it.ID, it.Dir, it.Title = e+"/"+ref.F.Meta.ID, e, ref.F.Meta.ID, ref.Dir, ref.F.Meta.Title
			switch {
			case late:
				err = &workflow.Denied{Reason: "not run: time limit reached; run again"}
			case act == "":
				err = s.bulkReviewers(ref, names, users, u)
			default:
				// the bulk menu's own limits, then the store's checks; both
				// again on the finding as it is inside the change
				if err = workflow.BulkCheck(u, ref.F.Meta, act); err == nil {
					if workflow.Gated(act) || store.SignsOff(act) {
						s.lintDeadline(w) // each row may run every rule
					}
					err = s.Store.TransitionChecked(e, ref.Dir, act, reason, u, func(m finding.Meta) error {
						return workflow.BulkCheck(u, m, act)
					})
				}
			}
			late = late || time.Since(start) > budget
		} else if seen[it.Key] {
			continue
		} else {
			seen[it.Key] = true
		}
		if err == nil {
			it.OK = true
			v.OK++
		} else {
			it.Reason = bulkSkip(err)
			v.Denied++
		}
		v.Items = append(v.Items, it)
	}
	if inPlace {
		// the user's own layout (only a director's has the bar)
		l, err := s.inboxAfterBulk(u, before, v)
		if err != nil {
			s.fail(w, err)
			return
		}
		s.exec(w, "inbox.html", "inbox_lists", l)
		return
	}
	if eng != "" && r.Header.Get("HX-Request") == "true" {
		keep := map[string]bool{}
		for _, it := range v.Items {
			if it.Dir != "" {
				keep[it.Dir] = true
			}
		}
		p, err := s.engPage(r, eng, keep)
		if err != nil {
			s.fail(w, err)
			return
		}
		p.Bulk.ran(v)
		// the progress panel above the list counts the moved rows too
		p.BarsOOB = true
		s.exec(w, "engagement.html", "findings_ran", p)
		return
	}
	s.exec(w, "engagement.html", "bulk_result", v)
}

// bulkBar is the bulk toolbar above an engagement's findings table and the
// table's pick column.
type bulkBar struct {
	On       bool   // the engagement is open: checkboxes and the bar
	URL      string // where the bar posts: /e/<eng>/bulk with the list's query
	Cross    bool   // across engagements (the inbox): rows are keyed "eng/dir", not by folder
	Options  []bulkMenuItem
	Assign   bool              // Assign reviewers (reviewers and directors)
	Users    []string          // who may be assigned
	Pick     map[string]bool   // rows the user may select, by key
	Acts     map[string]string // the menu actions each row can take ("submit withdraw")
	Picked   map[string]bool   // ticked rows
	Skipped  map[string]string // rows the last run skipped: why
	Selected int               // ticked rows shown
	Ran      bool              // a run's summary is shown
	Moved    int
	Skip     int
}

// bulkMenuItem is one Set state entry; Reason entries open the reason
// panel; an entry no ticked row can take is disabled.
type bulkMenuItem struct {
	workflow.BulkOption
	Reason, Enabled bool
}

// bulkBarFor builds the bar for the rows of an open engagement.
func (s *Server) bulkBarFor(u config.User, eng, query string, rows []index.Row) bulkBar {
	b := bulkBar{On: true, URL: "/e/" + eng + "/bulk", Assign: workflow.BulkAssign(u),
		Pick: map[string]bool{}, Acts: map[string]string{}}
	if query != "" {
		b.URL += "?" + query
	}
	opts := workflow.BulkOptions(u)
	for _, o := range opts {
		b.Options = append(b.Options, bulkMenuItem{BulkOption: o, Reason: workflow.NeedsReason(o.Action)})
	}
	for _, row := range rows {
		b.addRow(u, row, opts)
	}
	if b.Assign {
		for _, c := range s.Auth.Users() {
			// below director nobody makes themselves a reviewer
			self := c.Username == u.Username && !workflow.AtLeast(u, "director")
			if workflow.AtLeast(c, "reviewer") && !c.Disabled && !self && s.Store.CanSee(c, eng) {
				b.Users = append(b.Users, c.Username)
			}
		}
	}
	return b
}

// key is how the bar names a row: its folder, or "eng/dir" on a bar across
// engagements (two engagements can both have F-001).
func (b *bulkBar) key(eng, dir string) string {
	if b.Cross {
		return eng + "/" + dir
	}
	return dir
}

// addRow makes row pickable when u may tick it, with the menu actions it
// can take.
func (b *bulkBar) addRow(u config.User, row index.Row, opts []workflow.BulkOption) {
	if row.Meta == nil || !workflow.BulkPick(u, *row.Meta) {
		return
	}
	k := b.key(row.EngID, row.Dir)
	b.Pick[k] = true
	var acts []string
	for _, o := range opts {
		if workflow.BulkCheck(u, *row.Meta, o.Action) == nil {
			acts = append(acts, string(o.Action))
		}
	}
	b.Acts[k] = strings.Join(acts, " ")
}

// ran marks the outcome of a run on the bar: the selection stays ticked,
// skipped rows are tinted and the summary counts both.
func (b *bulkBar) ran(v bulkView) {
	b.Ran, b.Moved, b.Skip = true, v.OK, v.Denied
	b.Picked, b.Skipped = map[string]bool{}, map[string]string{}
	for _, it := range v.Items {
		if it.Dir == "" {
			continue
		}
		k := b.key(it.Eng, it.Dir)
		b.Picked[k] = true
		if !it.OK {
			b.Skipped[k] = it.Reason
		}
	}
	for dir := range b.Picked {
		if b.Pick[dir] {
			b.Selected++
		}
	}
	for i, o := range b.Options {
		for dir := range b.Picked {
			if b.Pick[dir] && slices.Contains(strings.Fields(b.Acts[dir]), string(o.Action)) {
				b.Options[i].Enabled = true
			}
		}
	}
}

// bulkSkip is why a row was skipped. Every per-row error is a skip, so a
// finding that changed or went away since the page was drawn never stops the
// run halfway with rows already moved.
func bulkSkip(err error) string {
	var d *workflow.Denied
	switch {
	case errors.As(err, &d):
		return d.Reason
	case errors.Is(err, store.ErrNotFound):
		return "unknown finding"
	case errors.Is(err, store.ErrArchived):
		return "archived"
	case errors.Is(err, store.ErrConflict):
		return "changed since the page was loaded; reload and try again"
	}
	log.Printf("bulk: %v", err)
	return "could not be changed; try again"
}

// bulkRef loads one selected finding; a malformed id, or a finding of an
// engagement u is not on the team of, is ErrNotFound.
func (s *Server) bulkRef(u config.User, eng, fid string) (store.FindingRef, error) {
	if !store.ValidID(eng) || !store.ValidID(fid) || !s.Store.CanSee(u, eng) {
		return store.FindingRef{}, store.ErrNotFound
	}
	return s.Store.Finding(eng, fid)
}

// bulkReviewers adds names to the finding's reviewers as u, merged with the
// list as it is inside the change (Store.AddReviewers). A name that cannot
// review this finding (its author, say) is skipped for this row only; the
// row is refused when no name is left.
func (s *Server) bulkReviewers(ref store.FindingRef, names []string, users []config.User, u config.User) error {
	m := ref.F.Meta
	var ok, refused []string
	for _, n := range names {
		if slices.ContainsFunc(users, func(c config.User) bool {
			return c.Username == n && s.Store.CanReview(c, ref.EngID, m)
		}) {
			ok = append(ok, n)
		} else {
			refused = append(refused, n+" cannot review this finding")
		}
	}
	if len(ok) == 0 {
		return &workflow.Denied{Reason: strings.Join(refused, "; ")}
	}
	return s.Store.AddReviewers(ref.EngID, ref.Dir, ok, u)
}
