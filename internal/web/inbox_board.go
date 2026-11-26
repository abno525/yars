package web

import (
	"net/http"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// Inbox queue "New on team board": the notes with an entry by someone else
// that the user has not seen (team members since they joined; others the
// notes they opened). It is read per request, not with the cached lists:
// board writes do not move the index generation. Opening a note takes it
// off; Mark all read takes them all off, until a new entry.

// boardInboxRows caps the queue.
const boardInboxRows = 50

// boardInboxRow is one note in the queue: what came last, by whom.
type boardInboxRow struct {
	Title, State, StateLabel string
	EngID, EngName, ID, URL  string
	Who, What                string
	At                       time.Time
}

// openIDs are the engagements among engs that are not archived, by id, and
// their names.
func openIDs(engs []store.Engagement) ([]string, map[string]string) {
	names := map[string]string{}
	var ids []string
	for _, e := range engs {
		if !e.Archived {
			names[e.ID] = e.Name
			ids = append(ids, e.ID)
		}
	}
	return ids, names
}

// boardInboxRead is the queue's Mark all read: every note it lists is seen,
// up to its newest entry; back to the inbox.
func (s *Server) boardInboxRead(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	vis, err := s.Store.Visible(u)
	if err != nil {
		s.fail(w, err)
		return
	}
	engs, err := s.Index.EngagementsFor(vis)
	if err != nil {
		s.fail(w, err)
		return
	}
	ids, _ := openIDs(engs)
	if err := s.Store.SeeQueue(u, ids); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// boardInbox lists the queue for u, of the open engagements among engs (the
// ones u sees), and how many notes it has in all.
func (s *Server) boardInbox(u config.User, engs []store.Engagement) ([]inboxRow, int, error) {
	ids, names := openIDs(engs)
	notes, total, err := s.Store.UnseenQueue(u, ids, boardInboxRows)
	if err != nil || len(notes) == 0 {
		return nil, 0, err
	}
	var out []boardInboxRow
	for _, n := range notes {
		name, ok := names[n.Eng]
		if !ok {
			continue
		}
		id := store.NoteID(n.Num)
		what := excerpt(n.LastText)
		switch n.LastKind {
		case db.KindState:
			what = "State · " + leadStateLabel[n.LastText]
		case db.KindDismiss:
			what = "Dismissed · " + excerpt(n.LastText)
		case db.KindSeverity:
			what = "Severity · " + sevLabel(n.LastText)
		case db.KindDup:
			what = "Duplicate of · " + n.LastText
		case db.KindFinding:
			what = "Finding · " + n.LastText
		}
		at, _ := time.Parse(time.RFC3339, n.LastTS)
		out = append(out, boardInboxRow{Title: n.Title, State: n.State, StateLabel: leadStateLabel[n.State], EngID: n.Eng, EngName: name,
			ID: id, URL: boardQuery{}.url(n.Eng, id), Who: n.LastUser, What: what, At: at})
	}
	return boardRows(out), total, nil
}
