package web

import (
	"time"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/store"
)

// Inbox queue "New on team board": the notes with an entry by someone else
// that the user has not seen (team members since they joined; others the
// notes they opened). It is read per request, not with the cached lists:
// board writes do not move the index generation.

// boardInboxRows caps the queue.
const boardInboxRows = 50

// boardInboxRow is one note in the queue: what came last, by whom.
type boardInboxRow struct {
	Title, State, StateLabel string
	EngID, EngName, ID, URL  string
	Who, What, Time          string
}

// ageOf is age of a stored RFC 3339 time.
func ageOf(at string) string {
	t, _ := time.Parse(time.RFC3339, at)
	return age(t)
}

// boardInbox lists the queue for u; engs are the engagements u sees.
func (s *Server) boardInbox(u config.User, engs []store.Engagement) ([]boardInboxRow, error) {
	notes, err := s.Store.UnseenNotes(u, boardInboxRows)
	if err != nil || len(notes) == 0 {
		return nil, err
	}
	names := map[string]string{}
	for _, e := range engs {
		names[e.ID] = e.Name
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
		out = append(out, boardInboxRow{Title: n.Title, State: n.State, StateLabel: leadStateLabel[n.State], EngID: n.Eng, EngName: name,
			ID: id, URL: boardQuery{}.url(n.Eng, id), Who: n.LastUser, What: what, Time: ageOf(n.LastTS)})
	}
	return out, nil
}
