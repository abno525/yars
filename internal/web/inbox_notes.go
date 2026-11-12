package web

import (
	"time"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/notify"
	"yars/internal/store"
)

// Inbox section "Notifications": the user's unread notices, less the events
// another section lists already (Returned to me, Awaiting my review) and
// those of archived engagements (nothing to do there; History, the
// notifications page, keeps them). It is read per request, as the board is:
// notices do not move the index generation. Open marks a notice read (a
// POST, as on the notifications page).

// notesInboxRows caps the section.
const notesInboxRows = 50

// notesInboxSkip are the events whose finding another section lists.
var notesInboxSkip = []string{notify.Returned, notify.Review}

// notesInbox lists the section for u (engs name the engagements), and how
// many notices it has in all.
func (s *Server) notesInbox(u config.User, engs []store.Engagement) ([]inboxRow, int, error) {
	l, total, err := s.Store.UnreadNotes(u, notesInboxSkip, archivedIDs(engs), notesInboxRows)
	if err != nil || len(l) == 0 {
		return nil, total, err
	}
	names := map[string]string{}
	for _, e := range engs {
		names[e.ID] = e.Name
	}
	// the findings' titles as they are now, as the notifications page shows them
	current := s.Index.CurrentTitles()
	out := make([]inboxRow, 0, len(l))
	for _, n := range l {
		ir := inboxRow{NoteID: n.ID, Title: n.Title, URL: noteTarget(n), TagClass: "nev-" + n.Event, Tag: notify.Label(n.Event),
			Who: n.Actor, What: excerpt(n.Text), Act: "Open"}
		if n.Event != notify.Token {
			ir.Title, ir.EngID, ir.EngName, ir.ID = current(n.Eng, n.Fid, n.Title), n.Eng, names[n.Eng], n.Fid
		}
		ir.ActURL = ir.URL
		ir.At, _ = time.Parse(time.RFC3339, n.TS)
		out = append(out, ir)
	}
	return out, total, nil
}

// archivedIDs are the archived engagements among engs.
func archivedIDs(engs []store.Engagement) []string {
	var out []string
	for _, e := range engs {
		if e.Archived {
			out = append(out, e.ID)
		}
	}
	return out
}

// markNotesRead is the section's Mark all read: what the section lists for
// u, not the notices it leaves out.
func (s *Server) markNotesRead(u config.User) error {
	vis, err := s.Store.Visible(u)
	if err != nil {
		return err
	}
	engs, err := s.Index.EngagementsFor(vis)
	if err != nil {
		return err
	}
	return s.Store.MarkNotesRead(u, notesInboxSkip, archivedIDs(engs))
}

// noteTarget is where a notice leads: the token list, its finding, or its
// engagement.
func noteTarget(n db.Notification) string {
	switch {
	case n.Event == notify.Token:
		return "/settings#tokens"
	case n.Dir != "" && store.ValidID(n.Eng) && store.ValidID(n.Dir):
		return findingURL(n.Eng, n.Dir)
	case store.ValidID(n.Eng):
		return "/e/" + n.Eng
	}
	return "/notifications"
}
