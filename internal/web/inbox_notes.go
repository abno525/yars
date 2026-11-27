package web

import (
	"slices"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/notify"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// Inbox section "Notifications": the user's unread notices, less the events
// another section of theirs lists already (Returned to me, Awaiting my
// review, Open threads on my findings) and
// those of archived engagements (nothing to do there; History, the
// notifications page, keeps them). It is read per request, as the board is:
// notices do not move the index generation. Open marks a notice read (a
// POST, as on the notifications page).

// notesInboxRows caps the section.
const notesInboxRows = 50

// notesInboxSkip are the events whose finding another section lists
// (Returned to me, Awaiting my review, Open threads on my findings).
var notesInboxSkip = []string{notify.Returned, notify.Review, notify.Thread}

// notesSkipFor are the events of notesInboxSkip for u: a new thread's notice is left out
// only for an account that has Open threads on my findings (a director has
// no such queue: the notice is the one place the inbox says it).
func (s *Server) notesSkipFor(u config.User) []string {
	if slices.Contains(s.flow().Queues(u), workflow.InboxThreads) {
		return notesInboxSkip
	}
	return slices.DeleteFunc(slices.Clone(notesInboxSkip), func(e string) bool { return e == notify.Thread })
}

// notesInbox lists the section for u (engs name the engagements), and how
// many notices it has in all.
func (s *Server) notesInbox(u config.User, engs []store.Engagement) ([]inboxRow, int, error) {
	l, total, err := s.Store.UnreadNotes(u, s.notesSkipFor(u), archivedIDs(engs), notesInboxRows)
	if err != nil || len(l) == 0 {
		return nil, total, err
	}
	names := map[string]string{}
	for _, e := range engs {
		names[e.ID] = e.Name
	}
	// the findings' titles as they are now, as the notifications page shows them
	current := s.Index.CurrentTitles()
	simple := s.flow().Simple
	out := make([]inboxRow, 0, len(l))
	for _, n := range l {
		ir := inboxRow{NoteID: n.ID, Title: n.Title, URL: noteTarget(n), TagClass: "nev-" + n.Event, Tag: notify.LabelFor(n.Event, simple),
			Who: n.Actor, What: excerpt(n.Text), Act: "Open"}
		// a token's and a webhook's notice have no engagement and no finding
		if n.Eng != "" {
			ir.EngID, ir.EngName, ir.ID = n.Eng, names[n.Eng], n.Fid
			if n.Fid != "" {
				ir.Title = current(n.Eng, n.Fid, n.Title)
			} else {
				ir.ID = n.Ref
			}
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
	return s.Store.MarkNotesRead(u, s.notesSkipFor(u), archivedIDs(engs))
}

// noteTarget is where a notice leads (notify.Target: the mail's link is the
// same).
func noteTarget(n db.Notification) string { return notify.Target(n) }

// noteRef is what a notice is about, for its row: engagement · finding, the
// engagement alone, or the kind of a notice that has neither.
func noteRef(n db.Notification) string {
	switch {
	case n.Event == notify.Token:
		return "Token"
	case n.Event == notify.Webhook:
		return "Webhook"
	case n.Fid != "":
		return n.Eng + " · " + n.Fid
	case n.Ref != "":
		return n.Eng + " · " + n.Ref
	}
	return n.Eng
}
