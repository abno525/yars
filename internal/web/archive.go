package web

// archiveView is the read-only bar of an archived engagement: its ID, the
// Archived tag, when and by whom; directors get Reopen.
type archiveView struct {
	On         bool
	ID, At, By string
	CanReopen  bool
}

func (s *Server) archiveOf(eng string, director bool) archiveView {
	m, _ := s.Store.EngMeta(eng)
	return archiveView{On: true, ID: eng, At: day(m.ArchivedAt), By: m.ArchivedBy, CanReopen: director}
}
