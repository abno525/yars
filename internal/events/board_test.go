package events

import "testing"

// Team board events reach only board subscribers: an engagement-wide
// stream (the findings list) neither gets them nor counts them as missed.
func TestBoardEventsOnlyToBoard(t *testing.T) {
	h := New()
	board := h.Subscribe("acme", Board, 4)
	eng := h.Subscribe("acme", "", 4)
	all := h.Subscribe("", "", 4)
	since := h.Last()
	h.Publish(Event{Eng: "acme", Fid: Board, Kind: Board})
	if len(board.C()) != 1 || len(eng.C()) != 0 || len(all.C()) != 0 {
		t.Fatalf("delivered board %d eng %d all %d", len(board.C()), len(eng.C()), len(all.C()))
	}
	if h.Missed(since, "acme", "") {
		t.Fatal("engagement stream missed a board event")
	}
	if !h.Missed(since, "acme", Board) {
		t.Fatal("board stream did not miss it")
	}
	// engagement-wide events still reach the board
	h.Publish(Event{Eng: "acme", Kind: Push})
	if len(board.C()) != 2 {
		t.Fatal("push not delivered to the board")
	}
}
