package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/store"
)

// assetsView is the Affected assets panel and its editor.
type assetsView struct {
	Rows                      []finding.Asset
	Base, Error               string
	Locked, ReadOnly          bool
	Dirty                     bool // the editor's fields are unsaved: not what is saved, or refused
	ViewURL, EditURL, SaveURL string
	LiveURL                   string // the read panel's live refresh
}

// maxAssetRows keeps one form within reason.
const maxAssetRows = 500

func (s *Server) routesAssets(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/assets", s.assetsGet)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/assets/edit", s.assetsEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/assets", s.assetsPost)
}

func (s *Server) assetsFor(ref store.FindingRef, rows []finding.Asset) assetsView {
	base := findingURL(ref.EngID, ref.Dir) + "/assets"
	if rows == nil {
		rows = ref.F.Meta.Assets
	}
	return assetsView{Rows: rows, Base: store.AssetsHash(ref.F.Meta), ViewURL: base, EditURL: base + "/edit", SaveURL: base,
		ReadOnly: s.Store.Archived(ref.EngID), LiveURL: s.liveURL(base, ref)}
}

func (s *Server) assetsGet(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.liveRef(w, r); ok {
		v := s.assetsFor(ref, nil)
		v.Locked = s.locked(r, ref)
		s.exec(w, "finding.html", "assets_panel", v)
	}
}

// editorRows is the list the editor shows: at least one (empty) row.
func editorRows(rows []finding.Asset) []finding.Asset {
	if len(rows) == 0 {
		return []finding.Asset{{}}
	}
	return rows
}

func (s *Server) assetsEdit(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.editRef(w, r); ok {
		v := s.assetsFor(ref, nil)
		v.Rows = editorRows(v.Rows)
		s.exec(w, "finding.html", "assets_editor", v)
	}
}

// assetsDirty: the editor drawn again (Add row, Remove, a refusal with
// message msg) holds rows other than the saved ones, so leaving it asks
// first. Both lists are compared cleaned (a push may keep an empty row).
func assetsDirty(rows, saved []finding.Asset, msg string) bool {
	clean, err := store.CleanAssets(rows)
	if s, err := store.CleanAssets(saved); err == nil {
		saved = s
	}
	return msg != "" || err != nil || !slices.Equal(clean, saved)
}

// postedAssets reads rows host_i, url_i, port_i, note_i for i < n.
func postedAssets(r *http.Request) []finding.Asset {
	n, _ := strconv.Atoi(r.PostForm.Get("n"))
	n = min(max(n, 0), maxAssetRows)
	out := make([]finding.Asset, 0, n)
	for i := range n {
		k := strconv.Itoa(i)
		out = append(out, finding.Asset{Host: r.PostForm.Get("host_" + k), URL: r.PostForm.Get("url_" + k),
			Port: r.PostForm.Get("port_" + k), Note: r.PostForm.Get("note_" + k)})
	}
	return out
}

// assetsPost edits the rows on the server (op add, del-<i>, draw) or saves
// them.
func (s *Server) assetsPost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	rows := postedAssets(r)
	op := r.PostForm.Get("op")
	editor := func(status int, rows []finding.Asset, msg string) {
		v := s.assetsFor(ref, editorRows(rows))
		v.Error = msg
		v.Dirty = assetsDirty(rows, ref.F.Meta.Assets, msg)
		if status != http.StatusConflict {
			v.Base = r.PostForm.Get("base") // still editing against what was shown
		}
		s.execStatus(w, status, "finding.html", "assets_editor", v)
	}
	switch {
	case op == "add":
		if len(rows) < maxAssetRows {
			rows = append(rows, finding.Asset{})
		}
		editor(http.StatusOK, rows, "")
		return
	case strings.HasPrefix(op, "del-"):
		if i, err := strconv.Atoi(strings.TrimPrefix(op, "del-")); err == nil && i >= 0 && i < len(rows) {
			rows = append(rows[:i], rows[i+1:]...)
		}
		editor(http.StatusOK, rows, "")
		return
	case op == "draw":
		// the rows as posted, nothing saved: a draft the browser kept, which
		// may hold more rows than the editor opened with
		editor(http.StatusOK, rows, "")
		return
	}
	err := s.Store.UpdateAssets(ref.EngID, ref.Dir, rows, r.PostForm.Get("base"), auth.UserFrom(r.Context()))
	switch {
	case errors.Is(err, store.ErrConflict):
		editor(http.StatusConflict, rows, conflictText)
		return
	case errors.Is(err, store.ErrInvalidValue):
		editor(http.StatusBadRequest, rows, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "))
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	if ref, err = s.Store.Finding(ref.EngID, ref.Dir); err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "assets_panel", s.assetsFor(ref, nil))
}
