package web

import (
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/store"
)

// attachView is the attachment strip of a section editor and the finding
// page's Attachments panel.
type attachView struct {
	UploadURL string // POST adds a file; GET answers the Attachments panel
	Items     []attachItem
}

type attachItem struct {
	Name, URL, Size, Kind string
	Src                   string // URL with the file's version, for <img>
	Image                 bool
	Insert                string // the Markdown to insert
	RedactURL             string
	HasOriginal           bool   // an earlier version is in git history (D28)
	PurgeURL              string // a director's Purge from history of it
}

// attachVer tells versions of an attachment apart: a redacted copy gets a
// new image URL, so a page that showed the original does not reuse it.
func attachVer(a store.Attachment) string {
	return strconv.FormatInt(a.ModTime.UnixNano(), 36)
}

func (s *Server) routesAttach(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/attachments", s.attachmentsPanel)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/attachments/{name}", s.attachmentGet)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/attachments", s.attachmentAdd)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/attachments/{name}/redact", s.attachmentRedact)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/attachments/{name}/purge", s.purgePage)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/attachments/{name}/purge", s.purgePost)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", (n+512)>>10)
	}
	return fmt.Sprintf("%d B", n)
}

// attachMD is the Markdown that shows (image) or links (text) a file.
func attachMD(name string, image bool) string {
	if image {
		return "![" + name + "](attachments/" + name + ")"
	}
	return "[" + name + "](attachments/" + name + ")"
}

func (s *Server) attachFor(r *http.Request, ref store.FindingRef) (*attachView, error) {
	base := findingURL(ref.EngID, ref.Dir) + "/attachments"
	v := &attachView{UploadURL: base}
	as, err := s.Store.AttachmentsOf(ref)
	if err != nil {
		return nil, err
	}
	purge := s.canPurge(r, ref)
	for _, a := range as {
		it := attachItem{Name: a.Name, URL: base + "/" + a.Name, Size: humanSize(a.Size), Image: a.Image, Insert: attachMD(a.Name, a.Image), HasOriginal: a.HasOriginal}
		if purge && a.HasOriginal {
			it.PurgeURL = purgeURL(ref, a.Name)
		}
		it.Src = it.URL + "?v=" + attachVer(a)
		if it.Kind = strings.ToUpper(strings.TrimPrefix(path.Ext(a.Name), ".")); it.Kind == "" {
			it.Kind = "FILE"
		}
		if a.Image {
			it.RedactURL = it.URL + "/redact"
		}
		v.Items = append(v.Items, it)
	}
	return v, nil
}

// attachmentsPanel answers the finding page's Attachments panel alone (live
// refreshes).
func (s *Server) attachmentsPanel(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	v, err := s.attachFor(r, ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "attachments_panel", v)
}

// linkAttachments points the relative attachment links of a finding's
// rendered Markdown at the attachment route; images get their version.
func (s *Server) linkAttachments(h template.HTML, ref store.FindingRef) template.HTML {
	if !strings.Contains(string(h), `="attachments/`) {
		return h
	}
	base := findingURL(ref.EngID, ref.Dir) + "/attachments/"
	out := string(h)
	if as, err := s.Store.AttachmentsOf(ref); err == nil {
		for _, a := range as {
			if a.Image {
				out = strings.ReplaceAll(out, `src="attachments/`+a.Name+`"`, `src="`+base+a.Name+`?v=`+attachVer(a)+`"`)
			}
		}
	}
	out = strings.ReplaceAll(out, `src="attachments/`, `src="`+base)
	return template.HTML(strings.ReplaceAll(out, `href="attachments/`, `href="`+base))
}

// attachmentGet serves an attachment: images as themselves, everything
// else as plain text in a sandbox, never sniffed.
func (s *Server) attachmentGet(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	b, err := s.Store.ReadAttachment(ref.EngID, ref.Dir, "attachments/"+r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	t := store.AttachmentType(b)
	if !strings.HasPrefix(t, "image/") {
		t = "text/plain; charset=utf-8"
	}
	h := w.Header()
	h.Set("Content-Type", t)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self'")
	h.Set("Cache-Control", "private, no-cache")
	w.Write(b)
}

// upload reads the "file" field of a multipart request of at most the
// attachment limit (plus room for the form).
func upload(w http.ResponseWriter, r *http.Request) (string, []byte, int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, store.MaxAttachment+64<<10)
	f, fh, err := r.FormFile("file")
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return "", nil, http.StatusRequestEntityTooLarge, store.ErrTooLarge
		}
		return "", nil, http.StatusBadRequest, errors.New("no file")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, store.MaxAttachment+1))
	if err != nil {
		return "", nil, http.StatusBadRequest, err
	}
	if len(b) > store.MaxAttachment {
		return "", nil, http.StatusRequestEntityTooLarge, store.ErrTooLarge
	}
	return fh.Filename, b, 0, nil
}

// attachFail answers a refused upload: too large 413, wrong type 415.
func (s *Server) attachFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrTooLarge):
		http.Error(w, "Larger than 10 MB", http.StatusRequestEntityTooLarge)
	case errors.Is(err, store.ErrInvalidValue):
		http.Error(w, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "), http.StatusUnsupportedMediaType)
	default:
		s.fail(w, err)
	}
}

// attachmentAdd stores an uploaded file and answers with the new strip;
// X-Yars-Name and X-Yars-Insert say what to put into the text.
func (s *Server) attachmentAdd(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	name, data, code, err := upload(w, r)
	if err != nil {
		if code == http.StatusRequestEntityTooLarge {
			s.attachFail(w, err)
		} else {
			http.Error(w, err.Error(), code)
		}
		return
	}
	got, err := s.Store.AddAttachment(ref.EngID, ref.Dir, name, data, auth.UserFrom(r.Context()))
	if err != nil {
		s.attachFail(w, err)
		return
	}
	v, err := s.attachFor(r, ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("X-Yars-Name", got)
	w.Header().Set("X-Yars-Insert", attachMD(got, strings.HasPrefix(store.AttachmentType(data), "image/")))
	s.exec(w, "finding.html", "attach_strip", v)
}

// attachmentRedact replaces an image with the redacted copy the browser
// drew.
func (s *Server) attachmentRedact(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	_, data, code, err := upload(w, r)
	if err != nil {
		if code == http.StatusRequestEntityTooLarge {
			s.attachFail(w, err)
		} else {
			http.Error(w, err.Error(), code)
		}
		return
	}
	rd, err := s.Store.RedactAttachment(ref.EngID, ref.Dir, r.PathValue("name"), data, auth.UserFrom(r.Context()))
	if err != nil {
		s.attachFail(w, err)
		return
	}
	v, err := s.attachFor(r, ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	if left := s.unredacted(rd); left != "" {
		// a toast after the save; escaped, as a name may not be ASCII
		w.Header().Set("X-Yars-Unredacted", url.PathEscape(left))
	}
	s.exec(w, "finding.html", "attach_strip", v)
}

// unredacted names the retests whose copy a redaction left holding an
// earlier version (Q12), by engagement name as the purge page does, and
// counts those the redactor cannot see: "not redacted in Retest 2
// (archived), rt3 (failed), 1 retest (no access)".
func (s *Server) unredacted(rd store.Redaction) string {
	var l []string
	for _, g := range []struct {
		ids []string
		why string
	}{{rd.Archived, "archived"}, {rd.Locked, "locked"}, {rd.Failed, "failed"}} {
		for _, id := range g.ids {
			n := id
			if e, err := s.Store.Engagement(id); err == nil && e.Name != "" {
				n = e.Name
			}
			l = append(l, n+" ("+g.why+")")
		}
	}
	if len(rd.Hidden) > 0 {
		l = append(l, plural(len(rd.Hidden), "retest")+" (no access)")
	}
	if len(l) == 0 {
		return ""
	}
	return "not redacted in " + strings.Join(l, ", ")
}
