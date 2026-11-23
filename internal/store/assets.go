package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/workflow"
)

// MaxAttachment is the largest file a finding may get as an attachment.
const MaxAttachment = 10 << 20

// ErrTooLarge rejects an attachment over MaxAttachment.
var ErrTooLarge = fmt.Errorf("%w: larger than 10 MB", ErrInvalidValue)

// EventMerge is the chat event of a finding another one was merged into
// (its text is the merged finding's ID).
const EventMerge = "merge"

// AssetsHash identifies the asset list for optimistic concurrency.
func AssetsHash(m finding.Meta) string {
	var b strings.Builder
	for _, a := range m.Assets {
		b.WriteString(a.Host + "\x00" + a.URL + "\x00" + a.Port + "\x00" + a.Note + "\x01")
	}
	return BodyHash(b.String())
}

// CleanAssets trims the rows, drops empty ones and checks the rest: a host
// or URL is required, a port is 1–65535, a URL has a scheme and host, and
// no field spans lines.
func CleanAssets(list []finding.Asset) ([]finding.Asset, error) {
	var out []finding.Asset
	for i, a := range list {
		a = finding.Asset{Host: strings.TrimSpace(a.Host), URL: strings.TrimSpace(a.URL), Port: strings.TrimSpace(a.Port), Note: strings.TrimSpace(a.Note)}
		if a == (finding.Asset{}) {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("%w: asset %d: %s", ErrInvalidValue, i+1, why) }
		for _, v := range []string{a.Host, a.URL, a.Port, a.Note} {
			if strings.ContainsAny(v, "\r\n") || len(v) > 2000 {
				return nil, bad("one line, at most 2000 characters")
			}
		}
		if a.Host == "" && a.URL == "" {
			return nil, bad("a host or URL is required")
		}
		if a.Port != "" {
			if n, err := strconv.Atoi(a.Port); err != nil || n < 1 || n > 65535 {
				return nil, bad("port must be 1–65535")
			}
		}
		if a.URL != "" {
			if u, err := url.Parse(a.URL); err != nil || u.Scheme == "" || u.Host == "" {
				return nil, bad("URL needs a scheme and host")
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// UpdateAssets replaces the finding's asset list. A non-empty base must
// match AssetsHash of the current list, else ErrConflict.
func (s *Store) UpdateAssets(engID, dir string, list []finding.Asset, base string, a Actor) error {
	clean, err := CleanAssets(list)
	if err != nil {
		return err
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && AssetsHash(f.Meta) != base {
			return "", ErrConflict
		}
		var v any
		if len(clean) > 0 {
			v = clean
		}
		return "edit assets", f.SetMeta("assets", v)
	})
}

// Attachment is one file in a finding's attachments/ folder.
type Attachment struct {
	Name    string
	Size    int64
	Image   bool
	ModTime time.Time // changes when the file is replaced (redacted)
	// HasOriginal: an earlier version of this image is in the git history
	// (it was redacted after its commit, and not purged since; D28)
	HasOriginal bool
}

func attachDir(eng, dir string) string {
	return path.Join("engagements", eng, "findings", dir, "attachments")
}

// Attachments lists the finding's attachments, sorted by name.
func (s *Store) Attachments(engID, dir string) ([]Attachment, error) {
	fid := ""
	if ref, err := s.Finding(engID, dir); err == nil {
		fid = ref.F.Meta.ID
	}
	return s.attachments(engID, dir, fid)
}

// AttachmentsOf is Attachments of a finding already read.
func (s *Store) AttachmentsOf(ref FindingRef) ([]Attachment, error) {
	fid := ""
	if ref.F != nil {
		fid = ref.F.Meta.ID
	}
	return s.attachments(ref.EngID, ref.Dir, fid)
}

// AttachmentsHash identifies dir's attachments as they are on disk (names,
// sizes and times; a replaced file gets a new time): a sign-off is for the
// files the page showed too (TransitionSeen). It reads no database, so it
// runs inside a transaction.
func (s *Store) AttachmentsHash(engID, dir string) (string, error) {
	as, err := s.attachments(engID, dir, "")
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, a := range as {
		b.WriteString(a.Name + "\x00" + strconv.FormatInt(a.Size, 10) + "\x00" + strconv.FormatInt(a.ModTime.UnixNano(), 10) + "\x01")
	}
	return BodyHash(b.String()), nil
}

// attachments lists dir's attachments; fid ("" = unknown) finds the ones
// whose original is still in history.
func (s *Store) attachments(engID, dir, fid string) ([]Attachment, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return nil, ErrNotFound
	}
	ents, err := s.readDir(attachDir(engID, dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	marked := map[string]bool{}
	if s.db != nil && fid != "" {
		if marked, err = s.db.Unpurged(engID, fid); err != nil {
			return nil, err
		}
	}
	var out []Attachment
	for _, e := range ents {
		if !e.Type().IsRegular() || !attachmentRe.MatchString("attachments/"+e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Attachment{Name: e.Name(), Size: info.Size(), Image: imageName(e.Name()), ModTime: info.ModTime(), HasOriginal: marked[e.Name()]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func imageName(n string) bool {
	switch strings.ToLower(path.Ext(n)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp":
		return true
	}
	return false
}

// AttachmentType is the media type an attachment is accepted and served
// as: an image type, text/plain, or "" (not accepted).
func AttachmentType(data []byte) string {
	t := http.DetectContentType(data)
	switch {
	case slices.Contains([]string{"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp"}, t):
		return t
	case strings.HasPrefix(t, "text/"):
		return "text/plain; charset=utf-8"
	}
	return ""
}

// SafeName turns an uploaded file name into an attachment name: its base
// name with only letters, digits, dot, dash and underscore, starting with a
// letter or digit, with no two dots in a row.
func SafeName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	dash, dot := false, false
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_'
		if r == '.' && dot {
			continue
		}
		dot = r == '.'
		if ok {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimLeft(b.String(), "-._")
	if len(out) > 80 {
		ext := path.Ext(out)
		if len(ext) > 10 {
			ext = ""
		}
		out = out[:80-len(ext)] + ext
	}
	if out == "" {
		out = "file"
	}
	return out
}

// freeName is name, or name with -2, -3… before the extension, whichever
// taken does not hold.
func freeName(name string, taken func(string) bool) string {
	if !taken(name) {
		return name
	}
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 2; ; i++ {
		if n := stem + "-" + strconv.Itoa(i) + ext; !taken(n) {
			return n
		}
	}
}

// changeFiles loads a finding under its engagement's lock, lets fn decide
// which files of the engagement to write (data-dir paths; the finding's
// own file included when it changed), and commits them as one commit
// "<ID>: <msg>". A config.User must be allowed to edit the finding.
func (s *Store) changeFiles(engID, dir string, who Actor, fn func(ref FindingRef) (map[string][]byte, string, error)) (FindingRef, error) {
	return s.changeFilesThen(engID, dir, who, fn, nil)
}

// changeFilesThen is changeFiles; after, when set, runs once the commit is
// made, still under the lock and before the change is announced (a failure
// there is logged: the commit stands).
func (s *Store) changeFilesThen(engID, dir string, who Actor, fn func(ref FindingRef) (map[string][]byte, string, error), after func(ref FindingRef) error) (FindingRef, error) {
	var ev Event
	ref, err := s.changeFilesLocked(engID, dir, who, fn, after, &ev)
	if ev.Kind != "" {
		s.Emit(ev) // after the lock is released
	}
	return ref, err
}

// changeFilesLocked does changeFiles' work under the lock; once it
// committed, *ev is the finding.updated event.
func (s *Store) changeFilesLocked(engID, dir string, who Actor, fn func(ref FindingRef) (map[string][]byte, string, error), after func(ref FindingRef) error, ev *Event) (FindingRef, error) {
	if !ValidID(engID) {
		return FindingRef{}, ErrNotFound
	}
	l := s.engLock(engID)
	l.Lock()
	defer l.Unlock()
	if err := s.writable(engID); err != nil { // under the lock, as Archive
		return FindingRef{}, err
	}
	head0, _ := s.freshHead(engID)
	ref, _, err := s.read(engID, dir, nil)
	if err != nil {
		return ref, err
	}
	if u, ok := who.(config.User); ok && !workflow.CanEdit(u, ref.F.Meta) {
		return ref, &workflow.Denied{Reason: "this finding is " + ref.F.Meta.Status + "; only a director can edit it"}
	}
	files, msg, err := fn(ref)
	if err != nil || len(files) == 0 {
		return ref, err
	}
	if err := s.unmoved(engID, head0); err != nil {
		return ref, err
	}
	prev := map[string][]byte{}
	var made []string
	for p, b := range files {
		old, err := s.readFile(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return ref, err
		}
		prev[p] = old
		if dirp := path.Dir(p); old == nil {
			if _, err := s.root.Lstat(dirp); err != nil {
				if err := s.root.MkdirAll(dirp, 0o755); err != nil {
					return ref, err
				}
				made = append(made, dirp)
			}
		}
		if err := s.writeFile(p, b); err != nil {
			s.restore(prev, made)
			return ref, err
		}
	}
	if err := s.commit(prev, ref.F.Meta.ID+": "+msg, who.GitAuthor(), ""); err != nil {
		for _, d := range made {
			s.root.RemoveAll(d)
		}
		return ref, err
	}
	if after != nil {
		if err := after(ref); err != nil {
			log.Printf("after %s %s: %v", engID, ref.F.Meta.ID, err)
		}
	}
	fp := findingPath(engID, ref.Dir)
	var serr error
	for p := range files {
		if p != fp && ref.F.Meta.Status == "verification" {
			// an attachment changed: the sign-offs go, as a text change's do
			// (before the page hears of the change)
			serr = dropSignOffs(s.db, engID, ref.F.Meta.ID)
			break
		}
	}
	s.notify(Change{Eng: engID, Fid: ref.F.Meta.ID, Kind: ChangeContent})
	*ev = filesEvent(who.GitAuthor().Name, ref, fp, prev, files)
	// a director's edit of a complete or reported finding keeps its approval
	if files[fp] != nil {
		serr = errors.Join(serr, s.carryApproval(ref, contentHash(prev[fp]), contentHash(files[fp])))
	}
	return ref, serr
}

// restore puts back files written before a failure (nil = did not exist)
// and removes folders made for them.
func (s *Store) restore(prev map[string][]byte, made []string) {
	for p, b := range prev {
		if b == nil {
			s.root.Remove(p)
		} else {
			s.writeFile(p, b)
		}
	}
	for _, d := range made {
		s.root.RemoveAll(d)
	}
}

func checkAttachment(data []byte) error {
	if len(data) > MaxAttachment {
		return ErrTooLarge
	}
	if AttachmentType(data) == "" {
		return fmt.Errorf("%w: only images and text files can be attached", ErrInvalidValue)
	}
	return nil
}

// AddAttachment stores data in the finding's attachments/ folder under a
// safe, free version of name, with a commit, and returns the name used.
func (s *Store) AddAttachment(engID, dir, name string, data []byte, a Actor) (string, error) {
	if err := checkAttachment(data); err != nil {
		return "", err
	}
	safe := SafeName(name)
	_, err := s.changeFiles(engID, dir, a, func(ref FindingRef) (map[string][]byte, string, error) {
		ad := attachDir(engID, ref.Dir)
		safe = freeName(safe, func(n string) bool {
			_, err := s.root.Lstat(path.Join(ad, n))
			return err == nil
		})
		return map[string][]byte{path.Join(ad, safe): data}, "attach " + safe, nil
	})
	return safe, err
}

// ReplaceAttachment is RedactAttachment without its report.
func (s *Store) ReplaceAttachment(engID, dir, name string, data []byte, a Actor) error {
	_, err := s.RedactAttachment(engID, dir, name, data, a)
	return err
}

// Redaction is what a redaction did in the retests made from the
// finding's engagement and in theirs (Q12), as engagement IDs: the copies
// it redacted too, and those it left holding an earlier version: in an
// archived retest, one locked to the redactor (CanEdit), one the redactor
// cannot see (Hidden: not to be named to them), or the change failed
// there (logged). A copy changed since the retest was made is in none.
type Redaction struct {
	Redacted, Archived, Locked, Hidden, Failed []string
}

// RedactAttachment overwrites an image attachment with another image (a
// redacted copy) in a new commit; the original stays in the git history,
// which is noted (D28: the mark, Purge from history). Then every retest
// copy of the finding that still holds an earlier version gets the
// redacted copy as well, with a commit and a note of its own, as a's
// change there.
func (s *Store) RedactAttachment(engID, dir, name string, data []byte, a Actor) (Redaction, error) {
	if err := checkAttachment(data); err != nil {
		return Redaction{}, err
	}
	if !strings.HasPrefix(AttachmentType(data), "image/") {
		return Redaction{}, fmt.Errorf("%w: a redacted copy must be an image", ErrInvalidValue)
	}
	if !attachmentRe.MatchString("attachments/" + name) {
		return Redaction{}, ErrNotFound
	}
	ref, orig, _, err := s.redact(engID, dir, name, data, nil, a)
	if err != nil {
		return Redaction{}, err
	}
	if bytes.Equal(orig, data) {
		return Redaction{}, nil
	}
	return s.redactRetests(ref, name, data, a), nil
}

// redact writes data over the finding's image name in one commit and
// notes the redaction. vers, when set (a retest's copy), are the versions
// (blob ids) the file may hold: otherwise (or with no such file) nothing
// is written and done is false. It returns the finding and, without vers,
// the image replaced.
func (s *Store) redact(engID, dir, name string, data []byte, vers map[string]bool, a Actor) (ref FindingRef, old []byte, done bool, err error) {
	ref, err = s.changeFilesThen(engID, dir, a, func(ref FindingRef) (map[string][]byte, string, error) {
		p := path.Join(attachDir(engID, ref.Dir), name)
		if vers != nil { // a retest's copy
			if b, err := s.attachBlob(engID, ref.Dir, name); err != nil || !vers[b] {
				return nil, "", err // none, changed since, or redacted already: left alone
			}
			done = true
			return map[string][]byte{p: data}, "redact " + name, nil
		}
		cur, err := s.ReadAttachment(engID, ref.Dir, "attachments/"+name)
		if err != nil {
			return nil, "", ErrNotFound
		}
		if !strings.HasPrefix(AttachmentType(cur), "image/") {
			return nil, "", fmt.Errorf("%w: only an image can be redacted", ErrInvalidValue)
		}
		old, done = cur, true
		return map[string][]byte{p: data}, "redact " + name, nil
	}, func(ref FindingRef) error {
		// noted under the lock, before the page hears of the change: a purge
		// waits for it, and the live refresh shows the mark
		if s.db == nil {
			return nil
		}
		return s.db.NoteRedaction(engID, ref.F.Meta.ID, name, a.GitAuthor().Name)
	})
	return ref, old, done && err == nil, err
}

// attachBlob is the blob id of the finding's attachment name at its
// engagement's HEAD ("" when there is none).
func (s *Store) attachBlob(engID, dir, name string) (string, error) {
	r, err := s.EngRepo(engID)
	if err != nil {
		return "", err
	}
	return r.BlobAt("HEAD", "findings/"+dir+"/attachments/"+name)
}

// redactRetests gives every retest copy of src's image name that still
// holds a version src had before the redaction the redacted image data,
// as a's change there (a config.User needs CanEdit, and is not told of a
// retest they cannot see). An archived retest is left as it is.
func (s *Store) redactRetests(src FindingRef, name string, data []byte, a Actor) Redaction {
	var rd Redaction
	fid := src.F.Meta.ID
	vers, err := s.earlierVersions(src.EngID, "findings/"+src.Dir+"/attachments/"+name, fid, name)
	if err != nil {
		log.Printf("redact %s/%s/%s in its retests: %v", src.EngID, fid, name, err)
		return rd
	}
	copies, err := s.retestCopies(src.EngID, fid)
	if err != nil {
		log.Printf("redact %s/%s/%s in its retests: %v", src.EngID, fid, name, err)
	}
	u, isUser := a.(config.User)
	for _, c := range copies {
		b, err := s.attachBlob(c.EngID, c.Dir, name)
		switch {
		case err != nil:
			log.Printf("redact %s/%s/%s: %v", c.EngID, c.Dir, name, err)
			if isUser && !s.CanSee(u, c.EngID) { // not named to them, failed or not
				rd.Hidden = append(rd.Hidden, c.EngID)
			} else {
				rd.Failed = append(rd.Failed, c.EngID)
			}
			continue
		case !vers[b]: // none, changed since, or redacted already
			continue
		case isUser && !s.CanSee(u, c.EngID):
			rd.Hidden = append(rd.Hidden, c.EngID)
			continue
		case s.Archived(c.EngID):
			rd.Archived = append(rd.Archived, c.EngID)
			continue
		}
		_, _, done, err := s.redact(c.EngID, c.Dir, name, data, vers, a)
		var d *workflow.Denied
		switch {
		case errors.Is(err, ErrArchived): // archived meanwhile
			rd.Archived = append(rd.Archived, c.EngID)
		case errors.As(err, &d): // locked: only a director edits it
			rd.Locked = append(rd.Locked, c.EngID)
		case err != nil:
			log.Printf("redact %s/%s/%s: %v", c.EngID, c.Dir, name, err)
			rd.Failed = append(rd.Failed, c.EngID)
		case done:
			rd.Redacted = append(rd.Redacted, c.EngID)
		}
	}
	return rd
}

// Merge moves finding src into dst as u (a director): src's sections are
// appended to dst's under a "### Merged from <ID>" heading, its assets are
// added to dst's, its attachments are copied (renamed when dst has one of
// the same name), all in one commit. src is withdrawn first, with the
// reason "merged into <dst ID>", so a second merge of it is refused; when
// the commit fails its state is put back. Then dst gets a merge event.
func (s *Store) Merge(engID, srcDir, dstDir string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	src, err := s.Finding(engID, srcDir)
	if err != nil {
		return err
	}
	dst, err := s.Finding(engID, dstDir)
	if err != nil {
		return err
	}
	if src.Dir == dst.Dir {
		return fmt.Errorf("%w: a finding can't be merged into itself", ErrInvalidValue)
	}
	if !workflow.AtLeast(u, "director") {
		return &workflow.Denied{Reason: "only a director can merge findings"}
	}
	if err := s.Flow().Check(u, src.F.Meta, workflow.Withdraw); err != nil {
		return err
	}
	if !workflow.Active(dst.F.Meta.Status) {
		return &workflow.Denied{Reason: dst.F.Meta.ID + " is withdrawn"}
	}
	key := engID + "/" + src.Dir
	if _, busy := s.merging.LoadOrStore(key, true); busy {
		return fmt.Errorf("%w: %s is being merged", ErrConflict, src.F.Meta.ID)
	}
	defer s.merging.Delete(key)
	prev, err := s.db.State(engID, src.F.Meta.ID)
	if err != nil {
		return err
	}
	dstID := dst.F.Meta.ID
	if err := s.Transition(engID, src.Dir, workflow.Withdraw, "merged into "+dstID, u); err != nil {
		return err
	}
	srcID, err := s.mergeContent(engID, src.Dir, dst.Dir, u)
	if err != nil {
		if rerr := s.unwithdraw(engID, src.Dir, prev, dstID, u); rerr != nil {
			log.Printf("merge %s/%s: putting the source back: %v", engID, src.Dir, rerr)
		}
		return err
	}
	err = s.changeState(engID, dst.Dir, func(FindingRef, *db.State, string) ([]chat.Message, error) {
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Event: EventMerge, Text: srcID}}, nil
	})
	if err != nil { // the merge itself is done; only its event is missing
		log.Printf("merge %s/%s: event: %v", engID, dst.Dir, err)
	}
	return nil
}

// unwithdraw puts back the state a merge's source had before it was
// withdrawn, with a restore event.
func (s *Store) unwithdraw(engID, dir string, prev db.State, dstID string, u config.User) error {
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		done = findingEvent(EventStatus, u.Username, ref)
		done.Action, done.From, done.To = string(workflow.Revise), ref.F.Meta.Status, prev.Status
		*st = prev
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Event: string(workflow.Revise), Text: "merge into " + dstID + " failed"}}, nil
	})
	if err == nil {
		s.Emit(done)
	}
	return err
}

// attachLinkRe finds attachment links in Markdown; a trailing dot is
// punctuation unless the name with it exists.
var attachLinkRe = regexp.MustCompile(`attachments/[A-Za-z0-9][A-Za-z0-9._-]*`)

// relink points the links to renamed attachments (old name to new) at
// their new names, matching whole names only.
func relink(body string, renames map[string]string) string {
	if len(renames) == 0 {
		return body
	}
	return attachLinkRe.ReplaceAllStringFunc(body, func(m string) string {
		name := strings.TrimPrefix(m, "attachments/")
		for n := name; n != ""; n = strings.TrimSuffix(n, ".") {
			if to, ok := renames[n]; ok {
				return "attachments/" + to + name[len(n):]
			}
			if !strings.HasSuffix(n, ".") {
				break
			}
		}
		return m
	})
}

// mergeContent is Merge's commit into dst; it returns src's ID.
func (s *Store) mergeContent(engID, srcDir, dstDir string, u config.User) (string, error) {
	var srcID string
	_, err := s.changeFiles(engID, dstDir, u, func(ref FindingRef) (map[string][]byte, string, error) {
		sr, _, err := s.read(engID, srcDir, nil)
		if err != nil {
			return nil, "", err
		}
		f := ref.F
		srcID = sr.F.Meta.ID
		files := map[string][]byte{}
		// attachments: copy, renaming on a clash
		renames := map[string]string{}
		atts, err := s.AttachmentsOf(sr)
		if err != nil {
			return nil, "", err
		}
		dad := attachDir(engID, ref.Dir)
		for _, at := range atts {
			b, err := s.readAttachment(engID, sr.Dir, "attachments/"+at.Name, 0)
			if err != nil {
				return nil, "", fmt.Errorf("%w: attachment %s of %s can't be read", ErrInvalidValue, at.Name, srcID)
			}
			n := freeName(at.Name, func(n string) bool {
				_, err := s.root.Lstat(path.Join(dad, n))
				return err == nil || files[path.Join(dad, n)] != nil
			})
			if n != at.Name {
				n = freeName(srcID+"-"+at.Name, func(n string) bool {
					_, err := s.root.Lstat(path.Join(dad, n))
					return err == nil || files[path.Join(dad, n)] != nil
				})
				renames[at.Name] = n
			}
			files[path.Join(dad, n)] = b
		}
		for _, sec := range sr.F.Sections {
			body := strings.Trim(sec.Body, "\n")
			if strings.TrimSpace(body) == "" {
				continue
			}
			body = relink(body, renames)
			cur, _ := f.Section(sec.Name)
			merged := "### Merged from " + srcID + "\n\n" + body
			if c := strings.Trim(cur, "\n"); strings.TrimSpace(c) != "" {
				merged = c + "\n\n" + merged
			}
			if err := finding.ValidateBody(merged); err != nil {
				return nil, "", fmt.Errorf("%w: %s: %v", ErrInvalidBody, sec.Name, err)
			}
			f.SetSection(sec.Name, merged)
		}
		assets := slices.Clone(f.Meta.Assets)
		for _, a := range sr.F.Meta.Assets {
			if !slices.ContainsFunc(assets, func(x finding.Asset) bool { return x.Key() == a.Key() }) {
				assets = append(assets, a)
			}
		}
		if len(assets) > len(f.Meta.Assets) {
			if err := f.SetMeta("assets", assets); err != nil {
				return nil, "", err
			}
		}
		files[findingPath(engID, ref.Dir)] = f.Bytes()
		return files, "merge " + srcID, nil
	})
	return srcID, err
}
