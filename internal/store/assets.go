package store

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
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
	Name  string
	Size  int64
	Image bool
}

func attachDir(eng, dir string) string {
	return path.Join("engagements", eng, "findings", dir, "attachments")
}

// Attachments lists the finding's attachments, sorted by name.
func (s *Store) Attachments(engID, dir string) ([]Attachment, error) {
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
	var out []Attachment
	for _, e := range ents {
		if !e.Type().IsRegular() || !attachmentRe.MatchString("attachments/"+e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Attachment{Name: e.Name(), Size: info.Size(), Image: imageName(e.Name())})
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
// letter or digit.
func SafeName(name string) string {
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	dash := false
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_'
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
	if !ValidID(engID) {
		return FindingRef{}, ErrNotFound
	}
	if err := s.writable(engID); err != nil {
		return FindingRef{}, err
	}
	l := s.engLock(engID)
	l.Lock()
	defer l.Unlock()
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
	s.notify(Change{Eng: engID, Fid: ref.F.Meta.ID, Kind: ChangeContent})
	// a director's edit of a complete or reported finding keeps its approval
	if fp := findingPath(engID, ref.Dir); files[fp] != nil {
		return ref, s.carryApproval(ref, contentHash(prev[fp]), contentHash(files[fp]))
	}
	return ref, nil
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

// ReplaceAttachment overwrites an image attachment with another image (a
// redacted copy) in a new commit.
func (s *Store) ReplaceAttachment(engID, dir, name string, data []byte, a Actor) error {
	if err := checkAttachment(data); err != nil {
		return err
	}
	if !strings.HasPrefix(AttachmentType(data), "image/") {
		return fmt.Errorf("%w: a redacted copy must be an image", ErrInvalidValue)
	}
	if !attachmentRe.MatchString("attachments/" + name) {
		return ErrNotFound
	}
	_, err := s.changeFiles(engID, dir, a, func(ref FindingRef) (map[string][]byte, string, error) {
		p := path.Join(attachDir(engID, ref.Dir), name)
		old, err := s.ReadAttachment(engID, ref.Dir, "attachments/"+name)
		if err != nil {
			return nil, "", ErrNotFound
		}
		if !strings.HasPrefix(AttachmentType(old), "image/") {
			return nil, "", fmt.Errorf("%w: only an image can be redacted", ErrInvalidValue)
		}
		return map[string][]byte{p: data}, "redact " + name, nil
	})
	return err
}

// Merge moves finding src into dst as u (a director): src's sections are
// appended to dst's under a "### Merged from <ID>" heading, its assets are
// added to dst's, its attachments are copied (renamed when dst has one of
// the same name), all in one commit; then dst gets a merge event and src
// is withdrawn with the reason "merged into <dst ID>".
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
	if err := workflow.Check(u, src.F.Meta, workflow.Withdraw); err != nil {
		return err
	}
	if !workflow.Active(dst.F.Meta.Status) {
		return &workflow.Denied{Reason: dst.F.Meta.ID + " is withdrawn"}
	}
	var srcID, dstID string
	_, err = s.changeFiles(engID, dst.Dir, u, func(ref FindingRef) (map[string][]byte, string, error) {
		sr, _, err := s.read(engID, src.Dir, nil)
		if err != nil {
			return nil, "", err
		}
		f := ref.F
		srcID, dstID = sr.F.Meta.ID, f.Meta.ID
		files := map[string][]byte{}
		// attachments: copy, renaming on a clash
		renames := map[string]string{}
		atts, err := s.Attachments(engID, sr.Dir)
		if err != nil {
			return nil, "", err
		}
		dad := attachDir(engID, ref.Dir)
		for _, at := range atts {
			b, err := s.ReadAttachment(engID, sr.Dir, "attachments/"+at.Name)
			if err != nil {
				return nil, "", err
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
		old := make([]string, 0, len(renames))
		for k := range renames {
			old = append(old, k)
		}
		sort.Slice(old, func(i, j int) bool { return len(old[i]) > len(old[j]) })
		for _, sec := range sr.F.Sections {
			body := strings.Trim(sec.Body, "\n")
			if strings.TrimSpace(body) == "" {
				continue
			}
			for _, k := range old {
				body = strings.ReplaceAll(body, "attachments/"+k, "attachments/"+renames[k])
			}
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
	if err != nil {
		return err
	}
	err = s.changeState(engID, dst.Dir, func(FindingRef, *db.State, string) ([]chat.Message, error) {
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Event: EventMerge, Text: srcID}}, nil
	})
	if err != nil {
		return err
	}
	return s.Transition(engID, src.Dir, workflow.Withdraw, "merged into "+dstID, u)
}
