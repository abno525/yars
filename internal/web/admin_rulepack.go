package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

// A rule pack is one YAML file, a list of rules; these bound an upload.
const (
	maxPack      = 256 << 10
	maxPackRules = 200
)

// The rule files the server writes added rules to. The names are the
// server's: an upload's file name is never a path.
const (
	starterFile  = "starter.yaml"
	importedFile = "imported.yaml"
)

// starterLeft counts the starter rules no loaded rule has the ID of.
func starterLeft(set *rules.Set) int {
	n := 0
	for _, r := range rules.Starter() {
		if _, has := findRule(set, r.ID); !has {
			n++
		}
	}
	return n
}

// packCounts reads the counts an added pack's redirect carries, as the
// status slot's words; "" when the address has none. Numbers only.
func packCounts(r *http.Request) string {
	q := r.URL.Query()
	added, err1 := strconv.Atoi(q.Get("added"))
	skipped, err2 := strconv.Atoi(q.Get("skipped"))
	if err1 != nil || err2 != nil || added < 0 || skipped < 0 {
		return ""
	}
	return fmt.Sprintf("added %d · skipped %d", added, skipped)
}

// packRefused answers the Rules page with why a pack or the starter set was
// not written, in the panel's status slot (400).
func (s *Server) packRefused(w http.ResponseWriter, r *http.Request, msg string) {
	p, err := s.adminBase(r, "rules")
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.rulesView(r, p, newRuleForm()); err != nil {
		s.fail(w, err)
		return
	}
	p.Admin.Rules.PackMsg, p.Admin.Rules.PackBad = msg, true
	s.renderStatus(w, http.StatusBadRequest, "admin.html", p)
}

// addRules appends the rules of rs whose ID no loaded rule has to the rule
// file named file, each turned off, in one commit (verb names it). A rule
// that exists is never changed. With nothing to add there is no commit. The
// counts are in the commit's message, which is taken before the lock: a
// rules change in that instant refuses the press instead of committing
// under a wrong message.
func (s *Server) addRules(r *http.Request, verb, file string, rs []rules.Rule) (added, skipped int, err error) {
	missing := func(cur *rules.Set) []rules.Rule {
		var out []rules.Rule
		for _, x := range rs {
			if _, has := findRule(cur, x.ID); !has {
				out = append(out, x)
			}
		}
		return out
	}
	ids := func(l []rules.Rule) []string {
		var out []string
		for _, x := range l {
			out = append(out, x.ID)
		}
		return out
	}
	plan := missing(rules.Load(rules.DirFor(s.Store.Repo().Dir)))
	added, skipped = len(plan), len(rs)-len(plan)
	if added == 0 {
		return added, skipped, nil
	}
	msg := fmt.Sprintf("rules: %s (added %d, skipped %d)", verb, added, skipped)
	err = s.editRules(msg, auth.UserFrom(r.Context()), func(cur *rules.Set, read func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		now := missing(cur)
		if !slices.Equal(ids(now), ids(plan)) {
			return nil, &ruleErr{"form", "the rules changed meanwhile: press again"}
		}
		b, err := readRuleFile(read, file)
		if err != nil {
			return nil, err
		}
		for _, x := range now {
			off := false
			x.Enabled = &off // read before it acts, whatever the pack says
			if b, err = rules.SetRule(b, "", &x); err != nil {
				return nil, &ruleErr{"form", file + ": " + err.Error()}
			}
		}
		return []store.SettingsFile{{Path: rulesRel + file, Data: b}}, nil
	})
	return added, skipped, err
}

// packAdded answers a press that added rules (or found them all there): a
// redirect whose address carries the two counts for the status slot. from
// says in the log which press it was: starter or pack.
func (s *Server) packAdded(w http.ResponseWriter, r *http.Request, from string, added, skipped int, err error) {
	u := auth.UserFrom(r.Context()).Username
	var re *ruleErr
	switch {
	case errors.As(err, &re):
		s.log().Warn("rules: rules are not added", "user", u, "from", from)
		s.packRefused(w, r, re.msg)
	case err != nil:
		s.fail(w, err)
	default:
		s.log().Info("rules: rules are added", "user", u, "from", from, "added", added, "skipped", skipped)
		http.Redirect(w, r, fmt.Sprintf("/admin/rules?added=%d&skipped=%d", added, skipped), http.StatusSeeOther)
	}
}

// rulesStarter writes the starter rules that are not there yet, turned off
// (yars init writes no rules: this button is how a new server gets some).
func (s *Server) rulesStarter(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2*maxPack) // the panel's form carries its file field
	added, skipped, err := s.addRules(r, "add starter rules", starterFile, rules.Starter())
	s.packAdded(w, r, "starter", added, skipped, err)
}

// packProblem checks one rule of a pack as the editor checks a rule it
// saves, and its script as an upload's name: "" when it may be added.
func (s *Server) packProblem(x rules.Rule) string {
	if !store.ValidID(x.ID) {
		return "the ID takes letters, digits, . _ -"
	}
	if !slices.Contains(levels, x.Level) {
		return "level must be error or warning"
	}
	if err := x.Validate(); err != nil {
		return err.Error()
	}
	if x.Script == "" {
		return ""
	}
	// a pack is one file and brings no script: the rule is taken only when
	// the script it names is in the rules folder already
	if !store.ValidID(x.Script) || strings.HasSuffix(x.Script, ".yaml") || strings.HasSuffix(x.Script, ".yml") {
		return "the script name takes letters, digits, . _ - and does not end in .yaml or .yml"
	}
	rel, ok := scriptRel(x.Script)
	if !ok {
		return "the script name takes letters, digits, . _ - and does not end in .yaml or .yml"
	}
	if info, err := os.Lstat(filepath.Join(s.Store.Repo().Dir, filepath.FromSlash(rel))); err != nil || !info.Mode().IsRegular() {
		return "the script " + x.Script + " is not in the rules folder"
	}
	return ""
}

// rulesImport adds the rules of an uploaded pack. The pack is other
// people's file: it is capped, read as a list of rules, and every rule is
// checked before anything is written; one problem refuses all of it. Nothing
// of it runs here, and its rules are written turned off.
func (s *Server) rulesImport(w http.ResponseWriter, r *http.Request) {
	const tooLarge = "the file is larger than 256 KiB"
	r.Body = http.MaxBytesReader(w, r.Body, maxPack+64<<10)
	file, _, err := r.FormFile("pack")
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.packRefused(w, r, tooLarge)
			return
		}
		s.packRefused(w, r, "choose a file")
		return
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, maxPack+1))
	if err != nil || len(b) > maxPack {
		s.packRefused(w, r, tooLarge)
		return
	}
	rs, err := rules.ParsePack(b)
	if err != nil {
		s.packRefused(w, r, err.Error())
		return
	}
	if len(rs) > maxPackRules {
		s.packRefused(w, r, "a pack has at most "+strconv.Itoa(maxPackRules)+" rules")
		return
	}
	for _, x := range rs {
		if msg := s.packProblem(x); msg != "" {
			s.packRefused(w, r, "rule "+x.ID+": "+strings.TrimPrefix(msg, x.ID+": "))
			return
		}
	}
	added, skipped, err := s.addRules(r, "import a pack", importedFile, rs)
	s.packAdded(w, r, "pack", added, skipped, err)
}

// rulesExport downloads every loaded rule, on or off, as one pack.
func (s *Server) rulesExport(w http.ResponseWriter, r *http.Request) {
	b, err := rules.Pack(s.Rules.Rules().Rules)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="yars-rules.yaml"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(b)
}
