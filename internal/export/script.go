package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/abno525/yars/internal/rules"
)

type scriptDoc struct {
	rules.Doc
	HTMLSections map[string]string `json:"html_sections"`
}

// scriptDocs is the findings as a script reads them, in report order, each
// with its sections in report order (sectionsOf): the list a script walks
// is the order of every other export, and the attachments follow it.
func scriptDocs(in Input) []scriptDoc {
	var docs []scriptDoc
	for _, f := range in.ordered() {
		g := *f // a copy: the finding keeps its file's order
		g.Sections = sectionsOf(f, in)
		d := scriptDoc{Doc: rules.DocOf(&g), HTMLSections: map[string]string{}}
		for _, s := range f.Sections {
			var buf bytes.Buffer
			md.Convert([]byte(s.Body), &buf)
			d.HTMLSections[s.Name] = buf.String()
		}
		docs = append(docs, d)
	}
	return docs
}

func (r *Runner) script(ctx context.Context, e Exporter, in Input) (Result, error) {
	p, err := r.safePath(e.Script)
	if err != nil {
		return Result{}, err
	}
	docs := scriptDocs(in)
	type reportDoc struct {
		ReportText
		HTML string `json:"html"`
	}
	report := []reportDoc{}
	for _, rt := range in.Report {
		report = append(report, reportDoc{ReportText: rt, HTML: reportHTML(rt.Body, false)})
	}
	input, err := json.Marshal(map[string]any{"engagement": in.Engagement, "engagement_id": in.Engagement.ID, "findings": docs, "report": report})
	if err != nil {
		return Result{}, err
	}
	cmd := exec.CommandContext(ctx, p)
	cmd.Dir = filepath.Dir(p)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdin = bytes.NewReader(input)
	out, stderr := &capWriter{max: maxOutput}, &capWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, stderr
	cmd.WaitDelay = 2e9
	if err := cmd.Run(); err != nil {
		switch {
		case out.over:
			return Result{}, errors.New("export script output too large")
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return Result{}, errors.New("export script timed out")
		case ctx.Err() != nil: // the request went away
			return Result{}, errors.New("export cancelled")
		}
		return Result{}, fmt.Errorf("export script failed: %v: %s", err, tail(stderr.buf.String()))
	}
	ext := strings.TrimPrefix(e.Extension, ".")
	return Result{Filename: in.Engagement.ID + "." + ext, ContentType: contentType(ext), Data: out.buf.Bytes()}, nil
}
