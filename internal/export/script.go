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

	"yars/internal/rules"
)

type scriptDoc struct {
	rules.Doc
	HTMLSections map[string]string `json:"html_sections"`
}

func (r *Runner) script(ctx context.Context, e Exporter, in Input) (Result, error) {
	p, err := r.safePath(e.Script)
	if err != nil {
		return Result{}, err
	}
	var docs []scriptDoc
	for _, f := range in.ordered() {
		d := scriptDoc{Doc: rules.DocOf(f), HTMLSections: map[string]string{}}
		for _, s := range f.Sections {
			var buf bytes.Buffer
			md.Convert([]byte(s.Body), &buf)
			d.HTMLSections[s.Name] = buf.String()
		}
		docs = append(docs, d)
	}
	input, err := json.Marshal(map[string]any{"engagement": in.Engagement, "engagement_id": in.Engagement.ID, "findings": docs})
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
		case ctx.Err() != nil:
			return Result{}, errors.New("export script timed out")
		}
		return Result{}, fmt.Errorf("export script failed: %v: %s", err, tail(stderr.buf.String()))
	}
	ext := strings.TrimPrefix(e.Extension, ".")
	return Result{Filename: in.Engagement.ID + "." + ext, ContentType: "application/octet-stream", Data: out.buf.Bytes()}, nil
}
