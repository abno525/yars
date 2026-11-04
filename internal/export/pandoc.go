package export

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var extOf = map[string]string{"markdown": "md", "gfm": "md", "commonmark": "md", "html5": "html", "plain": "txt", "latex": "tex", "docx": "docx", "pdf": "pdf", "odt": "odt", "html": "html", "pptx": "pptx", "rtf": "rtf", "epub": "epub"}

func (r *Runner) pandoc(ctx context.Context, e Exporter, in Input) (Result, error) {
	if r.PandocPath == "" {
		return Result{}, errors.New("pandoc is not installed on the server")
	}
	ext := extOf[e.Format]
	if ext == "" {
		ext = e.Format
	}
	tmp, err := os.MkdirTemp("", "yars-export-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(tmp)
	out := filepath.Join(tmp, "report."+ext)
	// pandoc reads the same sanitised XHTML as the Confluence export: raw
	// HTML from findings is already stripped, and <br/> in table cells
	// becomes a real line break in every output format.
	args := []string{"-f", "html", "-o", out, "--standalone", "--metadata", "title=" + in.Engagement.Name}
	if e.Format != "pdf" { // pdf: pandoc picks the writer from the extension
		args = append(args, "-t", e.Format)
	}
	if sub := in.subtitle(); sub != "" {
		args = append(args, "--metadata", "subtitle="+sub)
	}
	if e.Template != "" {
		p, err := r.safePath(e.Template)
		if err != nil {
			return Result{}, err
		}
		switch e.Format {
		case "docx", "odt", "pptx":
			args = append(args, "--reference-doc="+p)
		default:
			args = append(args, "--template="+p)
		}
	}
	args = append(args, e.Args...)
	cmd := exec.CommandContext(ctx, r.PandocPath, args...)
	cmd.Dir = tmp
	cmd.Stdin = strings.NewReader("<html><body>\n" + XHTML(in, false) + "</body></html>\n")
	stderr := &capWriter{max: 1 << 20}
	cmd.Stderr = stderr
	cmd.WaitDelay = 2e9
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Result{}, errors.New("pandoc timed out")
		}
		return Result{}, fmt.Errorf("pandoc failed: %v: %s", err, tail(stderr.buf.String()))
	}
	info, err := os.Stat(out)
	if err != nil {
		return Result{}, fmt.Errorf("pandoc produced no output: %s", tail(stderr.buf.String()))
	}
	if info.Size() > maxOutput {
		return Result{}, errors.New("pandoc output too large")
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return Result{}, err
	}
	ct := mime.TypeByExtension("." + ext)
	if ct == "" {
		ct = "application/octet-stream"
	}
	return Result{Filename: in.Engagement.ID + "." + ext, ContentType: ct, Data: data}, nil
}
