package export

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	// --sandbox: pandoc may not read or fetch anything but its arguments
	// (images are already inlined as data URIs from the finding's attachments).
	args := []string{"--sandbox", "-f", "html", "-o", out, "--standalone", "--metadata", "title=" + in.Engagement.Name}
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
	input := "<html><body>\n" + XHTML(in, false) + "</body></html>\n"
	run := func(args []string) (string, error) {
		cmd := exec.CommandContext(ctx, r.PandocPath, args...)
		cmd.Dir = tmp
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + tmp, "TMPDIR=" + tmp} // no server secrets
		cmd.Stdin = strings.NewReader(input)
		stderr := &capWriter{max: 1 << 20}
		cmd.Stderr = stderr
		cmd.WaitDelay = 2e9
		err := cmd.Run()
		return stderr.buf.String(), err
	}
	stderr, err := run(args)
	if err != nil && strings.Contains(stderr, "Could not find data file") {
		// Some pandoc builds can't load their own data files under
		// --sandbox. Images are already inlined/removed and raw HTML is
		// stripped, so retry unsandboxed with an empty resource path.
		args = append(slices.DeleteFunc(slices.Clone(args), func(a string) bool { return a == "--sandbox" }), "--resource-path="+tmp)
		stderr, err = run(args)
	}
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, errors.New("pandoc timed out")
		}
		return Result{}, fmt.Errorf("pandoc failed: %v: %s", err, tail(stderr))
	}
	info, err := os.Stat(out)
	if err != nil {
		return Result{}, fmt.Errorf("pandoc produced no output: %s", tail(stderr))
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
