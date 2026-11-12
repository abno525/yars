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
	"time"
)

var extOf = map[string]string{"markdown": "md", "gfm": "md", "commonmark": "md", "html5": "html", "plain": "txt", "latex": "tex", "docx": "docx", "pdf": "pdf", "odt": "odt", "html": "html", "pptx": "pptx", "rtf": "rtf", "epub": "epub"}

// typeOf is the content type of each extension pandoc writes here, so a
// download does not depend on the server's mime table (which may lack
// docx, odt or md); others fall back to that table.
var typeOf = map[string]string{
	"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	"pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	"odt":  "application/vnd.oasis.opendocument.text", "epub": "application/epub+zip", "rtf": "application/rtf",
	"pdf": "application/pdf", "md": "text/markdown; charset=utf-8", "html": "text/html; charset=utf-8",
	"txt": "text/plain; charset=utf-8", "tex": "application/x-tex",
}

func (r *Runner) pandoc(ctx context.Context, e Exporter, in Input) (Result, error) {
	if r.PandocPath == "" {
		return Result{}, errors.New("pandoc is not installed on the server")
	}
	base := baseFormat(e.Format) // the format without its extensions
	if base == "pdf" { // Run holds a PDF worker
		limit := r.PDFTimeout
		if limit <= 0 {
			limit = 60 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	ext := extOf[base]
	if ext == "" {
		ext = base
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
	if base != "pdf" { // pdf: pandoc picks the writer from the extension
		args = append(args, "-t", e.Format)
	}
	if sub := in.subtitle(); sub != "" {
		args = append(args, "--metadata", "subtitle="+sub)
	}
	body := XHTML(in, false)
	switch {
	case e.Template != "":
		p, err := r.safePath(e.Template)
		if err != nil {
			return Result{}, err
		}
		switch base {
		case "docx", "odt", "pptx":
			args = append(args, "--reference-doc="+p)
		default:
			args = append(args, "--template="+p)
		}
	case base == "pdf":
		// the theme: report structure, embedded template and filter, xelatex
		tpl, lua, err := writeTheme(tmp)
		if err != nil {
			return Result{}, err
		}
		args = append(args, "--template="+tpl, "--lua-filter="+lua, "--pdf-engine=xelatex", "--metadata", "client="+in.Engagement.Client)
		in.strictImages = true
		body = Report(in)
	}
	args = append(args, e.Args...)
	input := "<html><body>\n" + body + "</body></html>\n"
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return Result{}, errors.New("pandoc timed out")
		}
		if ctx.Err() != nil { // the request went away
			return Result{}, errors.New("export cancelled")
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
	return Result{Filename: in.Engagement.ID + "." + ext, ContentType: contentType(ext), Data: data}, nil
}

// contentType is a file extension's type: YARS's own, else the mime
// table's, else bytes.
func contentType(ext string) string {
	if ct := typeOf[ext]; ct != "" {
		return ct
	}
	if ct := mime.TypeByExtension("." + ext); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
