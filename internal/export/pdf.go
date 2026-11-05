package export

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"path/filepath"
)

// The PDF theme (the Report-PDF design): a LaTeX template for xelatex and a
// Lua filter that turns the report's marked HTML (cover, finding heads,
// severity tags) into the template's commands.
var (
	//go:embed pdf/report.latex
	themeTemplate []byte
	//go:embed pdf/report.lua
	themeFilter []byte
)

// writeTheme puts the theme files into dir for one pandoc run.
func writeTheme(dir string) (tpl, lua string, err error) {
	tpl, lua = filepath.Join(dir, "report.latex"), filepath.Join(dir, "report.lua")
	if err = os.WriteFile(tpl, themeTemplate, 0o600); err == nil {
		err = os.WriteFile(lua, themeFilter, 0o600)
	}
	return tpl, lua, err
}

// pdfSlot waits for one of the PDF workers; release gives it back.
func (r *Runner) pdfSlot(ctx context.Context) (release func(), err error) {
	r.pdfOnce.Do(func() { r.pdfSlots = make(chan struct{}, pdfWorkers) })
	select {
	case r.pdfSlots <- struct{}{}:
		return func() { <-r.pdfSlots }, nil
	case <-ctx.Done():
		return nil, errors.New("PDF not started: " + ctx.Err().Error())
	}
}
