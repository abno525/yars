// Package docs embeds the developer documentation (docs/*.md) that the
// server shows under /docs.
package docs

import "embed"

// FS holds the top-level Markdown files of docs/.
//
//go:embed *.md
var FS embed.FS

// Page reads docs/<name>.md.
func Page(name string) (string, error) {
	b, err := FS.ReadFile(name + ".md")
	return string(b), err
}
