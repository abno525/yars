// Package docs embeds the developer pages that the server shows under
// /docs.
package docs

import "embed"

// Pages are the pages the server shows, without ".md". The embed line
// below names the same files: a test holds the two together.
var Pages = []string{"config", "exporters", "git", "mcp", "rules", "webhooks"}

// FS holds the pages of Pages and nothing else of docs/.
//
//go:embed config.md exporters.md git.md mcp.md rules.md webhooks.md
var FS embed.FS

// Page reads docs/<name>.md.
func Page(name string) (string, error) {
	b, err := FS.ReadFile(name + ".md")
	return string(b), err
}
