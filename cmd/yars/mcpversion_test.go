package main

import (
	"bytes"
	"strings"
	"testing"

	"yars/internal/config"
)

// Q11: the MCP server of yars serve and of yars mcp names the build's
// version in initialize, as yars version prints it.
func TestMCPNamesBuildVersion(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "v1.2.3"
	if s := mcpServer(nil, nil, nil, config.Config{}, nil); s.Version != "v1.2.3" {
		t.Fatalf("serve's MCP server: %q", s.Version)
	}
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	var out bytes.Buffer
	if err := runMCP([]string{"--data", dir, "--user", "alice"}, in, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"serverInfo":{"name":"yars","version":"v1.2.3"}`) {
		t.Fatalf("yars mcp: %s", out.String())
	}
}
