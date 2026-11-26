package main

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"

	"github.com/abno525/yars/internal/db"
)

// version is set at build time: go build -ldflags "-X main.version=v1.0.0".
var version = ""

// source is where this build's source code is; Settings › About links it.
// A changed build names its own: go build -ldflags "-X main.source=https://…".
var source = "https://github.com/abno525/yars"

// buildVersion is version, else the VCS revision from debug.ReadBuildInfo
// (first 12 characters, with "+dirty" when modified), else "dev".
func buildVersion() string {
	if version != "" {
		return version
	}
	rev, modified := "", false
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	return revision(rev, modified)
}

// revision is a VCS revision as a version: its first 12 characters, with
// "+dirty" when the tree was modified; "dev" when there is none.
func revision(rev string, modified bool) string {
	if rev == "" {
		return "dev"
	}
	v := rev[:min(len(rev), 12)]
	if modified {
		v += "+dirty"
	}
	return v
}

// cmdVersion prints: yars <version> (schema <db.SchemaVersion>, <Go release>)
func cmdVersion(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: yars version")
	}
	_, err := fmt.Fprintf(out, "yars %s (schema %d, %s)\n", buildVersion(), db.SchemaVersion, runtime.Version())
	return err
}
