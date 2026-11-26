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

// buildVersion is version, else what debug.ReadBuildInfo gives: the VCS
// revision (first 12 characters, with "+dirty" when modified), else the
// module version, else "dev".
func buildVersion() string {
	if version != "" {
		return version
	}
	info, _ := debug.ReadBuildInfo()
	return infoVersion(info)
}

// infoVersion is the version a build's own info gives: the VCS revision, as
// revision writes it (a build in a clone); without one, the module version
// (a go install build, from the module cache); without either, "dev".
func infoVersion(info *debug.BuildInfo) string {
	if info == nil {
		return "dev"
	}
	rev, modified := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	// "(devel)" is what Go writes when the main module has no version
	if mv := info.Main.Version; rev == "" && mv != "" && mv != "(devel)" {
		return mv
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
