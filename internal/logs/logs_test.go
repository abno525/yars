package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// The same record in both formats: text is time level msg key=value, json
// one object a line; a debug line is hidden at info and shown at debug.
func TestFormatsAndLevel(t *testing.T) {
	for _, format := range []string{"", Text, JSON} {
		var buf bytes.Buffer
		lv := new(slog.LevelVar)
		lg := New(&buf, format, lv)
		lg.Debug("hidden", "eng", "acme")
		if buf.Len() != 0 {
			t.Fatalf("format %q: a debug line at info: %s", format, buf.String())
		}
		lg.Info("check finished", "eng", "acme", "ms", 12)
		got := buf.String()
		if strings.Count(got, "\n") != 1 {
			t.Fatalf("format %q: want one line, got %q", format, got)
		}
		if format == JSON {
			var m map[string]any
			if err := json.Unmarshal([]byte(got), &m); err != nil {
				t.Fatalf("json line does not parse: %v: %s", err, got)
			}
			if m["level"] != "INFO" || m["msg"] != "check finished" || m["eng"] != "acme" || m["ms"] != float64(12) || m["time"] == nil {
				t.Errorf("json line = %v", m)
			}
		} else {
			if !strings.HasPrefix(got, "time=") || !strings.Contains(got, ` level=INFO msg="check finished" eng=acme ms=12`) {
				t.Errorf("text line = %q", got)
			}
		}
		buf.Reset()
		lv.Set(slog.LevelDebug) // the level is read on every line
		lg.Debug("shown")
		if !strings.Contains(buf.String(), "shown") {
			t.Errorf("format %q: no debug line at debug", format)
		}
	}
}

// A line at Always passes every level and reads as INFO.
func TestAlwaysPassesEveryLevel(t *testing.T) {
	var buf bytes.Buffer
	lg := New(&buf, Text, slog.LevelError)
	lg.Warn("hidden")
	lg.Log(context.Background(), Always, "setup code", "setup_code", "abcd")
	got := buf.String()
	if strings.Contains(got, "hidden") || !strings.Contains(got, `level=INFO msg="setup code" setup_code=abcd`) {
		t.Errorf("got %q", got)
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{"": slog.LevelInfo, "debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError} {
		if got, ok := ParseLevel(in); !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, ok)
		}
	}
	for _, in := range []string{"INFO", "warning", "trace", " info"} {
		if _, ok := ParseLevel(in); ok {
			t.Errorf("ParseLevel(%q) is accepted", in)
		}
	}
	if !ValidFormat("") || !ValidFormat("text") || !ValidFormat("json") || ValidFormat("JSON") || ValidFormat("logfmt") {
		t.Error("ValidFormat")
	}
}

// A part without a logger writes nothing and does not panic.
func TestOrNil(t *testing.T) {
	Or(nil).Error("nothing", "err", "x")
	var buf bytes.Buffer
	lg := New(&buf, Text, slog.LevelInfo)
	if Or(lg) != lg {
		t.Error("Or(l) is not l")
	}
}
