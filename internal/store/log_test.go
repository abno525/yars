package store

import (
	"strings"
	"testing"
)

// A pushed or saved config.yaml is held to the log keys' words too
// (CheckConfig is what a push and Admin › Structure both go through).
func TestCheckConfigLogKeys(t *testing.T) {
	if _, err := CheckConfig([]byte("log:\n  level: debug\n  format: json\n")); err != nil {
		t.Errorf("good log keys: %v", err)
	}
	if _, err := CheckConfig([]byte("log:\n  level: chatty\n")); err == nil || !strings.Contains(err.Error(), `log.level "chatty"`) {
		t.Errorf("log.level chatty: %v", err)
	}
	if _, err := CheckConfig([]byte("log:\n  format: csv\n")); err == nil || !strings.Contains(err.Error(), `log.format "csv"`) {
		t.Errorf("log.format csv: %v", err)
	}
}

// A log line names a finding by its ID alone: the folder's name holds the
// title's slug.
func TestLogID(t *testing.T) {
	for in, want := range map[string]string{
		"F-001-sql-injection": "F-001",
		"F-001":               "F-001",
		"001":                 "F-001",
		"7":                   "F-7",
		"custom-dir":          "?",
		"":                    "?",
		"F-abc":               "?",
		"F-0000000000001-x":   "?",
	} {
		if got := LogID(in); got != want {
			t.Errorf("LogID(%q) = %q, want %q", in, got, want)
		}
	}
}
