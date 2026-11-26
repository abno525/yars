package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// log.level and log.format: each word is accepted, no key is the default
// (empty), another word is refused with the key in the message.
func TestLogKeys(t *testing.T) {
	for _, lv := range []string{"debug", "info", "warn", "error"} {
		c, err := Parse([]byte("log:\n  level: " + lv + "\n"))
		if err != nil || c.Log.Level != lv {
			t.Errorf("log.level %s: %q, %v", lv, c.Log.Level, err)
		}
	}
	for _, f := range []string{"text", "json"} {
		c, err := Parse([]byte("log:\n  format: " + f + "\n"))
		if err != nil || c.Log.Format != f {
			t.Errorf("log.format %s: %q, %v", f, c.Log.Format, err)
		}
	}
	c, err := Parse(nil)
	if err != nil || c.Log.Level != "" || c.Log.Format != "" {
		t.Errorf("no log keys: %+v, %v", c.Log, err)
	}
	for in, want := range map[string]string{
		"log:\n  level: verbose\n": `config: log.level "verbose" must be debug, info, warn or error`,
		"log:\n  level: INFO\n":    `config: log.level "INFO" must be debug, info, warn or error`,
		"log:\n  format: logfmt\n": `config: log.format "logfmt" must be text or json`,
	} {
		if _, err := Parse([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", in, err, want)
		}
	}
}

// yars init writes the default configuration: it holds no log key.
func TestDefaultWritesNoLogKey(t *testing.T) {
	b, err := yaml.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains("\n"+string(b), "\nlog:") {
		t.Errorf("the default config.yaml names log:\n%s", b)
	}
}
