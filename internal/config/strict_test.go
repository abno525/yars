package config

import (
	"reflect"
	"strings"
	"testing"
)

// A key YARS does not know is refused with its name and line: a typo such
// as base-url was read as "not set" without a word.
func TestUnknownKeyRefused(t *testing.T) {
	for body, wants := range map[string][]string{
		"base-url: https://yars.example.com\n":             {`unknown key "base-url"`, "line 1"},
		"sections: [A]\nsmtp:\n  hots: mail.example.com\n": {`unknown key "hots"`, "line 3"},
		"ai:\n  provider: openai\n  api_key: sk-1\n":       {`unknown key "api_key"`, "line 3"},
		"severity: [critical]\nbase-url: x\n":              {`unknown key "severity"`, "line 1", `unknown key "base-url"`, "line 2"},
	} {
		_, err := Parse([]byte(body))
		if err == nil {
			t.Fatalf("loaded:\n%s", body)
		}
		for _, w := range append(wants, "config: ", ".yars/config.yaml in the data folder", "commit") {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%q: the message lacks %q: %v", body, w, err)
			}
		}
		if strings.Contains(err.Error(), "config.Config") || strings.Contains(err.Error(), "SMTPConfig") {
			t.Errorf("the message names a Go type: %v", err)
		}
	}
	if _, err := Load(writeCfg(t, "base-url: x\n")); err == nil {
		t.Fatal("Load took an unknown key")
	}
}

// A file without any key is all defaults, as a missing one: empty, blank,
// comments only, or an empty document.
func TestEmptyConfigIsDefaults(t *testing.T) {
	for _, body := range []string{"", "\n\n", "# nothing set\n", "---\n", "# a comment\n---\n# another\n"} {
		c, err := Parse([]byte(body))
		if err != nil || !reflect.DeepEqual(c, Default()) {
			t.Fatalf("%q: %+v %v", body, c, err)
		}
	}
	if c, err := Parse(nil); err != nil || !reflect.DeepEqual(c, Default()) {
		t.Fatalf("nil: %+v %v", c, err)
	}
}

// Every key of the documented example is known.
func TestDocumentedKeysLoad(t *testing.T) {
	c, err := Parse([]byte(`workflow: standard
severities: [critical, high, medium, low, info]
sections: [Description, Impact]
details_rows: [Location]
report_sections: [Executive summary]
cvss:
  version: "3.1"
  standard: { AC: L, A: "-" }
ai:
  provider: anthropic
  base_url: https://ai.example.com
  model: m
  api_key_env: YARS_AI_KEY
base_url: https://yars.example.com
smtp:
  host: mail.example.com
  port: 587
  from: yars@example.com
  username: yars
  password_env: YARS_SMTP_PASSWORD
checks:
  max_running: 4
log:
  level: info
  format: text
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.SMTP != (SMTPConfig{Host: "mail.example.com", Port: 587, From: "yars@example.com", Username: "yars", PasswordEnv: "YARS_SMTP_PASSWORD"}) {
		t.Fatalf("smtp %+v", c.SMTP)
	}
}

// smtp.port is a port, smtp.from a bare address (it is the envelope sender
// too) and smtp.host a host name without a port: a line break in one of them
// would be a header or a command of its own.
func TestSMTPValuesChecked(t *testing.T) {
	load := func(smtp string) error {
		_, err := Parse([]byte("smtp:\n" + smtp))
		return err
	}
	for _, good := range []string{
		"  port: 587\n", "  port: 0\n", "  port: 65535\n",
		"  from: a@b\n", "  from: yars@example.com\n",
		"  host: mail.example.com\n", "  host: 10.0.0.5\n", "  host: \"[::1]\"\n", "  host: localhost\n",
		"  host: mail.example.com\n  port: 25\n  from: yars@example.com\n",
	} {
		if err := load(good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for bad, key := range map[string]string{
		"  port: -1\n":                          "smtp.port",
		"  port: 70000\n":                       "smtp.port",
		"  from: \"YARS <yars@example.com>\"\n": "smtp.from",
		"  from: \"a@b\\r\\nBcc: x@y\"\n":       "smtp.from",
		"  from: \"a@b\\nRCPT TO:<x@y>\"\n":     "smtp.from",
		"  from: not-an-address\n":              "smtp.from",
		"  from: \"a@b \"\n":                    "smtp.from",
		"  host: smtp://mail.example.com\n":     "smtp.host",
		"  host: mail.example.com:587\n":        "smtp.host",
		"  host: mail example.com\n":            "smtp.host",
		"  host: mail.example.com/x\n":          "smtp.host",
		"  host: \"mail.example.com\\r\\nX\"\n": "smtp.host",
		"  host: \"::1\"\n":                     "smtp.host",
	} {
		err := load(bad)
		if err == nil || !strings.Contains(err.Error(), "config: "+key) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the port's default is still 25
	if c, _ := Parse([]byte("smtp:\n  host: mail.example.com\n")); c.SMTP.Port != 25 {
		t.Fatalf("port %d", c.SMTP.Port)
	}
}
