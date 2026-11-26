package logs

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type valuer struct{ v string }

func (v valuer) LogValue() slog.Value { return slog.StringValue(v.v) }

// redacted are the records a logger behind Redact passes on.
func redacted() (*slog.Logger, *Recorder) {
	_, rec := NewRecorder()
	return slog.New(Redact(&recHandler{to: rec})), rec
}

// An attribute whose key names something private is dropped, however the
// key is written and however the attribute reaches the handler: on the
// line, from With, in a group, behind a LogValuer.
func TestRedactDropsPrivateKeys(t *testing.T) {
	const m = "zqsecret7f3kq"
	for _, key := range []string{"password", "Password", "new_password", "newPassword", "passwd", "pw", "token", "auth_token", "authToken", "secret",
		"key", "api_key", "api-key", "apiKey", "authorization", "Authorization", "cookie", "Set-Cookie", "session", "body", "text", "title", "reason",
		"chat", "name", "file_name", "filename", "label", "prompt", "answer", "query", "q", "email", "comment", "content"} {
		lg, rec := redacted()
		lg.Info("on the line", key, m)
		lg.With(key, m).Info("with")
		lg.Info("in a group", slog.Group("g", key, m))
		lg.With(slog.Group("g", key, m)).Info("with a group")
		lg.WithGroup("g").Info("under a group", key, m)
		lg.WithGroup(key).Info("a group of that name", "value", m)
		lg.Info("a group attribute of that name", slog.Group(key, "value", m))
		lg.Info("a valuer", key, valuer{m})
		lg.Info("an error", key, errors.New(m))
		if len(rec.Records()) != 9 {
			t.Fatalf("%s: %d records", key, len(rec.Records()))
		}
		if strings.Contains(rec.Text(), m) {
			t.Errorf("key %q passes:\n%s", key, rec.Text())
		}
	}
}

// The fields of the log pass, in a group and from With too; token passes as
// a number (a token's ID) and never as a string (its value).
func TestRedactKeepsTheLogsFields(t *testing.T) {
	lg, rec := redacted()
	lg.With("req", "4f2a9c1b").WithGroup("g").Info("request", "user", "alice", "token", int64(17), "eng", "acme", "finding", "F-001",
		"route", "GET /e/{eng}", "status", 200, "ms", int64(3), "err", errors.New("disk full"), "setup_code", "abcd-efgh-ijkl",
		"tool", "read_finding", "code", "ok", "method", "GET", "users", []string{"Alice", "alice"}, "monkey", "x", "keyboard", "y")
	r := rec.Records()[0]
	for key, want := range map[string]string{"req": "4f2a9c1b", "g.user": "alice", "g.token": "17", "g.eng": "acme", "g.finding": "F-001",
		"g.route": "GET /e/{eng}", "g.status": "200", "g.ms": "3", "g.err": "disk full", "g.setup_code": "abcd-efgh-ijkl", "g.tool": "read_finding",
		"g.code": "ok", "g.method": "GET", "g.users": "[Alice alice]", "g.monkey": "x", "g.keyboard": "y"} {
		if r.Str(key) != want {
			t.Errorf("%s = %q, want %q", key, r.Str(key), want)
		}
	}
	if _, ok := r.Attrs["g.token"].(int64); !ok {
		t.Errorf("token is %T", r.Attrs["g.token"])
	}
	lg.Info("a token's value", "token", "yars_0123")
	if r := rec.Records()[1]; r.Has("token") {
		t.Errorf("a token's value passes: %s", r)
	}
}

// The text of a value is cleaned: a finding's folder becomes its ID, an
// attachment's name goes, an address loses its login and query, and a long
// value is cut.
func TestRedactScrubsValues(t *testing.T) {
	for in, want := range map[string]string{
		"open /srv/yars/engagements/acme/findings/F-001-zqtitle7f3kq/finding.md: permission denied":   "open /srv/yars/engagements/acme/findings/F-001/finding.md: permission denied",
		"openat engagements/acme/findings/F-002-zqtitle7f3kq/.finding.md.yars-tmp: permission denied": "openat engagements/acme/findings/F-002/.finding.md.yars-tmp: permission denied",
		"F-012-zqtitle7f3kq: front matter": "F-012: front matter",
		"yaml: unmarshal errors:\n  line 5: cannot unmarshal !!str `zqtext7f3kq` into map[string]string": "yaml: unmarshal errors:\n  line 5: cannot unmarshal !!str `-` into map[string]string",
		"finding F-001 of acme": "finding F-001 of acme",
		"remove findings/F-003-x/attachments/zqfile7f3kq.png: no such file":                                    "remove findings/F-003/attachments/-: no such file",
		`Post "https://zquser7f3kq:zqpw7f3kq@hooks.example.com/in/abc?secret=zqkey7f3kq#zqfrag7f3kq": timeout`: `Post "https://hooks.example.com/in/abc": timeout`,
		"dial http://localhost:8080/v1?key=zqkey7f3kq failed":                                                  "dial http://localhost:8080/v1 failed",
		"no address here: a?b=c": "no address here: a?b=c",
	} {
		lg, rec := redacted()
		lg.Error("failed", "err", errors.New(in))
		lg.With("err", in).Error("failed")
		for _, r := range rec.Records() {
			if got := r.Str("err"); got != want {
				t.Errorf("scrub(%q)\n got %q\nwant %q", in, got, want)
			}
		}
	}
	lg, rec := redacted()
	lg.Error("failed", "err", strings.Repeat("é", 10<<10))
	if got := rec.Records()[0].Str("err"); len(got) > valueMax+4 || !strings.HasSuffix(got, "…") || !strings.HasPrefix(got, "ééé") {
		t.Errorf("a long value: %d bytes", len(got))
	}
}

// The service log is built behind Redact, in both formats.
func TestHandlerRedacts(t *testing.T) {
	for _, format := range []string{Text, JSON} {
		var buf bytes.Buffer
		lg := New(&buf, format, slog.LevelDebug)
		lg.With("password", "zqpw7f3kq").Debug("saved", "title", "zqtitle7f3kq", "eng", "acme",
			"err", errors.New("open findings/F-001-zqslug7f3kq/finding.md: permission denied"))
		got := buf.String()
		if strings.Contains(got, "zq") || !strings.Contains(got, "acme") || !strings.Contains(got, "findings/F-001/finding.md: permission denied") {
			t.Errorf("%s: %s", format, got)
		}
	}
}
