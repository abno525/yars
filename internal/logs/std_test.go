package logs

import (
	"log/slog"
	"strings"
	"testing"
)

// What net/http writes for a handler's panic is one record: its first part
// in err, the trace in stack. The trace is cleaned as any value is, and
// kept whole up to stackMax; a line without a trace has no stack.
func TestStdHandlerKeepsAPanicsStack(t *testing.T) {
	lg, rec := redacted()
	std := slog.NewLogLogger(StdHandler(lg, "http server"), slog.LevelWarn)
	frames := strings.Repeat("github.com/abno525/yars/internal/web.(*Server).page(...)\n\t/src/internal/web/server.go:100 +0x1c\n", 60)
	trace := "goroutine 52 [running]:\n" + frames + "opened findings/F-001-zqslug7f3kq/finding.md\nnet/http.(*conn).serve(0xc000)\n"
	std.Print("http: panic serving 192.0.2.1:1: two\nlines\n" + trace)
	std.Print("http: TLS handshake error from 192.0.2.1:1: EOF\n")
	std.Print("http: panic serving 192.0.2.1:1: x\ngoroutine 1 [running]:\n" + strings.Repeat("a", 2*stackMax))
	recs := rec.With("http server")
	if len(recs) != 3 {
		t.Fatalf("%d records:\n%s", len(recs), rec.Text())
	}
	r := recs[0]
	if r.Level != slog.LevelWarn || r.Str("err") != "http: panic serving 192.0.2.1:1: two\nlines" {
		t.Errorf("level %v, err %q", r.Level, r.Str("err"))
	}
	stack := r.Str("stack")
	if len(trace) < 4*valueMax || !strings.HasPrefix(stack, "goroutine 52 [running]:\n") || !strings.HasSuffix(stack, "net/http.(*conn).serve(0xc000)") {
		t.Errorf("the stack is cut: %d of %d bytes", len(stack), len(trace))
	}
	if strings.Contains(stack, "zqslug7f3kq") || !strings.Contains(stack, "findings/F-001/finding.md") {
		t.Errorf("the stack is not cleaned")
	}
	if r := recs[1]; r.Has("stack") || r.Str("err") != "http: TLS handshake error from 192.0.2.1:1: EOF" {
		t.Errorf("a line without a trace: %s", r)
	}
	if got := recs[2].Str("stack"); len(got) > stackMax+4 || !strings.HasSuffix(got, "…") {
		t.Errorf("a trace over the limit: %d bytes", len(got))
	}
	// only stack has the larger limit
	lg.Warn("failed", "err", strings.Repeat("a", 2*valueMax), "stack_of", strings.Repeat("a", 2*valueMax))
	last := rec.Records()[3]
	if len(last.Str("err")) > valueMax+4 || len(last.Str("stack_of")) > valueMax+4 {
		t.Errorf("a value over valueMax passes")
	}
}
