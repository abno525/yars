package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/logs"
)

//go:noinline
func panicsDeepForTheLogTest(n int) int {
	if n == 0 {
		panic("zqboom")
	}
	return panicsDeepForTheLogTest(n-1) + 1
}

func handlerOfThePanicLogTest(w http.ResponseWriter, r *http.Request) {
	panicsDeepForTheLogTest(40)
}

// A handler's panic is one line of the service log with the whole stack:
// net/http's text in err, the trace in stack, down to the handler that was
// called (the last frames of a trace, far past what a value is cut at).
func TestHandlerPanicKeepsItsStack(t *testing.T) {
	var out lockedBuf
	hs := (&Server{Auth: auth.New(nil), Logger: logs.New(&out, logs.JSON, slog.LevelInfo)}).HTTPServer("127.0.0.1:0")
	hs.Handler = http.HandlerFunc(handlerOfThePanicLogTest)
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = hs
	ts.Start()
	defer ts.Close()
	if res, err := ts.Client().Get(ts.URL); err == nil {
		res.Body.Close()
		t.Fatalf("answered %d", res.StatusCode)
	}
	var line string
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if line = out.String(); strings.Contains(line, "panic serving") {
			break
		}
	}
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("the panic is not one line:\n%s", line)
	}
	var rec struct{ Level, Msg, Err, Stack string }
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("%v:\n%s", err, line)
	}
	if rec.Level != "WARN" || rec.Msg != "http server" {
		t.Errorf("level %q, msg %q", rec.Level, rec.Msg)
	}
	if !strings.HasPrefix(rec.Err, "http: panic serving ") || !strings.HasSuffix(rec.Err, ": zqboom") {
		t.Errorf("err %q", rec.Err)
	}
	if len(rec.Stack) < 2048 {
		t.Errorf("the stack is %d bytes", len(rec.Stack))
	}
	for _, want := range []string{"goroutine ", "panicsDeepForTheLogTest", "handlerOfThePanicLogTest", "panic_log_test.go:", "net/http.(*conn).serve"} {
		if !strings.Contains(rec.Stack, want) {
			t.Errorf("the stack lacks %s", want)
		}
	}
	if t.Failed() {
		t.Logf("log:\n%s", line)
	}
}
