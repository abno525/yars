package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// rpcError is the JSON-RPC error of Handle's answer to msg (nil: none).
func rpcError(t *testing.T, f *fx, msg string) map[string]any {
	t.Helper()
	out := f.s.Handle(context.Background(), alice, []byte(msg))
	var r map[string]any
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("answer %q to %s: %v", out, msg, err)
	}
	e, _ := r["error"].(map[string]any)
	return e
}

// R2: the scheme word of Authorization in any case, then spaces.
func TestBearerAnyCase(t *testing.T) {
	f := newFx(t)
	srv, _, tok := f.httpServer(t)
	send := func(auth string) int {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", auth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, auth := range []string{"Bearer " + tok, "bearer " + tok, "BEARER   " + tok} {
		if c := send(auth); c != 200 {
			t.Errorf("%q: %d", strings.Fields(auth)[0], c)
		}
	}
	for _, auth := range []string{"Bearer" + tok, "Basic " + tok, tok} {
		if c := send(auth); c != 401 {
			t.Errorf("%q accepted: %d", auth[:6], c)
		}
	}
}

// 2025-03-26 needs request batches, which are not supported: not offered.
func TestOldProtocolNotOffered(t *testing.T) {
	f := newFx(t)
	r := f.rpc(alice, "initialize", map[string]any{"protocolVersion": "2025-03-26"})
	if v := r["result"].(map[string]any)["protocolVersion"]; v != "2025-06-18" {
		t.Fatalf("answered %v", v)
	}
	if got := ProtocolVersions(); len(got) != 2 || got[0] != "2025-06-18" || got[1] != "2024-11-05" {
		t.Fatalf("versions %v", got)
	}
}

func TestBatchIsInvalidRequest(t *testing.T) {
	f := newFx(t)
	e := rpcError(t, f, ` [{"jsonrpc":"2.0","id":1,"method":"ping"}]`)
	if e == nil || e["code"] != float64(-32600) || e["message"] != "batches are not supported" {
		t.Fatalf("%v", e)
	}
}

func TestRejectsWrongJSONRPC(t *testing.T) {
	f := newFx(t)
	for _, msg := range []string{`{"jsonrpc":"1.0","id":1,"method":"ping"}`, `{"id":1,"method":"ping"}`} {
		if e := rpcError(t, f, msg); e == nil || e["code"] != float64(-32600) || e["message"] != "jsonrpc must be 2.0" {
			t.Errorf("%s: %v", msg, e)
		}
	}
}

func TestRejectsNullID(t *testing.T) {
	f := newFx(t)
	if e := rpcError(t, f, `{"jsonrpc":"2.0","id":null,"method":"ping"}`); e == nil || e["code"] != float64(-32600) || e["message"] != "id must not be null" {
		t.Fatalf("%v", e)
	}
}

// A request without an id is a notification: never answered.
func TestNotificationStillSilent(t *testing.T) {
	f := newFx(t)
	for _, msg := range []string{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, `{"jsonrpc":"2.0","method":"ping"}`} {
		if out := f.s.Handle(context.Background(), alice, []byte(msg)); out != nil {
			t.Errorf("%s answered: %s", msg, out)
		}
	}
}

// A line over the limit is a parse error; the session goes on.
func TestStdioLongLineGoesOn(t *testing.T) {
	f := newFx(t)
	long := `{"jsonrpc":"2.0","id":1,"method":"ping","params":"` + strings.Repeat("x", 9<<20) + `"}`
	in := strings.NewReader(long + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n")
	var out bytes.Buffer
	if err := f.s.ServeStdio(context.Background(), alice, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "-32700") || !strings.Contains(lines[1], `"id":2`) {
		t.Fatalf("stdio output:\n%.400s", out.String())
	}
}
