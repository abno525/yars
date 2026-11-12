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

// A line over the limit is a parse error; the session goes on. A long line
// within it (more than the reader's buffer) and CRLF ends are read whole.
func TestStdioLongLineGoesOn(t *testing.T) {
	f := newFx(t)
	long := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("x", 9<<20) + `"}}`
	mid := `{"jsonrpc":"2.0","id":3,"method":"ping","params":{"x":"` + strings.Repeat("y", 200<<10) + `"}}`
	in := strings.NewReader(long + "\n" + `{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\r\n" + mid + "\n")
	var out bytes.Buffer
	if err := f.s.ServeStdio(context.Background(), alice, in, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "longer than 8 MiB") || !strings.Contains(lines[1], `"id":2`) || !strings.Contains(lines[2], `"id":3,"result"`) {
		t.Fatalf("stdio output:\n%.400s", out.String())
	}
}

// failingReader gives its data, then an error mid-line.
type failingReader struct{ data []byte }

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// A read error mid-line ends the session with the error; the cut line is
// not answered.
func TestStdioReadErrorMidLine(t *testing.T) {
	f := newFx(t)
	var out bytes.Buffer
	err := f.s.ServeStdio(context.Background(), alice, &failingReader{[]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n" + `{"jsonrpc":"2.0","id":2,"me`)}, &out)
	if err == nil || strings.Count(out.String(), "\n") != 1 || strings.Contains(out.String(), "-32700") {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

// An id is a string or a number (MCP); never an object, array or boolean.
func TestRejectsBadID(t *testing.T) {
	f := newFx(t)
	for _, id := range []string{`{}`, `[1]`, `true`} {
		e := rpcError(t, f, `{"jsonrpc":"2.0","id":`+id+`,"method":"ping"}`)
		if e == nil || e["code"] != float64(-32600) || e["message"] != "id must be a string or a number" {
			t.Errorf("id %s: %v", id, e)
		}
	}
	for _, id := range []string{`"a-1"`, `7`, `-2`} {
		if e := rpcError(t, f, `{"jsonrpc":"2.0","id":`+id+`,"method":"ping"}`); e != nil {
			t.Errorf("id %s refused: %v", id, e)
		}
	}
}

// Valid JSON that is no request is an invalid request (-32600), not a
// parse error; a client's response to nothing asked is left alone.
func TestNotARequest(t *testing.T) {
	f := newFx(t)
	for _, msg := range []string{`5`, `"x"`, `null`, `{"jsonrpc":2,"id":1,"method":"ping"}`, `{"jsonrpc":"2.0","id":1}`, `{"jsonrpc":"2.0","id":1,"method":5}`} {
		if e := rpcError(t, f, msg); e == nil || e["code"] != float64(-32600) {
			t.Errorf("%s: %v", msg, e)
		}
	}
	if out := f.s.Handle(context.Background(), alice, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)); out != nil {
		t.Errorf("a response answered: %s", out)
	}
}

// Member names are matched exactly: "ID" is not "id".
func TestExactMemberNames(t *testing.T) {
	f := newFx(t)
	if e := rpcError(t, f, `{"JSONRPC":"2.0","ID":7,"METHOD":"ping"}`); e == nil || e["code"] != float64(-32600) {
		t.Errorf("upper-case names: %v", e)
	}
	if out := f.s.Handle(context.Background(), alice, []byte(`{"jsonrpc":"2.0","method":"ping","Id":8}`)); out != nil {
		t.Errorf("Id is no id, so a notification: %s", out)
	}
}

// An invalid message without an id is answered with id null (JSON-RPC
// 2.0), and over HTTP with 400 (MCP: input it cannot accept).
func TestInvalidNotificationAnswered(t *testing.T) {
	f := newFx(t)
	msg := `{"jsonrpc":"1.0","method":"x"}`
	out := f.s.Handle(context.Background(), alice, []byte(msg))
	if !strings.Contains(string(out), `"id":null`) || !strings.Contains(string(out), "-32600") {
		t.Fatalf("%s", out)
	}
	srv, _, tok := f.httpServer(t)
	for _, body := range []string{msg, `{not json`, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`} {
		if c, b := post(t, srv.URL, tok, body); c != 400 || !strings.Contains(b, `"id":null`) {
			t.Errorf("%s: %d %s", body, c, b)
		}
	}
	if c, _ := post(t, srv.URL, tok, `{"jsonrpc":"2.0","id":1,"method":"nope"}`); c != 200 {
		t.Errorf("an unknown method is a request's answer: %d", c)
	}
}

// MCP 2025-06-18: an unsupported MCP-Protocol-Version header is 400.
func TestProtocolVersionHeader(t *testing.T) {
	f := newFx(t)
	srv, _, tok := f.httpServer(t)
	send := func(v string) int {
		req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		if v != "" {
			req.Header.Set("MCP-Protocol-Version", v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := send("1999-01-01"); c != 400 {
		t.Errorf("unsupported version: %d", c)
	}
	for _, v := range []string{"", "2025-06-18", "2024-11-05"} {
		if c := send(v); c != 200 {
			t.Errorf("%q: %d", v, c)
		}
	}
}
