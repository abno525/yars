package main

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/web"
)

// A certificate needs its key and the key its certificate.
func TestServeTLSFlagsNeedBoth(t *testing.T) {
	data := t.TempDir() // never the real default folder, even if the check broke
	for _, args := range [][]string{{"--tls-cert", "x"}, {"--tls-key", "y"}} {
		err := cmdServe(append([]string{"--data", data}, args...))
		if err == nil || err.Error() != "--tls-cert and --tls-key go together" {
			t.Fatalf("%v: err %v", args, err)
		}
	}
	if err := cmdServe([]string{"--data", data, "--https", "--tls-cert", "x"}); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("--https with only a certificate: %v", err)
	}
	// a certificate that does not load stops before the data folder is read
	err := cmdServe([]string{"--data", data, "--tls-cert", "missing.pem", "--tls-key", "missing.key"})
	if err == nil || !strings.HasPrefix(err.Error(), "--tls-cert, --tls-key:") {
		t.Fatalf("missing certificate: %v", err)
	}
}

// Told to stop, the server finishes the request in flight, ends open event
// streams, refuses new connections and closes the database.
func TestServeStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "ann", Role: "director", PasswordHash: pw}); err != nil {
		t.Fatal(err)
	}
	st := store.New(r, cfg, d)
	au := auth.New(d)
	tok, ok := au.Login("ann", "pw")
	if !ok {
		t.Fatal("login failed")
	}
	srv := &web.Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg}
	hs := srv.HTTPServer("127.0.0.1:0")
	inner := hs.Handler
	started := make(chan struct{})
	var once sync.Once
	hs.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			once.Do(func() { close(started) })
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}
		inner.ServeHTTP(w, req)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, hs, srv, st, d) }()

	// an open page's event stream
	req, _ := http.NewRequest("GET", "http://"+addr+"/events", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("events %d", stream.StatusCode)
	}
	if _, err := bufio.NewReader(stream.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	got := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			got <- -1
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	<-started // the request is in flight
	cancel()
	if code := <-got; code != http.StatusOK {
		t.Fatalf("the request in flight got %d", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return within 5 s")
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("the server still accepts connections")
	}
	if err := d.Ping(); err == nil {
		t.Fatal("the database is still open")
	}
}
