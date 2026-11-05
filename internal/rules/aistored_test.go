package rules

import (
	"context"
	"net/http"
	"testing"

	"yars/internal/config"
)

// Settings saved on the admin page override config.yaml; the environment
// variable's key still wins over the stored key.
func TestAIStoredSettings(t *testing.T) {
	var auth string
	f := &fakeAI{body: func(req map[string]any) string {
		if req["model"] != "stored-model" {
			return `{"error":"wrong model"}`
		}
		return `{"choices":[{"message":{"content":"{\"violations\":[]}"}}]}`
	}}
	f.check = func(r *http.Request) { auth = r.Header.Get("Authorization") }
	srv := f.server(t)
	r := NewRunner(t.TempDir(), config.AIConfig{APIKeyEnv: "TEST_KEY"})
	env := ""
	r.Getenv = func(k string) string {
		if k == "TEST_KEY" {
			return env
		}
		return ""
	}
	r.Stored = func() (config.AIConfig, string) {
		return config.AIConfig{Provider: "openai", BaseURL: srv.URL, Model: "stored-model"}, "stored-key"
	}
	if vs := r.AI(context.Background(), acr, "title", "one"); len(vs) != 0 {
		t.Fatalf("got %+v", vs)
	}
	if auth != "Bearer stored-key" {
		t.Fatalf("auth %q", auth)
	}
	env = "env-key"
	r.AI(context.Background(), acr, "title", "two")
	if auth != "Bearer env-key" {
		t.Fatalf("env key does not win: %q", auth)
	}
	c, key, fromEnv := r.Effective()
	if c.Model != "stored-model" || key != "env-key" || !fromEnv {
		t.Fatalf("effective %+v %q %v", c, key, fromEnv)
	}
	if d, err := r.Ping(context.Background()); err != nil || d <= 0 {
		t.Fatalf("ping %v %v", d, err)
	}
	r.Stored = func() (config.AIConfig, string) { return config.AIConfig{}, "" }
	env = ""
	if _, err := r.Ping(context.Background()); err == nil {
		t.Fatal("ping without a provider succeeded")
	}
	// "off" on the admin page turns off a provider set in config.yaml
	r.AIConf.Provider = "openai"
	r.Stored = func() (config.AIConfig, string) { return config.AIConfig{Provider: "off"}, "k" }
	if c, _, _ := r.Effective(); c.Provider != "" {
		t.Fatalf("provider %q", c.Provider)
	}
}
