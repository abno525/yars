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
	// the environment key never goes to an address or provider set on the
	// admin page: only to config.yaml's
	env = "env-key"
	r.AI(context.Background(), acr, "title", "two")
	if auth != "Bearer stored-key" {
		t.Fatalf("env key sent to the admin page's address: %q", auth)
	}
	if _, key, fromEnv := r.Effective(); key != "stored-key" || fromEnv {
		t.Fatalf("key %q fromEnv %v", key, fromEnv)
	}
	r.AIConf = config.AIConfig{Provider: "openai", BaseURL: srv.URL, APIKeyEnv: "TEST_KEY"}
	r.AI(context.Background(), acr, "title", "three")
	if auth != "Bearer env-key" {
		t.Fatalf("env key does not win at config.yaml's address: %q", auth)
	}
	c, key, fromEnv := r.Effective()
	if c.Model != "stored-model" || key != "env-key" || !fromEnv {
		t.Fatalf("effective %+v %q %v", c, key, fromEnv)
	}
	// a provider switch on the admin page does not send the other provider's key
	r.Stored = func() (config.AIConfig, string) {
		return config.AIConfig{Provider: "anthropic", BaseURL: srv.URL}, ""
	}
	if _, key, fromEnv := r.Effective(); key != "" || fromEnv {
		t.Fatalf("provider switch: key %q fromEnv %v", key, fromEnv)
	}
	r.Stored = func() (config.AIConfig, string) {
		return config.AIConfig{Provider: "openai", BaseURL: srv.URL, Model: "stored-model"}, "stored-key"
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
