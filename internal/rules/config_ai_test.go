package rules

import (
	"testing"

	"yars/internal/config"
)

// A new configuration (saved or pushed) brings its ai: settings to the AI
// rules too, not only the report structure.
func TestSetConfigReachesAIRunner(t *testing.T) {
	e := NewEngine(t.TempDir(), config.Default())
	c := config.Default()
	c.AI = config.AIConfig{Provider: "openai", BaseURL: "https://llm.example/v1", Model: "m2", APIKeyEnv: "YARS_TEST_KEY"}
	e.SetConfig(c)
	got, _, _ := e.Runner.(*Runner).Effective()
	if got.Provider != "openai" || got.Model != "m2" || got.BaseURL != "https://llm.example/v1" {
		t.Fatalf("runner AI settings %+v", got)
	}
}

// Q11: AI rules can run only with a provider and a key.
func TestAIConfigured(t *testing.T) {
	e := NewEngine(t.TempDir(), config.Default())
	rn := e.Runner.(*Runner)
	rn.Getenv = func(k string) string { return map[string]string{"YARS_TEST_KEY": "sk-1"}[k] }
	if e.AIConfigured() {
		t.Fatal("configured without a provider")
	}
	c := config.Default()
	c.AI = config.AIConfig{Provider: "openai", BaseURL: "https://llm.example/v1", Model: "m2", APIKeyEnv: "YARS_NO_SUCH_KEY"}
	e.SetConfig(c)
	if e.AIConfigured() {
		t.Fatal("configured without a key")
	}
	c.AI.APIKeyEnv = "YARS_TEST_KEY"
	e.SetConfig(c)
	if !e.AIConfigured() {
		t.Fatal("not configured with a provider and a key")
	}
}
