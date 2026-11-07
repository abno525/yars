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
