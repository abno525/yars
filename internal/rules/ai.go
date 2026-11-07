package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"yars/internal/config"
)

const systemPrompt = `You check penetration-test findings against one style rule. Reply with JSON only: {"violations":[{"quote":"exact text from the input","message":"what is wrong and how to fix it"}]}. Return an empty list when the text follows the rule.`

type aiResult struct {
	Violations []struct {
		Quote   string `json:"quote"`
		Message string `json:"message"`
	} `json:"violations"`
}

func aiWarning(r Rule, msg string) []Violation {
	return []Violation{{Rule: r.ID, Level: "warning", Message: msg, Target: "ai"}}
}

// ProviderOff, saved on the admin page, turns AI rules off whatever
// config.yaml says.
const ProviderOff = "off"

// Effective returns the AI settings in use: the admin page's (Stored) over
// config.yaml, field by field, and the key: the environment variable named
// by api_key_env wins over the stored key (fromEnv reports which), but only
// while the provider and address are config.yaml's, so the operator's key
// never goes to an address or provider set on the web page.
func (rn *Runner) Effective() (c config.AIConfig, key string, fromEnv bool) {
	conf := rn.aiConf()
	c = conf
	stored := ""
	if rn.Stored != nil {
		s, k := rn.Stored()
		switch s.Provider {
		case "":
		case ProviderOff:
			c.Provider = ""
		default:
			c.Provider = s.Provider
		}
		if s.BaseURL != "" {
			c.BaseURL = s.BaseURL
		}
		if s.Model != "" {
			c.Model = s.Model
		}
		stored = k
	}
	if EnvKeyApplies(conf, c) && rn.Getenv != nil {
		if k := rn.Getenv(c.APIKeyEnv); k != "" {
			return c, k, true
		}
	}
	return c, stored, false
}

// EnvKeyApplies reports whether the key in config.yaml's api_key_env may be
// sent with the effective settings eff: only to config.yaml's own provider
// and address.
func EnvKeyApplies(conf, eff config.AIConfig) bool {
	return conf.APIKeyEnv != "" && eff.Provider == conf.Provider && eff.BaseURL == conf.BaseURL
}

// ask sends one prompt to the provider in c.
func (rn *Runner) ask(ctx context.Context, c config.AIConfig, key, user string) (string, error) {
	if c.Provider == "anthropic" {
		return rn.anthropic(ctx, c, key, user)
	}
	return rn.openai(ctx, c, key, user)
}

// Ping sends a minimal request to the provider in use and returns how long
// the reply took (the admin page's Test button and the health check).
func (rn *Runner) Ping(ctx context.Context) (time.Duration, error) {
	c, key, _ := rn.Effective()
	if c.Provider == "" || key == "" {
		return 0, errors.New("no AI provider configured")
	}
	ctx, cancel := context.WithTimeout(ctx, min(rn.AITimeout, 20*time.Second))
	defer cancel()
	start := time.Now()
	content, err := rn.ask(ctx, c, key, "Rule: none.\n\nText (title):\nping")
	if err != nil {
		return 0, err
	}
	var res aiResult
	if err := parseAI(content, &res); err != nil {
		return 0, err
	}
	return max(time.Since(start), time.Nanosecond), nil
}

// AI asks the configured model whether text (from target) follows the rule.
// Provider errors are warnings, never blocking.
func (rn *Runner) AI(ctx context.Context, r Rule, target, text string) []Violation {
	c, key, _ := rn.Effective()
	if c.Provider == "" || key == "" {
		return aiWarning(r, "AI rules skipped: no AI provider configured")
	}
	h := sha256.Sum256([]byte(c.Provider + "\x00" + c.Model + "\x00" + r.AI + "\x00" + text))
	ck := hex.EncodeToString(h[:])
	var res aiResult
	if v, ok := rn.aiCache().Get(ck); ok {
		res = v
	} else {
		ctx, cancel := context.WithTimeout(ctx, rn.AITimeout)
		defer cancel()
		user := "Rule: " + r.AI + "\n\nText (" + target + "):\n" + text
		content, err := rn.ask(ctx, c, key, user)
		if err == nil {
			err = parseAI(content, &res)
		}
		if err != nil {
			return aiWarning(r, "AI check failed: "+quote(err.Error()))
		}
		rn.aiCache().Add(ck, res)
	}
	var vs []Violation
	for _, x := range res.Violations {
		msg := x.Message
		if msg == "" {
			msg = r.message()
		}
		vs = append(vs, r.v(target, msg, x.Quote))
	}
	return vs
}

// parseAI extracts the first JSON object from the model's reply.
func parseAI(content string, res *aiResult) error {
	i, j := strings.Index(content, "{"), strings.LastIndex(content, "}")
	if i < 0 || j < i {
		return errors.New("reply is not JSON")
	}
	return json.Unmarshal([]byte(content[i:j+1]), res)
}

func (rn *Runner) post(ctx context.Context, url string, body any, hdr map[string]string, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := rn.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}

func (rn *Runner) openai(ctx context.Context, c config.AIConfig, key, user string) (string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	body := map[string]any{
		"model":           c.Model,
		"temperature":     0,
		"response_format": map[string]string{"type": "json_object"},
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": user},
		},
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := rn.post(ctx, base+"/chat/completions", body, map[string]string{"Authorization": "Bearer " + key}, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("empty reply")
	}
	return out.Choices[0].Message.Content, nil
}

func (rn *Runner) anthropic(ctx context.Context, c config.AIConfig, key, user string) (string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	body := map[string]any{
		"model":      c.Model,
		"max_tokens": 1024,
		"system":     systemPrompt,
		"messages":   []map[string]string{{"role": "user", "content": user}},
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	hdr := map[string]string{"x-api-key": key, "anthropic-version": "2023-06-01"}
	if err := rn.post(ctx, base+"/v1/messages", body, hdr, &out); err != nil {
		return "", err
	}
	for _, c := range out.Content {
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	return "", errors.New("empty reply")
}
