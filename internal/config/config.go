// Package config loads .yars/config.yaml and .yars/users.yaml from a data repo.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"yars/internal/cvss"
	"yars/internal/gitrepo"
)

// The workflows a data folder can be set up with (yars init). The standard
// one has roles and review (draft → verification → complete → reported);
// the simple one has neither (draft → complete → reported).
const (
	WorkflowStandard = "standard"
	WorkflowSimple   = "simple"
)

type Config struct {
	// Workflow is the workflow yars init set up: WorkflowSimple, or ""
	// (also WorkflowStandard) for the standard one. It is fixed after init;
	// the standard workflow writes no key.
	Workflow    string   `yaml:"workflow,omitempty"`
	Severities  []string `yaml:"severities"`
	Sections    []string `yaml:"sections"`
	DetailsRows []string `yaml:"details_rows"`
	// ReportSections are the engagement's report-level sections (executive
	// summary, scope, …), stored as report/<slug>.md in the engagement.
	ReportSections []string   `yaml:"report_sections"`
	CVSS           CVSSConfig `yaml:"cvss"`
	AI             AIConfig   `yaml:"ai"`
	// BaseURL is the server's address as people open it (links in webhooks
	// and email); "" = links are paths only.
	BaseURL string       `yaml:"base_url"`
	SMTP    SMTPConfig   `yaml:"smtp"`
	Checks  ChecksConfig `yaml:"checks"`
}

// ChecksConfig bounds the stored check runs (Check, start_check, the run
// after Fix with AI): MaxRunning run at once, the others wait in a queue.
type ChecksConfig struct {
	MaxRunning int `yaml:"max_running"` // at least 1
}

// DefaultMaxRunning is checks.max_running when config.yaml sets none.
const DefaultMaxRunning = 4

// SMTPConfig sends notification email. The password is read from the
// environment variable named by PasswordEnv and never stored in the repo.
type SMTPConfig struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // default 25
	From        string `yaml:"from"`
	Username    string `yaml:"username"`
	PasswordEnv string `yaml:"password_env"`
}

// Configured reports whether email can be sent.
func (s SMTPConfig) Configured() bool { return s.Host != "" && s.From != "" }

// AIConfig selects the LLM used by AI rules. The key itself is read from the
// environment variable named by APIKeyEnv and never stored in the repo.
type AIConfig struct {
	Provider  string `yaml:"provider"` // openai (also LiteLLM / OpenAI-compatible) | anthropic
	BaseURL   string `yaml:"base_url"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
}

type CVSSConfig struct {
	Version string `yaml:"version"`
	// Standard is the team's usual value per base metric; a finding value
	// differing from it is "non-standard" and needs a written reason.
	Standard map[string]string `yaml:"standard"`
}

// Simple reports whether the data folder runs the simple workflow.
func (c Config) Simple() bool { return c.Workflow == WorkflowSimple }

// NonStandard reports whether value differs from the configured standard
// for metric key. Metrics without a standard are never non-standard.
func (c Config) NonStandard(key, value string) bool {
	std, ok := c.CVSS.Standard[key]
	return ok && value != std
}

func defaultStandard() map[string]string {
	return map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
}

// RatingSeverities are the severity names CVSS ratings map to.
var RatingSeverities = []string{"critical", "high", "medium", "low", "info"}

func validate(c *Config) error {
	if w := c.Workflow; w != "" && w != WorkflowStandard && w != WorkflowSimple {
		return fmt.Errorf("config: workflow %q must be standard or simple", w)
	}
	var missing []string
	for _, r := range RatingSeverities {
		if !slices.Contains(c.Severities, r) {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: severities must include the CVSS ratings; missing %s", strings.Join(missing, ", "))
	}
	if c.CVSS.Version != "3.1" {
		return fmt.Errorf("config: cvss.version %q is not supported (only 3.1)", c.CVSS.Version)
	}
	if p := c.AI.Provider; p != "" && p != "openai" && p != "anthropic" {
		return fmt.Errorf("config: ai.provider %q must be openai or anthropic", p)
	}
	if b := c.AI.BaseURL; b != "" {
		u, err := url.Parse(b)
		local := err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
		if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && local)) {
			return fmt.Errorf("config: ai.base_url %q must use https (plain http only for localhost)", b)
		}
	}
	if b := c.BaseURL; b != "" {
		u, err := url.Parse(b)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("config: base_url %q must be an http(s) address", b)
		}
		c.BaseURL = strings.TrimRight(b, "/")
	}
	if c.SMTP.Port == 0 {
		c.SMTP.Port = 25
	}
	if n := c.Checks.MaxRunning; n < 1 {
		return fmt.Errorf("config: checks.max_running %d must be at least 1", n)
	}
	for k, v := range c.CVSS.Standard {
		if !cvss.Valid(k, v) {
			return fmt.Errorf("config: cvss.standard %s: invalid value %q", k, v)
		}
	}
	return nil
}

type User struct {
	Username     string `yaml:"username"`
	Email        string `yaml:"email,omitempty"`
	Role         string `yaml:"role"`
	PasswordHash string `yaml:"password_hash"`
	// IsAdmin opens the admin pages; it is separate from the role, which
	// keeps the workflow powers.
	IsAdmin bool `yaml:"is_admin,omitempty"`
	// Disabled accounts can't log in; their sessions and tokens stop working.
	Disabled bool `yaml:"disabled,omitempty"`
	// Theme is the account's chosen theme: "light", "dark" or "" (system).
	Theme string `yaml:"theme,omitempty"`
	// Created is when the account was added (RFC 3339; from the database).
	Created string `yaml:"-"`
	// MustChange: the password is a temporary one an admin gave (Add user,
	// Reset password); the user sets a new one before anything else.
	MustChange bool `yaml:"-"`
	// KeysOff: the account switched the keyboard shortcuts off (Settings ›
	// Preferences); Ctrl+S, Ctrl+Enter, Ctrl+K and Esc still work, as does
	// the Redact dialog's own Ctrl+Z.
	KeysOff bool `yaml:"-"`
}

// GitAuthor is the account's git identity.
func (u User) GitAuthor() gitrepo.Author {
	email := u.Email
	if email == "" {
		email = u.Username + "@yars.local"
	}
	return gitrepo.Author{Name: u.Username, Email: email}
}

// SameEmail reports whether two emails are one address: equal once ASCII
// letters are lowercased, as the database compares them (SQL lower()).
// Other characters must match exactly, so a look-alike such as the Kelvin
// sign never stands for a "k".
func SameEmail(a, b string) bool {
	return asciiLower(strings.TrimSpace(a)) == asciiLower(strings.TrimSpace(b))
}

func asciiLower(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}

// Roles in increasing power; each role can do everything the ones before it can.
var Roles = []string{"pentester", "reviewer", "director"}

func Default() Config {
	return Config{
		Severities:     []string{"critical", "high", "medium", "low", "info"},
		Sections:       []string{"Description", "Impact", "Steps to Reproduce", "Remediation", "References"},
		DetailsRows:    []string{"Location", "Cause", "Result", "Attack condition", "Business impact"},
		ReportSections: []string{"Executive summary", "Scope", "Methodology"},
		CVSS:           CVSSConfig{Version: "3.1", Standard: defaultStandard()},
		SMTP:           SMTPConfig{Port: 25},
		Checks:         ChecksConfig{MaxRunning: DefaultMaxRunning},
	}
}

func ConfigPath(dataDir string) string { return filepath.Join(dataDir, ".yars", "config.yaml") }
func UsersPath(dataDir string) string  { return filepath.Join(dataDir, ".yars", "users.yaml") }

func Load(dataDir string) (Config, error) {
	b, err := os.ReadFile(ConfigPath(dataDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Config{}, err
	}
	return Parse(b)
}

// Parse reads a config.yaml (nil or empty: all defaults) and validates it
// as Load does.
func Parse(b []byte) (Config, error) {
	// set before the YAML: only a max_running written there replaces it, so
	// an explicit 0 is refused rather than taken for unset
	c := Config{Checks: ChecksConfig{MaxRunning: DefaultMaxRunning}}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, err
	}
	d := Default()
	if len(c.Severities) == 0 {
		c.Severities = d.Severities
	}
	if len(c.Sections) == 0 {
		c.Sections = d.Sections
	}
	if len(c.DetailsRows) == 0 {
		c.DetailsRows = d.DetailsRows
	}
	if len(c.ReportSections) == 0 {
		c.ReportSections = d.ReportSections
	}
	if c.CVSS.Version == "" {
		c.CVSS.Version = d.CVSS.Version
	}
	std := d.CVSS.Standard
	for k, v := range c.CVSS.Standard {
		k, v = strings.ToUpper(k), strings.ToUpper(v)
		if v == "-" {
			delete(std, k)
		} else {
			std[k] = v
		}
	}
	c.CVSS.Standard = std
	return c, validate(&c)
}

func LoadUsers(dataDir string) ([]User, error) {
	b, err := os.ReadFile(UsersPath(dataDir))
	if errors.Is(err, fs.ErrNotExist) {
		return []User{}, nil
	}
	if err != nil {
		return nil, err
	}
	users := []User{}
	if err := yaml.Unmarshal(b, &users); err != nil {
		return nil, err
	}
	for _, u := range users {
		if !ValidRole(u.Role) {
			return nil, fmt.Errorf("%s: user %s has unknown role %q (roles: %s); edit the file and set one of them",
				UsersPath(dataDir), u.Username, u.Role, strings.Join(Roles, ", "))
		}
	}
	return users, nil
}

func SaveUsers(dataDir string, users []User) error {
	if err := os.MkdirAll(filepath.Dir(UsersPath(dataDir)), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(users)
	if err != nil {
		return err
	}
	return os.WriteFile(UsersPath(dataDir), b, 0o600)
}

func ValidRole(r string) bool {
	for _, x := range Roles {
		if x == r {
			return true
		}
	}
	return false
}
