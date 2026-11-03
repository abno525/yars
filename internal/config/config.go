// Package config loads .yars/config.yaml and .yars/users.yaml from a data repo.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"yars/internal/cvss"
	"yars/internal/gitrepo"
)

type Config struct {
	Severities  []string   `yaml:"severities"`
	Sections    []string   `yaml:"sections"`
	DetailsRows []string   `yaml:"details_rows"`
	CVSS        CVSSConfig `yaml:"cvss"`
	AI          AIConfig   `yaml:"ai"`
}

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
}

// GitAuthor is the account's git identity.
func (u User) GitAuthor() gitrepo.Author {
	email := u.Email
	if email == "" {
		email = u.Username + "@yars.local"
	}
	return gitrepo.Author{Name: u.Username, Email: email}
}

var Roles = []string{"pentester", "reviewer", "director", "admin"}

func Default() Config {
	return Config{
		Severities:  []string{"critical", "high", "medium", "low", "info"},
		Sections:    []string{"Description", "Impact", "Steps to Reproduce", "Remediation", "References"},
		DetailsRows: []string{"Location", "Business impact", "Row 3", "Row 4", "Row 5"},
		CVSS:        CVSSConfig{Version: "3.1", Standard: defaultStandard()},
	}
}

func ConfigPath(dataDir string) string { return filepath.Join(dataDir, ".yars", "config.yaml") }
func UsersPath(dataDir string) string  { return filepath.Join(dataDir, ".yars", "users.yaml") }

func Load(dataDir string) (Config, error) {
	c := Config{}
	b, err := os.ReadFile(ConfigPath(dataDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return c, err
	}
	if err == nil {
		if err := yaml.Unmarshal(b, &c); err != nil {
			return c, err
		}
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
