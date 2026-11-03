// Package config loads .yars/config.yaml and .yars/users.yaml from a data repo.
package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Severities []string `yaml:"severities"`
	Sections   []string `yaml:"sections"`
}

type User struct {
	Username     string `yaml:"username"`
	Email        string `yaml:"email,omitempty"`
	Role         string `yaml:"role"`
	PasswordHash string `yaml:"password_hash"`
}

var Roles = []string{"pentester", "reviewer", "director", "admin"}

func Default() Config {
	return Config{
		Severities: []string{"critical", "high", "medium", "low", "info"},
		Sections:   []string{"Description", "Location", "Impact", "Steps to Reproduce", "Remediation", "References"},
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
	return c, nil
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
