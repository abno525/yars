package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
)

// dataEnv names the data folder when --data is not given.
const dataEnv = "YARS_DATA"

// dataFlag adds --data to a command that works on the server's data
// folder; resolveData then fills in the default.
func dataFlag(f *flag.FlagSet) *string {
	return f.String("data", "", "data folder (default: "+dataEnv+", then yars use, then .)")
}

// userConfigPath is yars' own settings file: $XDG_CONFIG_HOME/yars/
// config.yaml, or ~/.config/yars/config.yaml (a relative XDG_CONFIG_HOME
// is ignored, as the XDG spec says).
func userConfigPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "yars", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "yars", "config.yaml"), nil
}

type userConfig struct {
	Data string `yaml:"data"`
}

// resolveData is the data folder a command works on, and where it came
// from: the --data flag when given (even "."), else YARS_DATA, else data:
// in the user's config file (yars use), else ".".
func resolveData(f *flag.FlagSet, v string) (string, string, error) {
	set := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == "data" {
			set = true
		}
	})
	if set {
		return v, "--data", nil
	}
	if e := os.Getenv(dataEnv); e != "" {
		return e, dataEnv, nil
	}
	p, err := userConfigPath()
	if err != nil {
		return ".", "default", nil
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ".", "default", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", p, err)
	}
	var c userConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return "", "", fmt.Errorf("%s: %w", p, err)
	}
	switch {
	case c.Data == "":
		return ".", "default", nil
	case !filepath.IsAbs(c.Data):
		return "", "", fmt.Errorf("%s: data must be an absolute path (set it with yars use <dir>)", p)
	}
	return c.Data, p, nil
}

// openData resolves the data folder and opens its main repository.
func openData(f *flag.FlagSet, v string) (*gitrepo.Repo, error) {
	dir, _, err := resolveData(f, v)
	if err != nil {
		return nil, err
	}
	return gitrepo.Open(dir)
}

// cmdUse sets the default data folder (yars use <dir>), or shows it and
// where it comes from (yars use).
func cmdUse(args []string, out io.Writer) error {
	switch len(args) {
	case 0:
		f := flag.NewFlagSet("use", flag.ContinueOnError)
		dir, src, err := resolveData(f, "")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%s (from %s)\n", dir, src)
		return nil
	case 1:
	default:
		return fmt.Errorf("usage: yars use [<dir>]")
	}
	dir, err := filepath.Abs(args[0])
	if err != nil {
		return err
	}
	if _, err := gitrepo.Open(dir); err != nil {
		return fmt.Errorf("%s is not a YARS data folder (run yars init first)", dir)
	}
	if _, err := os.Stat(config.ConfigPath(dir)); err != nil {
		return fmt.Errorf("%s is not a YARS data folder (no .yars/config.yaml)", dir)
	}
	p, err := userConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := yaml.Marshal(userConfig{Data: dir})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(out, "default data folder: %s (in %s)\n", dir, p)
	// the folder the next command uses, as it resolves it
	now, src, err := resolveData(flag.NewFlagSet("use", flag.ContinueOnError), "")
	if abs, aerr := filepath.Abs(now); err == nil && aerr == nil && src == dataEnv && abs != dir {
		fmt.Fprintf(out, "%s=%s overrides it: commands use %s\n", dataEnv, now, abs)
	}
	return nil
}

// knownUser fails for a name with no account, or with the database's own
// error (not blamed on the name).
func knownUser(d *db.DB, name string) error {
	_, ok, err := d.User(name)
	switch {
	case err != nil:
		return err
	case !ok:
		return fmt.Errorf("no user %s", name)
	}
	return nil
}

// cmdUnlock ends a user's login lockout: yars unlock --data <dir> <user>.
func cmdUnlock(args []string, out io.Writer) error {
	f, d, err := accountCmd("unlock", args, 1, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	name := f.Arg(0)
	if err := knownUser(d, name); err != nil {
		return err
	}
	if err := d.ClearLockout(name); err != nil {
		return err
	}
	d.Audit("cli", "login.unlock", name, "")
	fmt.Fprintln(out, "unlocked", name)
	return nil
}
