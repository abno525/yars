// Command yars: git-backed pentest findings tracker.
//
//	yars init <dir>
//	yars useradd --data <dir> --role <role> [--email e] <username>   (password read from stdin)
//	yars serve --data <dir> [--addr :8080]
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/web"
)

var system = gitrepo.Author{Name: "yars", Email: "yars@yars.local"}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: yars init <dir> | useradd --data <dir> --role <role> <username> | serve --data <dir> [--addr :8080]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "useradd":
		err = cmdUseradd(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yars:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	if len(args) != 1 {
		usage()
	}
	dir := args[0]
	r, err := gitrepo.Init(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(config.ConfigPath(dir)); err == nil {
		return fmt.Errorf("%s is already initialised", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, "engagements"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(config.ConfigPath(dir)), 0o755); err != nil {
		return err
	}
	b, _ := yaml.Marshal(config.Default())
	files := map[string][]byte{
		config.ConfigPath(dir):                        b,
		config.UsersPath(dir):                         []byte("[]\n"),
		filepath.Join(dir, "engagements", ".gitkeep"): nil,
	}
	for p, c := range files {
		if err := os.WriteFile(p, c, 0o644); err != nil {
			return err
		}
	}
	if err := r.Commit([]string{".yars", "engagements"}, "init", system); err != nil {
		return err
	}
	fmt.Println("initialised", dir)
	return nil
}

func cmdUseradd(args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	data := fs.String("data", ".", "data repo")
	role := fs.String("role", "pentester", "pentester|reviewer|director|admin")
	email := fs.String("email", "", "email for git authorship")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	name := fs.Arg(0)
	if !config.ValidRole(*role) {
		fmt.Fprintf(os.Stderr, "yars: invalid role %q (want %s)\n", *role, strings.Join(config.Roles, ", "))
		os.Exit(2)
	}
	if !store.ValidID(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Username == name {
			return fmt.Errorf("user %s already exists", name)
		}
	}
	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return fmt.Errorf("empty password (%v)", err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	users = append(users, config.User{Username: name, Email: *email, Role: *role, PasswordHash: hash})
	if err := config.SaveUsers(r.Dir, users); err != nil {
		return err
	}
	if err := r.Commit([]string{".yars/users.yaml"}, "user "+name+": add", system); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\nadded", name, "as", *role)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", ".", "data repo")
	addr := fs.String("addr", ":8080", "listen address")
	fs.Parse(args)
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return err
	}
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		log.Println("warning: no users; add one with: yars useradd --data", *data, "--role director <name>")
	}
	st := store.New(r, cfg)
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	st.Linter = eng
	srv := &web.Server{Store: st, Index: index.New(st, r), Auth: auth.New(users), Cfg: cfg, Rules: eng}
	log.Printf("yars serving %s on %s", r.Dir, *addr)
	return http.ListenAndServe(*addr, srv.Handler())
}
