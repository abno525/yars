package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/web"
)

// statusSocket is the socket yars status reads the running server on: a
// file in the data folder's .yars, the service account's alone (0600).
func statusSocket(dataDir string) string { return filepath.Join(dataDir, ".yars", "status.sock") }

// startStatus serves srv's status (web.Server.StatusHandler: one GET route,
// nothing else of the website) on the data folder's socket, and returns the
// function that stops it and removes the socket. Whoever can open the socket
// is the service's own account (or root): that is the proof, so there is no
// password and no route on the network. A socket left by a server that was
// killed is replaced. A socket another server answers on (a second yars
// serve on the same data folder) is left alone, at the start and at the
// stop: one warn line, and this server runs without yars status. A socket
// that cannot be made is one warn line too.
func startStatus(dataDir string, srv *web.Server, lg *slog.Logger) (stop func()) {
	path := statusSocket(dataDir)
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err == nil {
		c.Close()
	}
	// a server too busy to take the connection in time is still a server
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		logs.Or(lg).Warn("status: the status socket is in use by another server; this server runs without it")
		return func() {}
	}
	os.Remove(path) // a stale one: a listen on an existing file fails
	var mine os.FileInfo
	ln, err := net.Listen("unix", path)
	if err == nil {
		// the stop removes the path itself, and only while it is this socket
		ln.(*net.UnixListener).SetUnlinkOnClose(false)
		// set, not left to the umask: only the owner connects
		if err = os.Chmod(path, 0o600); err == nil {
			mine, err = os.Lstat(path)
		}
		if err != nil {
			ln.Close()
			os.Remove(path)
		}
	}
	if err != nil {
		logs.Or(lg).Warn("status: the socket of yars status is not opened; the server runs without it", "err", err)
		return func() {}
	}
	hs := &http.Server{Handler: srv.StatusHandler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(logs.StdHandler(lg, "status server"), slog.LevelWarn)}
	go hs.Serve(ln)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if hs.Shutdown(ctx) != nil {
			hs.Close()
		}
		// only the socket this server made: not one a later server put there
		if now, err := os.Lstat(path); err == nil && os.SameFile(mine, now) {
			os.Remove(path)
		}
	}
}

// cmdStatus prints what the running server does now, as plain text for a
// person:
//
//	yars status --data <dir>
//
// It asks the server over the data folder's socket (startStatus), so it
// runs as the account the server runs as, and takes no password. Without a
// server it says so and fails.
func cmdStatus(args []string, out io.Writer) error {
	f := flag.NewFlagSet("status", flag.ContinueOnError)
	data := dataFlag(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("usage: yars status --data <dir>")
	}
	dir, _, err := resolveData(f, *data)
	if err != nil {
		return err
	}
	st, err := readStatus(dir)
	if err != nil {
		return err
	}
	printStatus(out, st)
	return nil
}

// readStatus asks the server of dataDir for its status.
func readStatus(dataDir string) (web.Status, error) {
	path := statusSocket(dataDir)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		return web.Status{}, fmt.Errorf("no server is running on %s", dataDir)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}}
	resp, err := client.Get("http://yars/status")
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return web.Status{}, fmt.Errorf("the server on %s runs as another account: run yars status as that account", dataDir)
		}
		// no socket, or one a killed server left behind
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return web.Status{}, fmt.Errorf("no server is running on %s", dataDir)
		}
		return web.Status{}, fmt.Errorf("the server on %s does not answer", dataDir)
	}
	defer resp.Body.Close()
	var st web.Status
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&st) != nil {
		return web.Status{}, fmt.Errorf("the server on %s gave no status", dataDir)
	}
	return st, nil
}

// span shows milliseconds for a person: ms and s when short, then minutes,
// hours and days.
func span(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return strconv.FormatInt(max(ms, 1), 10) + " ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h %02d min", int(d/time.Hour), int(d%time.Hour/time.Minute))
	}
	return fmt.Sprintf("%d d %d h", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
}

// word is s as a terminal may show it: as it is when it is made of
// printing characters without a space, else quoted (a name can hold what a
// client typed).
func word(s string) string {
	for _, r := range s {
		if !unicode.IsPrint(r) || unicode.IsSpace(r) {
			return strconv.Quote(s)
		}
	}
	if s == "" {
		return `""`
	}
	return s
}

// printStatus writes st as plain text. Every value that is not a number is
// written through word, and a line of the log comes quoted from the server
// (the log's text form): nothing a client typed reaches the terminal raw.
func printStatus(out io.Writer, st web.Status) {
	schema, deliveries := "—", "—"
	if st.Schema > 0 {
		schema = strconv.Itoa(st.Schema)
	}
	if st.Deliveries >= 0 {
		deliveries = strconv.Itoa(st.Deliveries)
	}
	fmt.Fprintf(out, "yars %s · schema %s · up %s\n", word(st.Version), schema, span(st.UptimeMS))
	switch {
	case !st.DebugUntil.IsZero():
		fmt.Fprintf(out, "log level: debug until %s\n", st.DebugUntil.Local().Format("15:04"))
	case st.Level != "":
		fmt.Fprintf(out, "log level: %s\n", word(st.Level))
	}
	fmt.Fprintf(out, "checks: %d running, %d queued\n", st.ChecksRunning, st.ChecksQueued)
	fmt.Fprintf(out, "fixes: %d running\n", st.Fixes)
	fmt.Fprintf(out, "webhook deliveries: %s waiting\n", deliveries)
	fmt.Fprintf(out, "mails: %d being sent\n", st.Mails)
	streams := make([]string, 0, len(st.Streams))
	for _, s := range st.Streams {
		streams = append(streams, word(s.User)+" "+strconv.Itoa(s.Open))
	}
	fmt.Fprintf(out, "event streams: %s\n", orNone(streams))
	locks := make([]string, 0, len(st.Locks))
	for _, l := range st.Locks {
		name := "main"
		if l.Eng != "" {
			name = word(l.Eng)
		}
		held := "free"
		if l.HeldMS > 0 {
			held = "held " + span(l.HeldMS)
		}
		locks = append(locks, fmt.Sprintf("%s %s, %d waiting", name, held, l.Waiting))
	}
	fmt.Fprintf(out, "locks: %s\n", orNone(locks))
	fmt.Fprintf(out, "last warnings and errors: %d\n", len(st.Lines))
	for _, l := range st.Lines {
		fmt.Fprintf(out, "%s %-5s %s\n", l.Time.Local().Format("2006-01-02 15:04:05"), word(l.Level), safeLine(l.Text))
	}
}

// orNone joins items with "; ", or says none.
func orNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, "; ")
}

// safeLine is a log line for the terminal. The server sends it in the log's
// text form, which quotes what does not print; a character that still does
// not print (a server that is not this version) is written as its escape.
func safeLine(s string) string {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			q := strconv.Quote(s)
			return q[1 : len(q)-1]
		}
	}
	return s
}
