// Command nyyrikki is the CLI agents use to reach Nyyrikki (docs/02 D12,
// §5.5). It is an MCP client of /mcp and nothing more: it holds no target
// credential and can't approve, deny or end anything.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/client"
	"github.com/Tuhis/Nyyrikki/internal/client/attach"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

var version = "dev"

// Exit codes (docs/02 §5.5).
const (
	exitUsage       = 64
	exitNotSignedIn = 67
	exitUnavailable = 69
	exitNoAnswer    = 75
	exitDenied      = 77
)

const usage = `usage:
  nyyrikki login [--server URL] [--client-id ID] [--ca-file PEM] [--mcp] [--force]
  nyyrikki logout [--mcp]
  nyyrikki targets
  nyyrikki run [--reason TEXT] [--elevation HANDLE] [--timeout D] [-i] [-t] TARGET -- KUBECTL-ARGS...
  nyyrikki run [--reason TEXT] [--elevation HANDLE] [--timeout D] [-i] [-t] SSH-TARGET [-- COMMAND...]
  nyyrikki run [--reason TEXT] [--elevation HANDLE] [--timeout D] -i SOPS-TARGET -- SOPS-ARGS... < FILE

  Use nyyrikki only for what your own access can't do: every request waits for
  a human. With read-only Kubernetes access, for example, run kubectl get,
  describe and logs yourself, and nyyrikki run only for apply, delete, exec...
  On an SSH target, stdin is sent only with -i, and the approver sees only its
  size and hash: put a script the approver must read in the command (a heredoc).
  -t with no command opens a login shell.
  On a sops target, stdin (with -i) is the file and stdout the result:
  decrypt [--extract PATH] [--output-type T], set PATH VALUE, unset PATH or
  encrypt --gcp-kms KEY, each with --input-type yaml|json|dotenv and
  --filename-override NAME, the file's path, shown to the approver as your claim.
  ssh is run on an SSH target only: with no command on a terminal it is
  run -t SSH-TARGET (a login shell), otherwise run SSH-TARGET -- COMMAND...
  elevate takes group names from targets too, and covers their members.
  nyyrikki ssh [--reason TEXT] [--elevation HANDLE] [--timeout D] [-i] SSH-TARGET [-- COMMAND...]
  nyyrikki elevate --reason TEXT [--for D] TARGET-OR-GROUP...
  nyyrikki mcp-headers
  nyyrikki version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr}
	switch args[0] {
	case "login":
		return c.login(ctx, args[1:])
	case "logout":
		return c.logout(args[1:])
	case "targets":
		return c.targets(ctx, args[1:])
	case "run":
		return c.run(ctx, args[1:])
	case "ssh":
		return c.ssh(ctx, args[1:])
	case "elevate":
		return c.elevate(ctx, args[1:])
	case "mcp-headers":
		return c.mcpHeaders(ctx, args[1:])
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprint(stderr, usage)
	return exitUsage
}

type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	// typeOf replaces the list_targets lookup of ssh (tests); nil means
	// asking the server.
	typeOf func(ctx context.Context, path, target string) (string, error)
	// runCmd replaces c.run for ssh (tests); nil means c.run.
	runCmd func(ctx context.Context, args []string) int
}

// fail prints Nyyrikki's own outcome as the last stderr line,
// "nyyrikki: error: <code>: <message>" (docs/02 §5.5), and maps it to an
// exit code.
func (c *cli) fail(err error) int {
	code, exit := codes.Unavailable, exitUnavailable
	var te *client.ToolError
	var ce *codes.Error // from /stream (internal/client/attach)
	switch {
	case errors.Is(err, client.ErrNotSignedIn):
		code, exit = codes.Unauthenticated, exitNotSignedIn
	case errors.As(err, &ce):
		te = &client.ToolError{Code: ce.Code}
		fallthrough
	case errors.As(err, &te):
		code = te.Code
		switch te.Code {
		case codes.InvalidRequest:
			exit = exitUsage
		case codes.Unauthenticated:
			exit = exitNotSignedIn
		case codes.Expired, codes.Withdrawn:
			exit = exitNoAnswer
		case codes.Denied, codes.TargetNotAllowed, codes.HandleUnknown, codes.SessionInactive, codes.IntrospectionFailed:
			exit = exitDenied
		}
	case strings.Contains(err.Error(), "401"):
		code, exit = codes.Unauthenticated, exitNotSignedIn
	}
	msg := strings.TrimPrefix(err.Error(), string(code)+": ")
	fmt.Fprintf(c.stderr, "nyyrikki: error: %s: %s\n", code, msg)
	return exit
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

func loginPath(fs *flag.FlagSet, mcp bool) *string {
	def, _ := client.DefaultPath(mcp)
	return fs.String("login-file", def, "login file (env NYYRIKKI_LOGIN_FILE)")
}

func (c *cli) login(ctx context.Context, args []string) int {
	fs := c.flags("login")
	server := fs.String("server", os.Getenv("NYYRIKKI_SERVER"), "Nyyrikki's URL (env NYYRIKKI_SERVER)")
	clientID := fs.String("client-id", "", "the CLI's OAuth client (default: from the server's metadata)")
	caFile := fs.String("ca-file", "", "PEM file of extra CA certificates to trust")
	mcp := fs.Bool("mcp", false, "sign in for `nyyrikki mcp-headers` (an MCP harness's headersHelper)")
	force := fs.Bool("force", false, "replace an existing login")
	pathFlag := fs.String("login-file", "", "login file (env NYYRIKKI_LOGIN_FILE)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *server == "" {
		fmt.Fprintln(c.stderr, "usage: nyyrikki login --server URL [--client-id ID] [--ca-file PEM] [--mcp] [--force]")
		return exitUsage
	}
	path := *pathFlag
	if path == "" {
		var err error
		if path, err = client.DefaultPath(*mcp); err != nil {
			return c.fail(err)
		}
	}
	host, _ := os.Hostname()
	l, err := client.SignIn(ctx, client.LoginOptions{
		Server: *server, ClientID: *clientID, CAFile: *caFile, MCP: *mcp, Path: path, Force: *force,
		ClientName: "nyyrikki mcp-headers on " + host,
		Prompt: func(uri, code, complete string) {
			fmt.Fprintf(c.stderr, "nyyrikki: to sign in, open %s and enter the code %s\n", uri, code)
			if complete != "" {
				fmt.Fprintf(c.stderr, "nyyrikki: or open %s\n", complete)
			}
		},
		Notice: func(m string) { fmt.Fprintln(c.stderr, "nyyrikki: "+m) },
	})
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stderr, "nyyrikki: signed in to %s as client %s; login saved in %s\n", l.Server, l.ClientID, path)
	return 0
}

func (c *cli) logout(args []string) int {
	fs := c.flags("logout")
	mcp := fs.Bool("mcp", false, "remove the mcp-headers login")
	pathFlag := fs.String("login-file", "", "login file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	path := *pathFlag
	if path == "" {
		path, _ = client.DefaultPath(*mcp)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "nyyrikki: login removed; end the session in the authorization server's account console to revoke it at once")
	return 0
}

func (c *cli) session(ctx context.Context, path string) (*client.Login, *client.Session, error) {
	l, err := client.LoadLogin(path)
	if err != nil {
		return nil, nil, err
	}
	if l.MCP {
		return nil, nil, errors.New("this is an --mcp login, for mcp-headers only; run `nyyrikki login` for the CLI")
	}
	s, err := client.Connect(ctx, l, version, func(msg string) {
		fmt.Fprintf(c.stderr, "nyyrikki: %s\n", msg)
	})
	if err != nil {
		return nil, nil, err
	}
	return l, s, nil
}

func (c *cli) targets(ctx context.Context, args []string) int {
	fs := c.flags("targets")
	path := loginPath(fs, false)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	_, s, err := c.session(ctx, *path)
	if err != nil {
		return c.fail(err)
	}
	defer s.Close()
	var out api.ListTargetsOut
	if err := s.Call(ctx, api.ToolListTargets, api.ListTargetsIn{}, &out); err != nil {
		return c.fail(err)
	}
	printTargets(c.stdout, out.Targets)
	return 0
}

// printTargets writes one line per target: name, type, sudo (yes or no
// on an SSH target, - otherwise), its groups (comma-separated, or -),
// and the description last, since it is free text (docs/08 D11).
func printTargets(w io.Writer, targets []api.TargetInfo) {
	for _, t := range targets {
		sudo, groups := "-", "-"
		if t.Sudo != nil {
			sudo = "no"
			if *t.Sudo {
				sudo = "yes"
			}
		}
		if len(t.Groups) > 0 {
			groups = strings.Join(t.Groups, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.Name, t.Type, sudo, groups, t.Description)
	}
}

// ssh is sugar over run for SSH targets (docs/08 D12): with no command
// and a terminal on stdin it is exactly `run -t TARGET`, a login shell;
// otherwise `run TARGET -- COMMAND...`. It refuses a target that
// list_targets doesn't list as an SSH target before calling run, so a
// command meant for a host is never sent to a Kubernetes target as
// kubectl arguments. The server decides as for any run.
func (c *cli) ssh(ctx context.Context, args []string) int {
	fs := c.flags("ssh")
	reason := fs.String("reason", "", "why; shown to the approver as the agent's claim")
	elevation := fs.String("elevation", os.Getenv("NYYRIKKI_ELEVATION"), "elevation handle (env NYYRIKKI_ELEVATION)")
	timeout := fs.String("timeout", "", "how long the command may run (Go duration)")
	stdinFlag := fs.Bool("i", false, "send stdin to the command")
	path := loginPath(fs, false)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	runArgs, err := sshRunArgs(fs.Args(), c.stdinIsTerminal())
	if err != nil {
		fmt.Fprintf(c.stderr, "nyyrikki: %v\nusage: nyyrikki ssh [flags] SSH-TARGET [-- COMMAND...]\n", err)
		return exitUsage
	}
	if *reason == "" {
		fmt.Fprintln(c.stderr, "nyyrikki: --reason is required: the approver sees it")
		return exitUsage
	}
	target := fs.Arg(0)
	typeOf := c.typeOf
	if typeOf == nil {
		typeOf = c.lookupType
	}
	typ, err := typeOf(ctx, *path, target)
	if err != nil {
		return c.fail(err)
	}
	if typ != codes.TypeSSH {
		// Unlisted reads as not SSH: the CLI can't tell "absent" from
		// "not yours", and doesn't try (docs/02 D5).
		fmt.Fprintf(c.stderr, "nyyrikki: %s is not an SSH target this agent may use (see nyyrikki targets)\n", target)
		return exitUsage
	}
	flags := []string{"--login-file", *path}
	if *reason != "" {
		flags = append(flags, "--reason", *reason)
	}
	if *elevation != "" {
		flags = append(flags, "--elevation", *elevation)
	}
	if *timeout != "" {
		flags = append(flags, "--timeout", *timeout)
	}
	if *stdinFlag && runArgs[0] != "-t" {
		flags = append(flags, "-i")
	}
	run := c.runCmd
	if run == nil {
		run = c.run
	}
	return run(ctx, append(flags, runArgs...))
}

// sshRunArgs maps ssh's arguments, TARGET [-- COMMAND...], to run's
// positional arguments (docs/08 D12).
func sshRunArgs(rest []string, terminal bool) ([]string, error) {
	switch {
	case len(rest) == 0:
		return nil, errors.New("no target")
	case len(rest) == 1 && terminal:
		return []string{"-t", rest[0]}, nil
	case len(rest) == 1:
		return nil, errors.New("no command, and stdin is not a terminal for a login shell")
	case rest[1] != "--":
		return nil, errors.New("put the command after --")
	case len(rest) == 2:
		return nil, errors.New("no command after --")
	}
	return append([]string{rest[0], "--"}, rest[2:]...), nil
}

func (c *cli) stdinIsTerminal() bool {
	f, ok := c.stdin.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// lookupType asks list_targets for target's type over its own session.
func (c *cli) lookupType(ctx context.Context, path, target string) (string, error) {
	_, s, err := c.session(ctx, path)
	if err != nil {
		return "", err
	}
	defer s.Close()
	return c.targetType(ctx, s, target)
}

// readsStdin reports whether kubectl args take a manifest from stdin. The
// server decides for real (docs/04 D2); this only saves sending input that
// would be refused.
func readsStdin(args []string) bool {
	for i, a := range args {
		if a == "--" {
			return false
		}
		switch {
		case a == "-f-", a == "-f=-", a == "--filename=-":
			return true
		case (a == "-f" || a == "--filename") && i+1 < len(args) && args[i+1] == "-":
			return true
		}
	}
	return false
}

func (c *cli) run(ctx context.Context, args []string) int {
	fs := c.flags("run")
	reason := fs.String("reason", "", "why; shown to the approver as the agent's claim")
	elevation := fs.String("elevation", os.Getenv("NYYRIKKI_ELEVATION"), "elevation handle (env NYYRIKKI_ELEVATION)")
	timeout := fs.String("timeout", "", "how long the command may run (Go duration)")
	stdinFlag := fs.Bool("i", false, "send stdin to the command (exec/attach -i; on SSH targets, the only way stdin is sent)")
	tty := fs.Bool("t", false, "interactive terminal (exec/attach -it; on SSH targets, a session, or a login shell without a command)")
	path := loginPath(fs, false)
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	rest := fs.Args()
	// TARGET alone is an SSH login shell (-t); the server refuses it for
	// any other target (docs/07 §5.4).
	loginShell := len(rest) == 1 && *tty
	if !loginShell && (len(rest) < 3 || rest[1] != "--") {
		fmt.Fprintln(c.stderr, "usage: nyyrikki run [flags] TARGET -- ARGS...   (or: nyyrikki run -t SSH-TARGET)")
		return exitUsage
	}
	if *reason == "" {
		fmt.Fprintln(c.stderr, "nyyrikki: --reason is required: the approver sees it")
		return exitUsage
	}
	in := api.RunIn{Target: rest[0], Reason: *reason, Elevation: *elevation, Timeout: *timeout}
	if !loginShell {
		in.Args = rest[2:]
	}

	stdinFile, isFile := c.stdin.(*os.File)
	interactive := *tty && isFile && term.IsTerminal(int(stdinFile.Fd()))
	if *tty && !interactive {
		fmt.Fprintln(c.stderr, "nyyrikki: -t needs a terminal on stdin")
		return exitUsage
	}
	in.Interactive = interactive

	l, s, err := c.session(ctx, *path)
	if err != nil {
		return c.fail(err)
	}
	defer s.Close()
	// kubectl's -f - reads a manifest from stdin; on an SSH target the
	// same letters are part of a shell command, and stdin goes only with
	// -i, like ssh -n otherwise (docs/07 §5.4).
	sendStdin := *stdinFlag
	if !interactive && !sendStdin && readsStdin(in.Args) {
		typ, err := c.targetType(ctx, s, in.Target)
		if err != nil {
			return c.fail(err)
		}
		sendStdin = typ != codes.TypeSSH
	}
	if !interactive && sendStdin {
		b, err := io.ReadAll(io.LimitReader(c.stdin, 1<<20+1))
		if err != nil {
			return c.fail(err)
		}
		if len(b) > 1<<20 {
			fmt.Fprintln(c.stderr, "nyyrikki: stdin is limited to 1 MiB")
			return exitUsage
		}
		in.Stdin = string(b)
	}
	fmt.Fprintln(c.stderr, "nyyrikki: waiting for the approver…")
	var out api.RunOut
	if err := s.Call(ctx, api.ToolRun, in, &out); err != nil {
		// A cut run still has what it printed so far (docs/04 D7).
		c.printOutput(out)
		return c.fail(err)
	}
	if interactive {
		if out.StreamTicket == "" {
			return c.fail(errors.New("the server returned no stream ticket"))
		}
		h, err := l.Header(ctx, "GET", l.StreamURL, time.Now)
		if err != nil {
			return c.fail(err)
		}
		// The login's client: its CA file, no proxy from the environment,
		// no redirects (as for /mcp).
		hc, err := client.HTTPClient(l.CAFile)
		if err != nil {
			return c.fail(err)
		}
		code, err := attach.AttachTerminal(ctx, hc, l.StreamURL, out.StreamTicket, h, stdinFile, c.stdout)
		if err != nil {
			return c.fail(err)
		}
		return code
	}
	c.printOutput(out)
	if out.ExitCode == nil {
		return c.fail(errors.New("the server returned no exit code"))
	}
	return *out.ExitCode
}

// targetType asks list_targets for a target's type; "" when it isn't
// listed (the run is then refused by the server).
func (c *cli) targetType(ctx context.Context, s *client.Session, name string) (string, error) {
	var out api.ListTargetsOut
	if err := s.Call(ctx, api.ToolListTargets, api.ListTargetsIn{}, &out); err != nil {
		return "", err
	}
	for _, t := range out.Targets {
		if t.Name == name {
			return t.Type, nil
		}
	}
	return "", nil
}

// printOutput writes a run's output: stdout to stdout (base64 when it
// isn't text), stderr to stderr, and a note when it was truncated.
func (c *cli) printOutput(out api.RunOut) {
	if out.StdoutBase64 != "" {
		fmt.Fprintln(c.stderr, "nyyrikki: binary output, base64-encoded")
		io.WriteString(c.stdout, out.StdoutBase64+"\n")
	} else {
		io.WriteString(c.stdout, out.Stdout)
	}
	io.WriteString(c.stderr, out.Stderr)
	if out.StdoutTruncated || out.StderrTruncated {
		fmt.Fprintln(c.stderr, "nyyrikki: output truncated")
	}
	if out.Detail != "" {
		fmt.Fprintf(c.stderr, "nyyrikki: %s\n", out.Detail)
	}
}

func (c *cli) elevate(ctx context.Context, args []string) int {
	fs := c.flags("elevate")
	reason := fs.String("reason", "", "why; shown to the approver as the agent's claim")
	dur := fs.String("for", "", "duration (Go syntax; default 15m, at most 30m)")
	path := loginPath(fs, false)
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 || *reason == "" {
		fmt.Fprintln(c.stderr, "usage: nyyrikki elevate --reason TEXT [--for D] TARGET-OR-GROUP...")
		return exitUsage
	}
	_, s, err := c.session(ctx, *path)
	if err != nil {
		return c.fail(err)
	}
	defer s.Close()
	fmt.Fprintln(c.stderr, "nyyrikki: waiting for the approver…")
	var out api.ElevateOut
	if err := s.Call(ctx, api.ToolElevate, api.ElevateIn{Targets: fs.Args(), Duration: *dur, Reason: *reason}, &out); err != nil {
		return c.fail(err)
	}
	// The handle alone on stdout, for $(…); it is a secret (docs/01 D24).
	fmt.Fprintln(c.stdout, out.Handle)
	fmt.Fprintf(c.stderr, "nyyrikki: elevation %s on %s live until %s\n", out.ElevationID, strings.Join(out.Targets, ", "), out.ExpiresAt)
	return 0
}

// mcpHeaders prints the headers an MCP harness's headersHelper needs
// (docs/01 D25). It fails closed: on any problem it prints nothing and
// exits non-zero.
func (c *cli) mcpHeaders(ctx context.Context, args []string) int {
	fs := c.flags("mcp-headers")
	path := loginPath(fs, true)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	l, err := client.LoadLogin(*path)
	if err != nil {
		return c.fail(err)
	}
	if !l.MCP {
		return c.fail(errors.New("not an --mcp login"))
	}
	// A .mcp.json pointing elsewhere gets no token.
	if u := os.Getenv("CLAUDE_CODE_MCP_SERVER_URL"); u != "" && strings.TrimSuffix(u, "/") != l.MCPURL {
		return c.fail(fmt.Errorf("refusing: the harness asks for %q, but this login is for %s", u, l.MCPURL))
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second) // Claude Code gives up after 10 s
	defer cancel()
	tok, err := l.Fresh(ctx, time.Now)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "{\"Authorization\": %q}\n", "Bearer "+tok)
	return 0
}
