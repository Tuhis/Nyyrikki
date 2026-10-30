// Package request parses a kubectl command line into its canonical form
// (docs/04 D2, D3): the one value the approver sees, the approval binds to
// and the runner executes.
//
// The parse uses kubectl's own command tree from k8s.io/kubectl, the same
// code the runner executes in its child process, so there is no parser
// difference between what Nyyrikki checks and what kubectl does.
package request

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	kcmd "k8s.io/kubectl/pkg/cmd"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// Detail values of the refusals Parse returns (codes.Error.Detail).
const (
	DetailEmpty                 = "empty_args"
	DetailParse                 = "parse_error"
	DetailCommandNotAllowed     = "command_not_allowed"
	DetailFlagDenied            = "flag_denied"
	DetailCanonicalMismatch     = "canonical_mismatch"
	DetailStdinNotRead          = "stdin_not_read"
	DetailInteractiveNotAllowed = "interactive_not_allowed"
	DetailInteractiveStdin      = "interactive_with_stdin"
)

// Canonical is a parsed, checked kubectl request (docs/04 D2). It is
// immutable once Parse returns it.
type Canonical struct {
	path        []string // command path below the root, e.g. ["rollout", "restart"]
	flags       []flagValue
	positionals []string
	dash        int // number of positionals before "--", or -1 when there was none
	stdin       []byte
	interactive bool
	argv        []string
}

type flagValue struct {
	name   string
	values []string // one element for scalar flags, one per element for slices
}

// treeMu serialises building and using kubectl's command tree:
// NewKubectlCommand writes package-level state (the completion factory),
// so two concurrent builds race.
var treeMu sync.Mutex

// Parse parses args (the kubectl arguments without the leading "kubectl")
// and stdin into a Canonical. interactive asks for a terminal session
// (docs/04 D12). Every refusal is a *codes.Error with codes.InvalidRequest
// and a Detail; nothing is ever passed through a shell (docs/04 D1).
func Parse(args []string, stdin []byte, interactive bool) (c *Canonical, err error) {
	if len(args) == 0 {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailEmpty, "no kubectl arguments")
	}
	// kubectl's flag values run their own Set methods on agent input.
	// Nothing they do may take the server down or turn into an allow.
	defer func() {
		if r := recover(); r != nil {
			c, err = nil, codes.WithDetail(codes.InvalidRequest, DetailParse, "the kubectl arguments could not be parsed")
		}
	}()

	first, err := parseArgs(args)
	if err != nil {
		return nil, err
	}
	if err := first.check(); err != nil {
		return nil, err
	}
	first.argv = first.render()

	// docs/04 D3: the rendered argv must parse back to exactly the same
	// request, or the renderer couldn't express it faithfully.
	second, err := parseArgs(first.argv)
	if err != nil {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailCanonicalMismatch, "the request has no faithful canonical form")
	}
	if !slices.Equal(second.render(), first.argv) {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailCanonicalMismatch, "the request has no faithful canonical form")
	}

	first.stdin = bytes.Clone(stdin)
	first.interactive = interactive
	if err := first.checkStdin(); err != nil {
		return nil, err
	}
	return first, nil
}

// parseArgs resolves the command and its flags with kubectl's own
// definitions (docs/04 D2, M1).
func parseArgs(args []string) (*Canonical, error) {
	treeMu.Lock()
	defer treeMu.Unlock()

	root := newTree()
	cmd, rest, err := root.Find(args)
	if err != nil || cmd == nil {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailParse, "unknown kubectl command")
	}
	if err := cmd.ParseFlags(rest); err != nil {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailParse, "invalid kubectl flags: %s", sanitize(err.Error()))
	}

	c := &Canonical{dash: cmd.ArgsLenAtDash()}
	for p := cmd; p != nil && p.HasParent(); p = p.Parent() {
		c.path = append([]string{p.Name()}, c.path...)
	}
	cmd.Flags().Visit(func(f *pflag.Flag) {
		fv := flagValue{name: f.Name}
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			fv.values = slices.Clone(sv.GetSlice())
			if len(fv.values) == 0 {
				fv.values = []string{""}
			}
		} else {
			fv.values = []string{f.Value.String()}
		}
		c.flags = append(c.flags, fv)
	})
	sort.Slice(c.flags, func(i, j int) bool { return c.flags[i].name < c.flags[j].name })
	c.positionals = slices.Clone(cmd.Flags().Args())
	if c.dash > len(c.positionals) {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailParse, "invalid use of --")
	}
	if !cmd.Runnable() {
		return nil, codes.WithDetail(codes.InvalidRequest, DetailCommandNotAllowed, "kubectl %s is not offered", c.Command())
	}
	return c, nil
}

// newTree builds kubectl's command tree. With no Arguments, kubectl
// doesn't read a kuberc file (kuberc.Preferences.Apply returns early), and
// with no PluginHandler it dispatches no plugins (docs/04 M2). The only
// outside state it reads is $PATH, to list plugins for help text; those
// are not added to the tree. Output goes nowhere: deprecation warnings
// about agent input don't belong on the server's stderr.
func newTree() *cobra.Command {
	streams := genericiooptions.IOStreams{In: bytes.NewReader(nil), Out: io.Discard, ErrOut: io.Discard}
	root := kcmd.NewKubectlCommand(kcmd.KubectlOptions{IOStreams: streams})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetIn(bytes.NewReader(nil))
	return root
}

// render produces the canonical argv (docs/04 D3): the command path,
// every set flag as --name=value sorted by name (one per slice element),
// the positionals before "--", then "--" and the rest when it was present.
func (c *Canonical) render() []string {
	argv := slices.Clone(c.path)
	for _, f := range c.flags {
		for _, v := range f.values {
			argv = append(argv, "--"+f.name+"="+v)
		}
	}
	if c.dash < 0 {
		return append(argv, c.positionals...)
	}
	argv = append(argv, c.positionals[:c.dash]...)
	argv = append(argv, "--")
	return append(argv, c.positionals[c.dash:]...)
}

func (c *Canonical) flag(name string) ([]string, bool) {
	for _, f := range c.flags {
		if f.name == name {
			return f.values, true
		}
	}
	return nil, false
}

func (c *Canonical) boolFlag(name string) bool {
	v, ok := c.flag(name)
	return ok && len(v) == 1 && v[0] == "true"
}

// check applies the command allowlist and the flag deny list (docs/04 D4,
// D5, §5.4), on the resolved command path and long flag names.
func (c *Canonical) check() error {
	if !commandAllowed(c.path) {
		return codes.WithDetail(codes.InvalidRequest, DetailCommandNotAllowed, "kubectl %s is not offered", c.Command())
	}
	for _, f := range c.flags {
		if reason := flagDenied(f); reason != "" {
			return codes.WithDetail(codes.InvalidRequest, DetailFlagDenied, "flag --%s is not allowed: %s", f.name, reason)
		}
	}
	return nil
}

func (c *Canonical) checkStdin() error {
	if c.interactive {
		// docs/04 D12: a terminal session is exec or attach with both
		// --stdin and --tty.
		cmd := c.Command()
		if (cmd != "exec" && cmd != "attach") || !c.boolFlag("stdin") || !c.boolFlag("tty") {
			return codes.WithDetail(codes.InvalidRequest, DetailInteractiveNotAllowed, "interactive runs are only for exec and attach with -i and -t")
		}
		if len(c.stdin) > 0 {
			return codes.WithDetail(codes.InvalidRequest, DetailInteractiveStdin, "an interactive run takes its input from the terminal, not from stdin")
		}
	}
	if len(c.stdin) > 0 && !c.ReadsStdin() {
		return codes.WithDetail(codes.InvalidRequest, DetailStdinNotRead, "stdin was given, but kubectl %s doesn't read it", c.Command())
	}
	return nil
}

// Argv returns the canonical argv, without the leading "kubectl"
// (docs/04 D3). This is what runs.
func (c *Canonical) Argv() []string { return slices.Clone(c.argv) }

// Command returns the resolved command path, e.g. "rollout restart".
func (c *Canonical) Command() string { return strings.Join(c.path, " ") }

// Stdin returns the stdin bytes, as sent.
func (c *Canonical) Stdin() []byte { return bytes.Clone(c.stdin) }

// Interactive reports whether this is a terminal session (docs/04 D12).
func (c *Canonical) Interactive() bool { return c.interactive }

// Type is the target type kubectl requests are for.
func (c *Canonical) Type() string { return codes.TypeKubernetes }

// Digest is Digest(target, c). The identity isn't part of a kubectl
// request's digest (docs/04 §5.3): the decision point and the runner
// take it from the Grant.
func (c *Canonical) Digest(target, _ string) [32]byte { return Digest(target, c) }

// DisplayCommand is DisplayArgv.
func (c *Canonical) DisplayCommand() string { return c.DisplayArgv() }

// ReadsStdin reports whether kubectl reads stdin for this request:
// "-f -", or exec and attach with --stdin.
func (c *Canonical) ReadsStdin() bool {
	if v, ok := c.flag("filename"); ok && len(v) == 1 && v[0] == "-" {
		return true
	}
	cmd := c.Command()
	return (cmd == "exec" || cmd == "attach") && c.boolFlag("stdin")
}

// Audit returns the audited form of the request: the redacted canonical
// argv (docs/04 D14) and stdin's size and hash, never its contents
// (docs/03 D6).
func (c *Canonical) Audit() audit.Request {
	r := audit.Request{Argv: c.redactedArgv(), Interactive: c.interactive}
	if len(c.stdin) > 0 {
		sum := sha256.Sum256(c.stdin)
		r.StdinBytes = len(c.stdin)
		r.StdinSHA256 = hex.EncodeToString(sum[:])
	}
	return r
}

// sanitize keeps a kubectl parse error short and printable. It can echo
// agent input, which is fine to return to the agent, but not unbounded.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
