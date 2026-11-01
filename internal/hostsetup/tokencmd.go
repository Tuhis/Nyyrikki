package hostsetup

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// TokenCommand is `nyyrikkid enroll-token <target>` (docs/08 D6), run in
// Nyyrikki's pod with `kubectl exec`, so that it reads the same config
// file and the same mounted host-ca as the server. It prints the token
// and the command to run on the host on stdout, and nothing else there;
// it logs nothing, and never writes the token anywhere but stdout.
type TokenCommand struct {
	Stdout, Stderr io.Writer
	Now            func() time.Time
}

const tokenUsage = `usage: nyyrikkid enroll-token [--config FILE] TARGET

Prints a one-time enrollment token for the SSH target TARGET, valid 15
minutes, and the command that sets the host up and enrolls it
(docs/08 D6, D7). Run it in Nyyrikki's pod:

  kubectl -n NAMESPACE exec deploy/RELEASE-nyyrikki -- nyyrikkid enroll-token TARGET
`

// noHostCARemedy is what enroll-token says without host-ca (docs/08
// D16): the chart's CronJob, or ssh-ca on a workstation.
const noHostCARemedy = `enrollment is off: the SSH CA Secret has no host-ca (docs/08 D16).
Add one, then wait a minute or two for the pod to see it:
  kubectl -n NAMESPACE create job --from=cronjob/RELEASE-ssh-ca-add-host-ca ssh-ca-add-host-ca-1
or, for a Secret the chart's CronJobs don't manage (no caJobs):
  kubectl -n NAMESPACE get secret SECRET -o yaml | nyyrikkid ssh-ca add-host-ca | kubectl replace -f -
`

// DefaultConfigPath is where the chart mounts the server's config file,
// so that the command reads it when run in the pod without --config.
const DefaultConfigPath = "/etc/nyyrikki/config/config.yaml"

// Main runs the command and returns its exit code.
func (c TokenCommand) Main(args []string) int {
	if c.Now == nil {
		c.Now = time.Now
	}
	fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	fs.Usage = func() { fmt.Fprint(c.Stderr, tokenUsage) }
	configPath := fs.String("config", DefaultConfigPath, "path to the configuration file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	name := fs.Arg(0)
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(c.Stderr, "enroll-token: invalid configuration: %v\n", err)
		return 1
	}
	t, ok := cfg.TargetByName(name)
	if !config.IsSlug(name) || !ok || t.SSH == nil {
		fmt.Fprintf(c.Stderr, "enroll-token: %q is not an SSH target in the registry\n", name)
		return 1
	}
	// No audit appender: the command keeps no state, and the server
	// audits the token's use (docs/08 D6). Warnings go nowhere.
	keys, err := sshca.FromConfig(cfg.SSH, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		fmt.Fprintf(c.Stderr, "enroll-token: %v\n", err)
		return 1
	}
	set, err := keys.Load()
	if err != nil {
		fmt.Fprintf(c.Stderr, "enroll-token: the SSH CA keys are unavailable (%s); fix the CA Secret first\n", detailOr(err, "unavailable"))
		return 1
	}
	key, err := set.EnrollTokenKey()
	set = nil
	if err != nil {
		if codes.DetailOf(err) == sshca.DetailHostCAAbsent {
			fmt.Fprint(c.Stderr, "enroll-token: "+noHostCARemedy)
		} else {
			fmt.Fprintf(c.Stderr, "enroll-token: %s\n", detailOr(err, "unavailable"))
		}
		return 1
	}
	tok, info, err := MintToken(key, t.Name, c.Now())
	clear(key)
	if err != nil {
		fmt.Fprintf(c.Stderr, "enroll-token: %v\n", err)
		return 1
	}
	base := strings.TrimSuffix(cfg.Server.CanonicalURL, "/")
	fmt.Fprintf(c.Stdout, "Enrollment token for %s, valid until %s UTC, for one enrollment.\n", t.Name, info.Expires.UTC().Format("15:04:05"))
	fmt.Fprintf(c.Stdout, "Run this as root on the host %s:\n\n", t.SSH.Address)
	fmt.Fprintf(c.Stdout, "  curl -fsSL %s/hosts/%s/setup.sh | sudo sh -s -- --enroll %s\n\n", base, t.Name, tok)
	fmt.Fprintln(c.Stdout, "It prints the host key's fingerprint; approve on Telegram only if the message shows the same one.")
	fmt.Fprintln(c.Stdout, "If Nyyrikki's certificate comes from a private CA, add --cacert with that CA. Never -k.")
	return 0
}
