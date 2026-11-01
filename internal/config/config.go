// Package config decodes and validates Nyyrikki's one configuration file
// (docs/01 D12, docs/02 §5.6). Unknown fields are errors, and invalid
// config means the process doesn't start. The file holds no secrets, only
// paths to them.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Config is the whole file.
type Config struct {
	Server   Server   `yaml:"server"`
	Auth     Auth     `yaml:"auth"`
	Approval Approval `yaml:"approval"`
	Run      Run      `yaml:"run"`
	Humans   []Human  `yaml:"humans"`
	Targets  []Target `yaml:"targets"`
	// Groups name sets of targets for elevate (docs/08 D11).
	Groups   []Group  `yaml:"groups"`
	Telegram Telegram `yaml:"telegram"`
	SSH      SSH      `yaml:"ssh"`
}

// Server holds listeners, TLS and directories (docs/01 D10, D11).
type Server struct {
	CanonicalURL string `yaml:"canonical_url"`
	Listen       string `yaml:"listen"`
	HealthListen string `yaml:"health_listen"`
	TLSCertFile  string `yaml:"tls_cert_file"`
	TLSKeyFile   string `yaml:"tls_key_file"`
	StateDir     string `yaml:"state_dir"`
	RuntimeDir   string `yaml:"runtime_dir"`
}

// Auth describes the authorization server (docs/01 D7, D9).
type Auth struct {
	Issuer      string `yaml:"issuer"`
	CLIClientID string `yaml:"cli_client_id"`
	// Scope is the optional client scope whose Audience mapper puts
	// Nyyrikki's URL in aud (docs/01 D7); published in scopes_supported.
	Scope                   string `yaml:"scope"`
	IntrospectionClientID   string `yaml:"introspection_client_id"`
	IntrospectionSecretFile string `yaml:"introspection_secret_file"`
}

// Approval holds the one-off wait (docs/02 D7).
type Approval struct {
	Timeout Duration `yaml:"timeout"`
}

// Run holds the runner's limits (docs/04 D7).
type Run struct {
	DefaultTimeout Duration `yaml:"default_timeout"`
	MaxTimeout     Duration `yaml:"max_timeout"`
	MaxInteractive Duration `yaml:"max_interactive"`
	MaxOutput      ByteSize `yaml:"max_output"`
}

// Human is one entry of the human registry (docs/02 D4).
type Human struct {
	ID             string    `yaml:"id"`
	Subject        string    `yaml:"subject"`
	Kubernetes     KubeIdent `yaml:"kubernetes"`
	TelegramUserID int64     `yaml:"telegram_user_id"`
}

// KubeIdent is who the human is on Kubernetes targets.
type KubeIdent struct {
	User   string   `yaml:"user"`
	Groups []string `yaml:"groups"`
}

// Target is one entry of the target registry (docs/02 D5, docs/04 D9).
type Target struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Humans      []string   `yaml:"humans"`
	Clients     []string   `yaml:"clients"`
	Kubernetes  KubeTarget `yaml:"kubernetes"`
	// SSH is set for an SSH target, instead of Kubernetes (docs/07 D13).
	SSH *SSHTarget `yaml:"ssh"`
}

// Type is the target's type (codes.TypeKubernetes or codes.TypeSSH).
func (t *Target) Type() string {
	if t.SSH != nil {
		return typeSSH
	}
	return typeKubernetes
}

// The values of codes.TypeKubernetes and codes.TypeSSH; config doesn't
// import codes, and TestTypesMatchCodes keeps them equal.
const (
	typeKubernetes = "kubernetes"
	typeSSH        = "ssh"
)

// Group is a named set of targets of any type (docs/08 D11). It only
// names the targets of an elevation: elevate expands it into its members
// on the server, and the elevation covers that fixed list.
type Group struct {
	Name    string   `yaml:"name"`
	Targets []string `yaml:"targets"`
}

// SSHTarget says how to reach an SSH host (docs/07 §5.5).
type SSHTarget struct {
	// Address is host:port. The file may omit the port; Parse adds the
	// default, 22, so every consumer sees host:port (docs/08 D11).
	Address string `yaml:"address"`
	// HostKeys are pinned host public keys, authorized_keys format
	// (docs/07 D8).
	HostKeys []string `yaml:"host_keys"`
	// HostCAs are host CA public keys whose host certificates are
	// accepted (docs/07 D8).
	HostCAs []string `yaml:"host_cas"`
	// Sudo states that the host gives the human's account passwordless
	// sudo (docs/07 D7, D12). It is the resolved value: SudoSet when the
	// file sets it, else ssh.defaults.sudo (docs/08 D11). Parse fills it
	// in; nothing reads SudoSet after that.
	Sudo bool `yaml:"-"`
	// SudoSet is sudo as the file wrote it; nil when unset.
	SudoSet *bool `yaml:"sudo"`
	// SessionKill states that the host ends a cut session's processes,
	// as its setup reported (docs/07 D11, D12).
	SessionKill bool `yaml:"session_kill"`
}

// SSH holds what all SSH targets share (docs/07 §5.5).
type SSH struct {
	// UserCAKeyFile is the user CA's private key, a mounted Secret
	// (docs/07 D6, docs/08 D1); required.
	UserCAKeyFile string `yaml:"user_ca_key_file"`
	// NextUserCAKeyFile is a staged next user CA key (docs/08 D1); a
	// missing file means no rotation is staged.
	NextUserCAKeyFile string `yaml:"next_user_ca_key_file"`
	// HostCAKeyFile is the host CA key (docs/08 D1); a missing file
	// means enrollment is off.
	HostCAKeyFile string `yaml:"host_ca_key_file"`
	// UserCAPublicKeys are extra CA keys hosts trust, beyond the ones
	// derived from the key files (docs/08 D1); optional.
	UserCAPublicKeys []string `yaml:"user_ca_public_keys"`
	// RevokedUserCAKeys are user CA keys hosts must refuse (docs/08 D3).
	RevokedUserCAKeys []string `yaml:"revoked_user_ca_keys"`
	// SourceAddresses are Nyyrikki's egress CIDRs (docs/07 D4, D5).
	SourceAddresses []string `yaml:"source_addresses"`
	ConnectTimeout  Duration `yaml:"connect_timeout"`
	// HostCAs are host CA public keys trusted for every SSH target, in
	// addition to each target's own host_cas (docs/08 D9).
	HostCAs []string `yaml:"host_cas"`
	// RevokedHostKeys are host keys and host CA keys that are never
	// trusted: a host presenting one, or a certificate of or by one, is
	// refused (docs/08 D9).
	RevokedHostKeys []string `yaml:"revoked_host_keys"`
	// Defaults apply to SSH targets that don't set the value
	// (docs/08 D11).
	Defaults SSHDefaults `yaml:"defaults"`
	// HostCertValidity is how long a host certificate issued by an
	// enrollment is valid (docs/08 D8): DefaultHostCertValidity unless
	// set, at most MaxHostCertValidity.
	HostCertValidity Duration `yaml:"host_cert_validity"`
}

// The host certificate's lifetime (docs/08 D8): five years by default,
// ten at most.
const (
	DefaultHostCertValidity = 43800 * time.Hour
	MaxHostCertValidity     = 87600 * time.Hour
)

// SSHDefaults are the values an SSH target takes when it doesn't set
// them (docs/08 D11).
type SSHDefaults struct {
	Sudo bool `yaml:"sudo"`
}

// SSHAccount is the account of human on SSH hosts (docs/07 D3). It is
// the one definition of the name; the setup script derives the same.
func SSHAccount(human string) string { return "ny-" + human }

// MaxSSHHumanID is the longest human ID usable with SSH targets, so
// that SSHAccount fits Linux's 32 characters (docs/07 D3).
const MaxSSHHumanID = 29

// KubeTarget says how to reach a Kubernetes target.
type KubeTarget struct {
	InCluster bool   `yaml:"in_cluster"`
	Server    string `yaml:"server"`
	CAFile    string `yaml:"ca_file"`
	TokenFile string `yaml:"token_file"`
}

// Telegram configures the approver bot (docs/05 §5.2).
type Telegram struct {
	BotTokenFile string `yaml:"bot_token_file"`
	APIURL       string `yaml:"api_url"`
}

// Duration is a time.Duration written in Go syntax (docs/01 §5.7).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

// D returns the time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// ByteSize is a size such as 1MiB, 512KiB or 1048576.
type ByteSize int64

func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := parseByteSize(s)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

func parseByteSize(s string) (int64, error) {
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.m
			break
		}
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || fmt.Sprint(n) != s || n <= 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return n * mult, nil
}

// Load reads, decodes and validates the file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates b, applying defaults.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	c := Defaults()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: more than one YAML document")
	}
	c.resolve()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// resolve applies the defaults that depend on other values, once, so
// that every consumer sees the resolved form (docs/08 D11): an SSH
// address without a port gets 22, and an SSH target that doesn't set
// sudo takes ssh.defaults.sudo.
func (c *Config) resolve() {
	for i := range c.Targets {
		s := c.Targets[i].SSH
		if s == nil {
			continue
		}
		s.Address = withDefaultPort(s.Address)
		if s.SudoSet != nil {
			s.Sudo = *s.SudoSet
		} else {
			s.Sudo = c.SSH.Defaults.Sudo
		}
	}
}

// Defaults returns a Config holding every default value.
func Defaults() *Config {
	return &Config{
		Server: Server{
			Listen:       ":8443",
			HealthListen: ":8081",
			StateDir:     "/var/lib/nyyrikki",
			RuntimeDir:   "/run/nyyrikki",
		},
		Auth:     Auth{Scope: "nyyrikki"},
		Approval: Approval{Timeout: Duration(3 * time.Minute)},
		Run: Run{
			DefaultTimeout: Duration(60 * time.Second),
			MaxTimeout:     Duration(10 * time.Minute),
			MaxInteractive: Duration(30 * time.Minute),
			MaxOutput:      ByteSize(1 << 20),
		},
		Telegram: Telegram{APIURL: "https://api.telegram.org"},
		SSH:      SSH{ConnectTimeout: Duration(10 * time.Second), HostCertValidity: Duration(DefaultHostCertValidity)},
	}
}

var slug = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// IsSlug reports whether s is a valid config ID (docs/01 §5.7).
func IsSlug(s string) bool { return slug.MatchString(s) }

// Validate checks the whole config and reports every problem it finds.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if u, err := url.Parse(c.Server.CanonicalURL); err != nil || u.Scheme != "https" || u.Host == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		bad("server.canonical_url must be an https URL with no path, query or fragment")
	}
	for name, v := range map[string]string{
		"server.listen": c.Server.Listen, "server.health_listen": c.Server.HealthListen,
		"server.tls_cert_file": c.Server.TLSCertFile, "server.tls_key_file": c.Server.TLSKeyFile,
		"server.state_dir": c.Server.StateDir, "server.runtime_dir": c.Server.RuntimeDir,
		"auth.cli_client_id": c.Auth.CLIClientID, "auth.scope": c.Auth.Scope, "auth.introspection_client_id": c.Auth.IntrospectionClientID,
		"auth.introspection_secret_file": c.Auth.IntrospectionSecretFile,
		"telegram.bot_token_file":        c.Telegram.BotTokenFile,
	} {
		if v == "" {
			bad("%s is required", name)
		}
	}
	if u, err := url.Parse(c.Auth.Issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		bad("auth.issuer must be an https URL")
	}
	// The bot token is part of every Bot API URL: https only, except on
	// loopback (a local test fake).
	if u, err := url.Parse(c.Telegram.APIURL); err != nil || u.Host == "" ||
		!(u.Scheme == "https" || u.Scheme == "http" && isLoopback(u.Hostname())) {
		bad("telegram.api_url must be an https URL")
	}
	if t := c.Approval.Timeout.D(); t < 10*time.Second || t > 10*time.Minute {
		bad("approval.timeout must be between 10s and 10m")
	}
	if c.Run.DefaultTimeout <= 0 || c.Run.MaxTimeout < c.Run.DefaultTimeout {
		bad("run.default_timeout must be positive and at most run.max_timeout")
	}
	if c.Run.MaxInteractive <= 0 || c.Run.MaxInteractive.D() > 30*time.Minute {
		bad("run.max_interactive must be positive and at most 30m")
	}

	// docs/02 D4: exactly one human in v1.
	if len(c.Humans) != 1 {
		bad("humans must have exactly one entry in this version")
	}
	humans := map[string]bool{}
	for i, h := range c.Humans {
		if !IsSlug(h.ID) {
			bad("humans[%d].id must be a slug", i)
		}
		if humans[h.ID] {
			bad("humans[%d].id %q is duplicated", i, h.ID)
		}
		humans[h.ID] = true
		if h.Subject == "" {
			bad("humans[%d].subject is required", i)
		}
		if h.Kubernetes.User == "" || strings.HasPrefix(h.Kubernetes.User, "system:") {
			bad("humans[%d].kubernetes.user is required and must not be a system: identity", i)
		}
		for _, g := range h.Kubernetes.Groups {
			if g == "" || strings.HasPrefix(g, "system:") {
				bad("humans[%d].kubernetes.groups must not contain %q", i, g)
			}
		}
		if h.TelegramUserID <= 0 {
			bad("humans[%d].telegram_user_id must be a positive Telegram user ID", i)
		}
	}

	if len(c.Targets) == 0 {
		bad("targets must have at least one entry")
	}
	// Group and target names share one namespace (docs/08 D11).
	names := map[string]bool{}
	for _, t := range c.Targets {
		names[t.Name] = true
	}
	targets := map[string]bool{}
	for i, t := range c.Targets {
		if !IsSlug(t.Name) {
			bad("targets[%d].name must be a slug", i)
		}
		if targets[t.Name] {
			bad("targets[%d].name %q is duplicated", i, t.Name)
		}
		targets[t.Name] = true
		if len(t.Humans) == 0 {
			bad("targets[%d].humans is required", i)
		}
		for _, h := range t.Humans {
			if !humans[h] {
				bad("targets[%d].humans names unknown human %q", i, h)
			}
		}
		if t.SSH != nil {
			if t.Kubernetes != (KubeTarget{}) {
				bad("targets[%d] has both kubernetes and ssh", i)
			}
			for _, h := range t.Humans {
				if len(h) > MaxSSHHumanID {
					bad("targets[%d]: human %q is longer than %d characters, too long for an SSH account", i, h, MaxSSHHumanID)
				}
			}
			for _, e := range validateSSHTarget(t.SSH) {
				bad("targets[%d].ssh: %v", i, e)
			}
			for _, e := range checkRevokedPins(t.SSH, c.SSH.RevokedHostKeys) {
				bad("targets[%d].ssh: %v", i, e)
			}
			continue
		}
		k := t.Kubernetes
		if k.InCluster {
			if k.Server != "" || k.CAFile != "" || k.TokenFile != "" {
				bad("targets[%d].kubernetes: in_cluster excludes server, ca_file and token_file", i)
			}
		} else {
			if u, err := url.Parse(k.Server); err != nil || u.Scheme != "https" || u.Host == "" {
				bad("targets[%d].kubernetes.server must be an https URL", i)
			}
			if k.CAFile == "" || k.TokenFile == "" {
				bad("targets[%d].kubernetes needs ca_file and token_file", i)
			}
		}
	}
	groups := map[string]bool{}
	for i, g := range c.Groups {
		if !IsSlug(g.Name) {
			bad("groups[%d].name must be a slug", i)
		}
		if names[g.Name] {
			bad("groups[%d].name %q is also the name of a target", i, g.Name)
		}
		if groups[g.Name] {
			bad("groups[%d].name %q is duplicated", i, g.Name)
		}
		groups[g.Name] = true
		if len(g.Targets) == 0 {
			bad("groups[%d].targets is required", i)
		}
		members := map[string]bool{}
		for _, m := range g.Targets {
			if !names[m] {
				bad("groups[%d].targets names unknown target %q", i, m)
			}
			if members[m] {
				bad("groups[%d].targets names %q twice", i, m)
			}
			members[m] = true
		}
	}
	if c.hasSSH() {
		for _, e := range validateSSH(&c.SSH) {
			bad("ssh: %v", e)
		}
		if _, err := HostURL(c.Server.CanonicalURL); err != nil {
			bad("server.canonical_url %v", err)
		}
	} else if !reflectZeroSSH(&c.SSH) {
		bad("ssh is set, but no target is an SSH target")
	}
	return errors.Join(errs...)
}

func (c *Config) hasSSH() bool {
	for _, t := range c.Targets {
		if t.SSH != nil {
			return true
		}
	}
	return false
}

// reflectZeroSSH reports whether s holds only defaults.
func reflectZeroSSH(s *SSH) bool {
	return s.UserCAKeyFile == "" && s.NextUserCAKeyFile == "" && s.HostCAKeyFile == "" &&
		len(s.UserCAPublicKeys) == 0 && len(s.RevokedUserCAKeys) == 0 && len(s.SourceAddresses) == 0 &&
		len(s.HostCAs) == 0 && len(s.RevokedHostKeys) == 0 && s.Defaults == (SSHDefaults{}) &&
		s.HostCertValidity.D() == DefaultHostCertValidity
}

// MCPURL is the canonical URL of /mcp.
func (c *Config) MCPURL() string { return strings.TrimSuffix(c.Server.CanonicalURL, "/") + "/mcp" }

// StreamURL is the canonical URL of /stream.
func (c *Config) StreamURL() string {
	return strings.TrimSuffix(c.Server.CanonicalURL, "/") + "/stream"
}

// HumanBySubject returns the human whose subject is sub.
func (c *Config) HumanBySubject(sub string) (*Human, bool) {
	for i := range c.Humans {
		if c.Humans[i].Subject == sub {
			return &c.Humans[i], true
		}
	}
	return nil, false
}

// HumanByID returns the human with the given id.
func (c *Config) HumanByID(id string) (*Human, bool) {
	for i := range c.Humans {
		if c.Humans[i].ID == id {
			return &c.Humans[i], true
		}
	}
	return nil, false
}

// Visible reports whether target t may be asked for by human on behalf of
// client (docs/02 D5).
func (t *Target) Visible(human, client string) bool {
	if !contains(t.Humans, human) {
		return false
	}
	return len(t.Clients) == 0 || contains(t.Clients, client)
}

// GroupByName returns the group named name.
func (c *Config) GroupByName(name string) (*Group, bool) {
	for i := range c.Groups {
		if c.Groups[i].Name == name {
			return &c.Groups[i], true
		}
	}
	return nil, false
}

// GroupsOf returns the names of the groups that contain target, in
// config order.
func (c *Config) GroupsOf(target string) []string {
	var out []string
	for _, g := range c.Groups {
		if contains(g.Targets, target) {
			out = append(out, g.Name)
		}
	}
	return out
}

// TargetByName returns the target named name.
func (c *Config) TargetByName(name string) (*Target, bool) {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i], true
		}
	}
	return nil, false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
