package config

import (
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

func TestTypesMatchCodes(t *testing.T) {
	if typeKubernetes != codes.TypeKubernetes || typeSSH != codes.TypeSSH {
		t.Fatal("config's target types differ from codes'")
	}
}

func TestSSHValid(t *testing.T) {
	c, err := Parse([]byte(valid(t)))
	if err != nil {
		t.Fatal(err)
	}
	db, _ := c.TargetByName("db-1")
	if db.Type() != codes.TypeSSH || !db.SSH.Sudo || !db.SSH.SessionKill || len(db.SSH.HostKeys) != 1 {
		t.Fatalf("db-1 %+v", db.SSH)
	}
	if prod, _ := c.TargetByName("prod-k8s"); prod.Type() != codes.TypeKubernetes {
		t.Fatal("prod-k8s type")
	}
	if c.SSH.ConnectTimeout.D() != 10*time.Second || SSHAccount("owner") != "ny-owner" {
		t.Fatal("defaults")
	}
	// Empty host_keys and host_cas are valid, so the setup script can be
	// served first (docs/07 §5.5).
	src := strings.Replace(valid(t), "      host_keys:\n        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n", "", 1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatalf("no host keys: %v", err)
	}
	// docs/08 D1: user_ca_public_keys holds only extra keys and may be
	// empty; the new key files and revoked keys parse.
	src = strings.Replace(valid(t), "  user_ca_public_keys:\n    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y nyyrikki-user-ca\n",
		"  next_user_ca_key_file: /etc/nyyrikki/ssh/user-ca-next\n  host_ca_key_file: /etc/nyyrikki/ssh/host-ca\n"+
			"  revoked_user_ca_keys: [ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y]\n", 1)
	c, err = Parse([]byte(src))
	if err != nil {
		t.Fatalf("no extra CA keys: %v", err)
	}
	if len(c.SSH.UserCAPublicKeys) != 0 || c.SSH.NextUserCAKeyFile != "/etc/nyyrikki/ssh/user-ca-next" ||
		c.SSH.HostCAKeyFile != "/etc/nyyrikki/ssh/host-ca" || len(c.SSH.RevokedUserCAKeys) != 1 {
		t.Fatalf("ssh %+v", c.SSH)
	}
}

func TestSSHInvalid(t *testing.T) {
	const caKey = "    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y nyyrikki-user-ca\n"
	cases := map[string][2]string{
		"no source addresses":  {"  source_addresses: [203.0.113.10/32]\n", ""},
		"no CA key file":       {"  user_ca_key_file: /etc/nyyrikki/ssh/user-ca\n", ""},
		"source not a CIDR":    {"[203.0.113.10/32]", "[203.0.113.10]"},
		"source not canonical": {"[203.0.113.10/32]", "[203.0.113.10/24]"},
		"source with shell":    {"[203.0.113.10/32]", "[\"203.0.113.10/32 $(id)\"]"},
		// Review round 1, finding 7: the setup script refuses these, and
		// nothing it refuses is served (D16).
		"source IPv4-mapped":  {"[203.0.113.10/32]", "[\"::ffff:10.0.0.0/104\"]"},
		"RSA CA key":          {caKey, "    - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\n"},
		"CA key with options": {caKey, "    - from=\"x\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y\n"},
		"two CA keys in one":  {caKey, "    - \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y x\\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y\"\n"},
		"no address":          {"address: db-1.example.com:22", "address: \"\""},
		"empty port":          {"address: db-1.example.com:22", "address: \"db-1.example.com:\""},
		"bad port":            {"address: db-1.example.com:22", "address: db-1.example.com:0"},
		"bad host":            {"address: db-1.example.com:22", "address: \"db 1:22\""},
		"bad host key":        {"        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "        - not-a-key"},
		"connect timeout":     {"  source_addresses: [203.0.113.10/32]\n", "  source_addresses: [203.0.113.10/32]\n  connect_timeout: 5m\n"},
		"both types":          {"    ssh:\n      address", "    kubernetes:\n      in_cluster: true\n    ssh:\n      address"},
		"unknown ssh field":   {"      sudo: true", "      sudo: true\n      port_forward: true"},
		// docs/08 D1, D3.
		"RSA revoked key":    {caKey, caKey + "  revoked_user_ca_keys: [\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7\"]\n"},
		"revoked not a key":  {caKey, caKey + "  revoked_user_ca_keys: [x]\n"},
		"next is user-ca":    {caKey, caKey + "  next_user_ca_key_file: /etc/nyyrikki/ssh/user-ca\n"},
		"host CA is user-ca": {caKey, caKey + "  host_ca_key_file: /etc/nyyrikki/ssh/user-ca\n"},
		"host CA is next":    {caKey, caKey + "  next_user_ca_key_file: /n\n  host_ca_key_file: /n\n"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			src := valid(t)
			if !strings.Contains(src, c[0]) {
				t.Fatalf("fixture lacks %q", c[0])
			}
			if _, err := Parse([]byte(strings.Replace(src, c[0], c[1], 1))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// docs/07 D3: SSH account names must fit Linux's 32 characters.
func TestSSHHumanIDLength(t *testing.T) {
	long := strings.Repeat("a", MaxSSHHumanID+1)
	src := strings.ReplaceAll(valid(t), "owner", long)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "too long for an SSH account") {
		t.Fatalf("a %d-character human on an SSH target: %v", len(long), err)
	}
}

// An ssh block without SSH targets is a mistake, not a no-op.
func TestSSHBlockWithoutTargets(t *testing.T) {
	src := valid(t)
	i := strings.Index(src, "  - name: db-1")
	j := strings.Index(src, "ssh:\n  user_ca_key_file")
	if _, err := Parse([]byte(src[:i] + src[j:])); err == nil {
		t.Fatal("accepted an ssh block with no SSH target")
	}
}

const (
	pinKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	otherKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y"
)

// sshConfig is the fixture with db-1's ssh block replaced by target and
// lines appended to the shared ssh block.
func sshConfig(t *testing.T, target, shared string) string {
	t.Helper()
	src := valid(t)
	old := "      address: db-1.example.com:22\n      host_keys:\n        - " + pinKey + "\n      sudo: true\n      session_kill: true\n"
	if !strings.Contains(src, old) {
		t.Fatal("fixture changed")
	}
	src = strings.Replace(src, old, target, 1)
	return strings.Replace(src, "  source_addresses: [203.0.113.10/32]\n", "  source_addresses: [203.0.113.10/32]\n"+shared, 1)
}

// TestConfigSSHDefaults covers docs/08 D11 (G10): the port defaults to
// 22, resolved once at load; ssh.defaults.sudo applies only where a
// target doesn't set sudo, in either direction.
func TestConfigSSHDefaults(t *testing.T) {
	for addr, want := range map[string]string{
		"db-1.example.com":       "db-1.example.com:22",
		"db-1.example.com:2222":  "db-1.example.com:2222",
		"10.0.0.5":               "10.0.0.5:22",
		"10.0.0.5:22":            "10.0.0.5:22",
		"\"2001:db8::5\"":        "[2001:db8::5]:22",
		"\"[2001:db8::5]\"":      "[2001:db8::5]:22",
		"\"[2001:db8::5]:2200\"": "[2001:db8::5]:2200",
	} {
		c, err := Parse([]byte(sshConfig(t, "      address: "+addr+"\n", "")))
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		db, _ := c.TargetByName("db-1")
		if db.SSH.Address != want {
			t.Errorf("%s: address %q, want %q", addr, db.SSH.Address, want)
		}
		if host, port, err := SplitAddress(db.SSH.Address); err != nil || port == 0 || host == "" {
			t.Errorf("%s: the resolved address doesn't split: %v", addr, err)
		}
	}
	for _, bad := range []string{"\"2001:db8::5:\"", "\"db-1:\"", "\"[db-1]\"", "\"db 1\""} {
		if _, err := Parse([]byte(sshConfig(t, "      address: "+bad+"\n", ""))); err == nil {
			t.Errorf("address %s accepted", bad)
		}
	}

	cases := []struct {
		target, shared string
		want           bool
	}{
		{"", "", false},
		{"", "  defaults: {sudo: false}\n", false},
		{"", "  defaults: {sudo: true}\n", true},
		{"      sudo: false\n", "  defaults: {sudo: true}\n", false},
		{"      sudo: true\n", "  defaults: {sudo: false}\n", true},
		{"      sudo: true\n", "", true},
	}
	for _, tc := range cases {
		c, err := Parse([]byte(sshConfig(t, "      address: db-1.example.com\n"+tc.target, tc.shared)))
		if err != nil {
			t.Fatalf("%q %q: %v", tc.target, tc.shared, err)
		}
		db, _ := c.TargetByName("db-1")
		if db.SSH.Sudo != tc.want {
			t.Errorf("target %q, shared %q: sudo %v, want %v", tc.target, tc.shared, db.SSH.Sudo, tc.want)
		}
	}
	if _, err := Parse([]byte(sshConfig(t, "      address: db-1.example.com\n", "  defaults: {sudo: true, session_kill: true}\n"))); err == nil {
		t.Error("an unknown default was accepted")
	}
}

// TestConfigHostCAsAndRevoked covers the config side of docs/08 D9:
// global host_cas and revoked_host_keys parse as keys, not certificates,
// and a pin that is also revoked is refused.
func TestConfigHostCAsAndRevoked(t *testing.T) {
	c, err := Parse([]byte(sshConfig(t, "      address: db-1\n",
		"  host_cas: [\""+otherKey+" org-ca\"]\n  revoked_host_keys: [\""+pinKey+"\"]\n")))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SSH.HostCAs) != 1 || len(c.SSH.RevokedHostKeys) != 1 {
		t.Fatalf("ssh %+v", c.SSH)
	}
	for name, shared := range map[string]string{
		"bad host CA":         "  host_cas: [not-a-key]\n",
		"bad revoked key":     "  revoked_host_keys: [not-a-key]\n",
		"revoked with option": "  revoked_host_keys: [\"from=\\\"x\\\" " + pinKey + "\"]\n",
	} {
		if _, err := Parse([]byte(sshConfig(t, "      address: db-1\n", shared))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A pin listed as revoked is a contradiction (D9).
	_, err = Parse([]byte(sshConfig(t, "      address: db-1\n      host_keys: [\""+pinKey+" db-1\"]\n",
		"  revoked_host_keys: [\""+pinKey+" old\"]\n")))
	if err == nil || !strings.Contains(err.Error(), "revoked_host_keys") {
		t.Fatalf("a revoked pin: %v", err)
	}
	// These belong to the ssh block: without an SSH target they are a
	// mistake, as the rest of the block is.
	for _, shared := range []string{"host_cas: [\"" + otherKey + "\"]", "revoked_host_keys: [\"" + pinKey + "\"]", "defaults: {sudo: true}"} {
		src := valid(t)
		i := strings.Index(src, "  - name: db-1")
		j := strings.Index(src, "ssh:\n  user_ca_key_file")
		k := strings.Index(src, "telegram:")
		if _, err := Parse([]byte(src[:i] + src[j:j+4] + "  " + shared + "\n" + src[k:])); err == nil {
			t.Errorf("ssh.%s without an SSH target: accepted", shared)
		}
	}
}
