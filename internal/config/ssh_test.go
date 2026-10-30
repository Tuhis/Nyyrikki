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
}

func TestSSHInvalid(t *testing.T) {
	const caKey = "    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y nyyrikki-user-ca\n"
	cases := map[string][2]string{
		"no source addresses":  {"  source_addresses: [203.0.113.10/32]\n", ""},
		"no CA public keys":    {"  user_ca_public_keys:\n" + caKey, ""},
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
		"no port":             {"address: db-1.example.com:22", "address: db-1.example.com"},
		"bad port":            {"address: db-1.example.com:22", "address: db-1.example.com:0"},
		"bad host":            {"address: db-1.example.com:22", "address: \"db 1:22\""},
		"bad host key":        {"        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl", "        - not-a-key"},
		"connect timeout":     {"  source_addresses: [203.0.113.10/32]\n", "  source_addresses: [203.0.113.10/32]\n  connect_timeout: 5m\n"},
		"both types":          {"    ssh:\n      address", "    kubernetes:\n      in_cluster: true\n    ssh:\n      address"},
		"unknown ssh field":   {"      sudo: true", "      sudo: true\n      port_forward: true"},
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
