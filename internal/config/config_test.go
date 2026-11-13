package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/codes"
)

func valid(t *testing.T) string {
	b, err := os.ReadFile("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestValid(t *testing.T) {
	c, err := Parse([]byte(valid(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Approval.Timeout.D() != 2*time.Minute || c.Run.MaxOutput != 512<<10 || c.Run.DefaultTimeout.D() != time.Minute {
		t.Fatalf("values: %+v %+v", c.Approval, c.Run)
	}
	if c.MCPURL() != "https://nyyrikki.example.com/mcp" || c.StreamURL() != "https://nyyrikki.example.com/stream" {
		t.Fatal(c.MCPURL())
	}
	lab, _ := c.TargetByName("lab")
	if !lab.Visible("owner", "nyyrikki-cli") || lab.Visible("owner", "claude") || lab.Visible("other", "nyyrikki-cli") {
		t.Fatal("visibility")
	}
	if h, ok := c.HumanBySubject("0b0e5f0c-1111-2222-3333-444455556666"); !ok || h.ID != "owner" {
		t.Fatal("human lookup")
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string][2]string{
		"unknown field":        {"  timeout: 2m", "  timeout: 2m\n  typo: 1"},
		"http canonical":       {"https://nyyrikki.example.com", "http://nyyrikki.example.com"},
		"canonical with path":  {"canonical_url: https://nyyrikki.example.com", "canonical_url: https://nyyrikki.example.com/x"},
		"timeout too long":     {"timeout: 2m", "timeout: 11m"},
		"bad duration":         {"timeout: 2m", "timeout: soon"},
		"system user":          {"user: owner@example.com", "user: system:admin"},
		"system:masters":       {"groups: [admins]", "groups: [system:masters]"},
		"no telegram id":       {"telegram_user_id: 123456789", "telegram_user_id: 0"},
		"unknown human":        {"humans: [owner]\n    kubernetes:\n      in_cluster", "humans: [ghost]\n    kubernetes:\n      in_cluster"},
		"bad target name":      {"name: lab", "name: Lab_1"},
		"in_cluster + server":  {"in_cluster: true", "in_cluster: true\n      server: https://x"},
		"remote without token": {"      token_file: /etc/nyyrikki/targets/lab/token\n", ""},
		"bad size":             {"max_output: 512KiB", "max_output: lots"},
		"no bot token":         {"  bot_token_file: /etc/nyyrikki/telegram/bot-token", "  api_url: https://api.telegram.org"},
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

// The bot token travels in the Bot API URL, so it must not cross the
// network in cleartext (found in review).
func TestTelegramAPIURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://api.telegram.org": true, "http://127.0.0.1:8080": true, "http://localhost:9": true,
		"http://api.telegram.org": false, "http://10.0.0.1": false, "ftp://x": false,
	} {
		src := strings.Replace(valid(t), "  bot_token_file:", "  api_url: "+url+"\n  bot_token_file:", 1)
		if _, err := Parse([]byte(src)); (err == nil) != ok {
			t.Errorf("%s: %v", url, err)
		}
	}
}

func TestExactlyOneHuman(t *testing.T) {
	src := strings.Replace(valid(t), "targets:", `  - id: second
    subject: x
    kubernetes: {user: x@example.com}
    telegram_user_id: 5
targets:`, 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("two humans: %v", err)
	}
}

func TestTwoDocumentsRejected(t *testing.T) {
	if _, err := Parse([]byte(valid(t) + "\n---\nserver: {}\n")); err == nil {
		t.Fatal("accepted a second document")
	}
}

// Found in review of #10 (L8).
func TestStrictnessGaps(t *testing.T) {
	if _, err := Parse([]byte(valid(t) + "\n---\n: : not yaml [\n")); err == nil {
		t.Error("a second document that doesn't parse was ignored")
	}
	src := strings.Replace(valid(t), "groups: [admins]", "groups: [admins, system:nodes]", 1)
	if _, err := Parse([]byte(src)); err == nil {
		t.Error("a system: group was accepted")
	}
}

func withGroups(t *testing.T, groups string) string {
	t.Helper()
	return strings.Replace(valid(t), "telegram:", groups+"telegram:", 1)
}

// TestGroupsValid covers docs/08 D11 (G10): groups name targets of any
// type, and GroupsOf lists them per target.
func TestGroupsValid(t *testing.T) {
	c, err := Parse([]byte(withGroups(t, "groups:\n  - name: mixed\n    targets: [db-1, prod-k8s]\n  - name: dbs\n    targets: [db-1]\n")))
	if err != nil {
		t.Fatal(err)
	}
	g, ok := c.GroupByName("mixed")
	if !ok || len(g.Targets) != 2 {
		t.Fatalf("group %+v", g)
	}
	if got := c.GroupsOf("db-1"); len(got) != 2 || got[0] != "mixed" || got[1] != "dbs" {
		t.Fatalf("GroupsOf(db-1) = %v", got)
	}
	if got := c.GroupsOf("lab"); len(got) != 0 {
		t.Fatalf("GroupsOf(lab) = %v", got)
	}
	if _, ok := c.GroupByName("db-1"); ok {
		t.Fatal("a target found as a group")
	}
}

// TestGroupsInvalid covers docs/08 D11 (G10): a name shared by a group
// and a target, a duplicated group, a group naming an unknown target, an
// empty group and a malformed name are refused.
func TestGroupsInvalid(t *testing.T) {
	for name, groups := range map[string]string{
		"same name as a target": "groups:\n  - name: lab\n    targets: [db-1]\n",
		"duplicated":            "groups:\n  - name: g\n    targets: [db-1]\n  - name: g\n    targets: [lab]\n",
		"unknown target":        "groups:\n  - name: g\n    targets: [db-1, db-2]\n",
		"group in a group":      "groups:\n  - name: a\n    targets: [db-1]\n  - name: b\n    targets: [a]\n",
		"empty":                 "groups:\n  - name: g\n    targets: []\n",
		"member twice":          "groups:\n  - name: g\n    targets: [db-1, db-1]\n",
		"bad name":              "groups:\n  - name: Web_1\n    targets: [db-1]\n",
		"unknown field":         "groups:\n  - name: g\n    targets: [db-1]\n    humans: [owner]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(withGroups(t, groups))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

const sopsTarget = `  - name: sops-prod
    description: Flux secrets of the prod cluster
    humans: [owner]
    sops:
      gcp_kms:
        credentials_file: /etc/nyyrikki/gcp/sops-prod.json
        keys:
          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod
          - projects/acme/locations/global/keyRings/flux/cryptoKeys/staging
`

// withSOPSTarget is the valid config with a SOPS target added.
func withSOPSTarget(t *testing.T) string {
	t.Helper()
	src := valid(t)
	if !strings.Contains(src, "\nssh:\n") {
		t.Fatal("fixture lacks the ssh block")
	}
	return strings.Replace(src, "\nssh:\n", "\n"+sopsTarget+"ssh:\n", 1)
}

// docs/10 §5.4: a sops target names one credential file and the keys it
// may use, and nothing else.
func TestSOPSTarget(t *testing.T) {
	c, err := Parse([]byte(withSOPSTarget(t)))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := c.TargetByName("sops-prod")
	if !ok || s.Type() != codes.TypeSOPS || s.SOPS.GCPKMS.CredentialsFile != "/etc/nyyrikki/gcp/sops-prod.json" || len(s.SOPS.GCPKMS.Keys) != 2 {
		t.Fatalf("sops target: %+v", s)
	}
	for _, name := range []string{"prod-k8s", "db-1"} {
		if o, _ := c.TargetByName(name); o.Type() == codes.TypeSOPS {
			t.Fatalf("%s reads as a sops target", name)
		}
	}
	if SOPSRunAs("owner") != "Nyyrikki's Google credential, for owner" {
		t.Fatal(SOPSRunAs("owner"))
	}
	key := "          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod\n"
	cases := map[string][2]string{
		"no credentials file":   {"        credentials_file: /etc/nyyrikki/gcp/sops-prod.json\n", ""},
		"a relative file":       {"credentials_file: /etc/nyyrikki/gcp/sops-prod.json", "credentials_file: gcp/sops-prod.json"},
		"no keys":               {"        keys:\n" + key + "          - projects/acme/locations/global/keyRings/flux/cryptoKeys/staging\n", ""},
		"a key twice":           {key, key + key},
		"a key version":         {key, "          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod/cryptoKeyVersions/1\n"},
		"a key ring":            {key, "          - projects/acme/locations/europe-north1/keyRings/flux\n"},
		"a key with a comma":    {key, "          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod,projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/x\n"},
		"a key with a query":    {key, "          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod?x=1\n"},
		"a URL":                 {key, "          - https://cloudkms.googleapis.com/v1/projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod\n"},
		"an unknown field":      {"      gcp_kms:\n", "      endpoint: https://evil.example\n      gcp_kms:\n"},
		"sops and kubernetes":   {"    sops:\n", "    kubernetes:\n      in_cluster: true\n    sops:\n"},
		"sops and ssh":          {"    sops:\n", "    ssh:\n      address: db-2.example.com\n    sops:\n"},
		"an unknown key source": {"      gcp_kms:\n", "      age:\n        recipients: [age1x]\n      gcp_kms:\n"},
	}
	for name, cse := range cases {
		t.Run(name, func(t *testing.T) {
			src := withSOPSTarget(t)
			if !strings.Contains(src, cse[0]) {
				t.Fatalf("fixture lacks %q", cse[0])
			}
			if _, err := Parse([]byte(strings.Replace(src, cse[0], cse[1], 1))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestIsKMSKeyName(t *testing.T) {
	for name, want := range map[string]bool{
		"projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod": true,
		"projects/my-proj:1/locations/global/keyRings/a_b/cryptoKeys/c-d_e":   true,
		"": false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/":                         false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/prod/":                    false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/prod\n":                   false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/pr od":                    false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/prod:decrypt":             false,
		"projects/../locations/global/keyRings/flux/cryptoKeys/prod":                       false,
		"projects/./locations/global/keyRings/flux/cryptoKeys/prod":                        false,
		"projects/acme/locations/global/keyRings/flux/cryptoKeys/prod/cryptoKeyVersions/1": false,
	} {
		if IsKMSKeyName(name) != want {
			t.Errorf("IsKMSKeyName(%q) = %v", name, !want)
		}
	}
}
