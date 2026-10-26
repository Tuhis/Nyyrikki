package config

import (
	"os"
	"strings"
	"testing"
	"time"
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
