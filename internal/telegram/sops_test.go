package telegram_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

const sopsKey = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod"

func sopsPrompt(id string) approval.RunPrompt {
	p := runPrompt(id)
	p.Target = "sops-prod"
	p.Type = codes.TypeSOPS
	p.RunAs = approval.Identity{User: "Nyyrikki's Google credential, for owner"}
	p.Argv = `sops set --filename-override=clusters/prod/shop/db-creds.enc.yaml --input-type=yaml '["stringData"]["password"]' '‹redacted: 10 bytes, sha256:9c1e5b0a77d2›'`
	p.Stdin = "‹sops yaml, 1423 bytes, sha256:ab12cd34ef56, last modified 2026-11-02T09:14:07Z›"
	p.Reason = "rotate the shop database password"
	p.SOPS = &approval.SOPSRequest{
		Asks:     `Change one value: ["stringData"]["password"] (new value not shown)`,
		FileName: "clusters/prod/shop/db-creds.enc.yaml",
		ShowSays: true,
		Says:     []string{`["apiVersion"] = "v1"`, `["kind"] = "Secret"`, `["metadata"]["name"] = "db-creds"`, `["metadata"]["namespace"] = "shop"`},
		KMSKeys:  []string{sopsKey},
	}
	return p
}

// TestRenderSOPSRun is the golden message of docs/10 D8 and §5.3 (G5):
// what is asked, which file by the agent's claim and by the file's own
// cleartext, who it runs as, the key, the command, and the reason.
func TestRenderSOPSRun(t *testing.T) {
	e := newEnv(t).start()
	m := e.askRun(sopsPrompt("apr_sops1"))
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	want := `<b>Run request</b> on <code>sops-prod</code>
<b>Change one value: ["stringData"]["password"] (new value not shown)</b>
<b>File (agent's claim):</b> <code>clusters/prod/shop/db-creds.enc.yaml</code>
<b>The file says:</b>
<pre>["apiVersion"] = "v1"
["kind"] = "Secret"
["metadata"]["name"] = "db-creds"
["metadata"]["namespace"] = "shop"</pre>
<b>Runs as:</b> <code>Nyyrikki's Google credential, for owner</code>
<b>KMS key:</b> <code>` + sopsKey + `</code>
<b>Agent:</b> <code>Claude Code</code> <i>(name claimed by the client)</i>
key <code>ab12cd34</code>, signed in 2026-10-26 11:00:00 UTC

<b>Request:</b>
<pre>sops set --filename-override=clusters/prod/shop/db-creds.enc.yaml --input-type=yaml '["stringData"]["password"]' '‹redacted: 10 bytes, sha256:9c1e5b0a77d2›'</pre>
<b>File:</b> <code>‹sops yaml, 1423 bytes, sha256:ab12cd34ef56, last modified 2026-11-02T09:14:07Z›</code>

<b>Agent's claim (unverified):</b>
<blockquote>rotate the shop database password</blockquote>

<b>Answer by:</b> 12:05:00 UTC`
	if m.Text != want {
		t.Fatalf("the message:\n%s\n\nwant:\n%s", m.Text, want)
	}
	// The Kubernetes identity of the human is not part of it.
	if strings.Contains(m.Text, "alice") || strings.Contains(m.Text, "groups") {
		t.Errorf("a sops prompt shows a Kubernetes identity:\n%s", m.Text)
	}
}

// The other operations of docs/10 D8: each says what is asked in its
// own fixed line; an encrypt shows no value and no "The file says".
func TestRenderSOPSOperations(t *testing.T) {
	e := newEnv(t).start()
	for i, asks := range []string{
		"Decrypt and return the whole file (2 encrypted values)",
		`Decrypt and return one value: ["stringData"]["password"]`,
		`Remove one value: ["stringData"]["user"]`,
	} {
		p := sopsPrompt("apr_sopsop" + string(rune('a'+i)))
		p.SOPS.Asks = asks
		m := e.askRun(p)
		if !strings.HasPrefix(m.Text, "<b>Run request</b> on <code>sops-prod</code>\n<b>"+asks+"</b>\n<b>File (agent's claim):</b>") {
			t.Errorf("%q doesn't lead the message:\n%s", asks, m.Text)
		}
	}

	// A file with nothing to show says why, in Nyyrikki's own words.
	for i, note := range []string{"nothing in cleartext", "13 cleartext values, not shown", "cleartext not verifiable, not shown"} {
		p := sopsPrompt("apr_sopsnote" + string(rune('a'+i)))
		p.SOPS.Says, p.SOPS.SaysNote = nil, note
		m := e.askRun(p)
		if !strings.Contains(m.Text, "<b>The file says:</b> <i>"+note+"</i>\n<b>Runs as:</b>") || strings.Contains(m.Text, "db-creds</pre>") {
			t.Errorf("note %q:\n%s", note, m.Text)
		}
	}

	p := sopsPrompt("apr_sopsenc")
	p.Argv = "sops encrypt --filename-override=clusters/prod/shop/new.enc.yaml --gcp-kms=" + sopsKey + " --input-type=yaml"
	p.Stdin = "‹plaintext yaml, 125 bytes, sha256:98c5bb849ab6›"
	p.SOPS = &approval.SOPSRequest{Asks: "Encrypt a new file: 2 values encrypted, 4 left in cleartext",
		FileName: "clusters/prod/shop/new.enc.yaml", KMSKeys: []string{sopsKey}}
	m := e.askRun(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.Text, "The file says") || strings.Contains(m.Text, "last modified") {
		t.Errorf("an encrypt shows the file:\n%s", m.Text)
	}
	if !strings.Contains(m.Text, "<b>Encrypt a new file: 2 values encrypted, 4 left in cleartext</b>\n<b>File (agent's claim):</b> <code>clusters/prod/shop/new.enc.yaml</code>\n<b>Runs as:</b>") {
		t.Errorf("an encrypt's message:\n%s", m.Text)
	}
}

// Everything the agent or the file controls is shown escaped, and none
// of it can pass for one of Nyyrikki's own lines (CODE-REVIEW.md: the
// agent is untrusted; docs/10 §6).
func TestRenderSOPSHostile(t *testing.T) {
	e := newEnv(t).start()
	p := sopsPrompt("apr_sopsh")
	forged := "</code>\n<b>The file says:</b> name=staging\n<b>Runs as:</b> nobody"
	p.SOPS.FileName = "a.yaml" + forged
	p.SOPS.Asks = `Decrypt and return one value: ["x` + forged + `"]`
	p.SOPS.Says = []string{`["name=\"staging-db\", [\"metadata\"][\"old\"]"] = "db-creds"`, `["k"] = "</pre>` + forged + "\u202e\""}
	p.SOPS.KMSKeys = []string{sopsKey + forged}
	m := e.askRun(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	if strings.Count(m.Text, "<b>The file says:</b>") != 1 || strings.Count(m.Text, "<b>Runs as:</b>") != 1 || strings.Contains(m.Text, "\u202e") {
		t.Errorf("forged a line or kept a bidi control:\n%s", m.Text)
	}
	// No line of the message starts with forged text: a newline in any
	// of the fields is shown, not sent.
	for _, line := range strings.Split(m.Text, "\n") {
		if strings.HasPrefix(line, "&lt;b&gt;") {
			t.Errorf("a field broke onto a line of its own: %q", line)
		}
	}
	block := between(t, m.Text, "<b>The file says:</b>\n<pre>", "</pre>")
	if lines := strings.Split(block, "\n"); len(lines) != 2 || !strings.HasPrefix(lines[0], `["name=\"staging-db\"`) {
		t.Errorf("the file's lines: %q", block)
	}

	// Too long to show is refused, not shortened (docs/05 D9).
	p = sopsPrompt("apr_sopslong")
	p.Argv = "sops set " + strings.Repeat("x", 5000)
	e.res.pending(p.ID)
	if err := e.bot.AskRun(context.Background(), p); codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("a request too long to show: %v", err)
	}
}

// TestRenderSOPSElevation is docs/10 D8 for the elevation message (G5):
// a window on a sops target is a window on every file its keys protect.
func TestRenderSOPSElevation(t *testing.T) {
	e := newEnv(t).start()
	other := strings.Replace(sopsKey, "/prod", "/staging", 1)
	p := elevationPrompt("elv_sops")
	p.Targets = []string{"prod", "sops-prod"}
	p.SOPS = []approval.SOPSTarget{{Target: "sops-prod", Keys: []string{sopsKey, other}}}
	m := e.askElevation(p)
	if _, err := telegramtest.CheckHTML(m.Text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<b>Runs as:</b> <code>alice@example.com</code>",
		"<b>On</b> <code>sops-prod</code>: <b>decrypts and changes any file encrypted with:</b> <code>" + sopsKey + "</code>, <code>" + other + "</code>\n",
	} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("lacks %q:\n%s", want, m.Text)
		}
	}
	// SOPS targets only: no Kubernetes identity.
	p = elevationPrompt("elv_sops2")
	p.Targets = []string{"sops-prod"}
	p.SOPS = []approval.SOPSTarget{{Target: "sops-prod", Keys: []string{sopsKey}}}
	m = e.askElevation(p)
	if strings.Contains(m.Text, "alice") || !strings.Contains(m.Text, "decrypts and changes any file encrypted with:") {
		t.Errorf("a sops-only elevation:\n%s", m.Text)
	}
	// With an SSH target as well, the Kubernetes identity stays out.
	p = elevationPrompt("elv_sops3")
	p.Targets = []string{"db-1", "sops-prod"}
	p.SSH = []approval.SSHHost{{Target: "db-1", Account: "ny-owner", Address: "db-1.example.com:22", SessionKill: true}}
	p.SOPS = []approval.SOPSTarget{{Target: "sops-prod", Keys: []string{sopsKey}}}
	m = e.askElevation(p)
	if strings.Contains(m.Text, "alice") {
		t.Errorf("an elevation without a Kubernetes target shows its identity:\n%s", m.Text)
	}
}
