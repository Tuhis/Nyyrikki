package server_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/client"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/server"
	"github.com/Tuhis/Nyyrikki/internal/server/servertest"
	"github.com/Tuhis/Nyyrikki/internal/sopstarget/sopstest"
)

const sopsPlain = `apiVersion: v1
kind: Secret
metadata:
    name: db-creds
    namespace: shop
stringData:
    password: hunter2
    user: app
`

// startSOPS is nyyrikkid with one SOPS target, sops-prod, on a fake
// Cloud KMS, and a file encrypted for it.
func startSOPS(t *testing.T, opts ...servertest.Option) (*servertest.Env, *sopstest.Fake, string) {
	t.Helper()
	f := sopstest.New(t)
	creds := f.ServiceAccountFile(t, t.TempDir())
	opts = append([]servertest.Option{func(c *config.Config) {
		c.Targets = append(c.Targets, config.Target{Name: "sops-prod", Description: "Flux secrets", Humans: []string{"owner"},
			SOPS: &config.SOPSTarget{GCPKMS: config.SOPSGCPKMS{CredentialsFile: creds, Keys: []string{sopstest.KeyProd}}}})
	}}, opts...)
	e := servertest.StartWithOptions(t, func(o *server.Options) { o.SOPSClientOptions = f.ClientOptions() }, opts...)
	enc := f.EncryptYAMLRegex(t, sopsPlain, sopstest.KeyProd, "^(data|stringData)$")
	return e, f, string(enc)
}

func sopsArgs(op string, rest ...string) []string {
	return append([]string{op, "--input-type", "yaml", "--filename-override", "clusters/prod/shop/db-creds.enc.yaml"}, rest...)
}

// TestSOPSRunMCP covers docs/10 from the config file to Cloud KMS (G2,
// G5, G6): list_targets names the type; nothing is called before the
// approval; the prompt says what is asked and which file; after the tap
// the plaintext comes back, the call carries the run's reason, and the
// audit record names the key. A denied request makes no call.
func TestSOPSRunMCP(t *testing.T) {
	e, f, enc := startSOPS(t)
	cs := mcpAgent(t, e, "claude-code", "s1")

	var lt api.ListTargetsOut
	call(t, cs, api.ToolListTargets, map[string]any{}, &lt)
	found := false
	for _, tg := range lt.Targets {
		if tg.Name == "sops-prod" && tg.Type == codes.TypeSOPS && tg.Sudo == nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("list_targets %+v", lt.Targets)
	}

	ch := runAsync(t, cs, api.RunIn{Target: "sops-prod", Args: sopsArgs("decrypt", "--extract", `["stringData"]["password"]`), Stdin: enc, Reason: "check the password"})
	msgs := e.Telegram.WaitSent(t, 1)
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("%d KMS calls before the approval", n)
	}
	for _, want := range []string{
		"<b>Run request</b> on <code>sops-prod</code>\n<b>Decrypt and return one value: [\"stringData\"][\"password\"]</b>",
		"<b>File (agent's claim):</b> <code>clusters/prod/shop/db-creds.enc.yaml</code>",
		"<b>The file says:</b>\n<pre>[\"apiVersion\"] = \"v1\"\n[\"kind\"] = \"Secret\"\n[\"metadata\"][\"name\"] = \"db-creds\"\n[\"metadata\"][\"namespace\"] = \"shop\"</pre>",
		"<b>Runs as:</b> <code>Nyyrikki's Google credential, for owner</code>",
		"<b>KMS key:</b> <code>" + sopstest.KeyProd + "</code>",
		"<pre>sops decrypt '--extract=[\"stringData\"][\"password\"]' --filename-override=clusters/prod/shop/db-creds.enc.yaml --input-type=yaml</pre>",
		"<b>File:</b> <code>‹sops yaml, ",
		"<blockquote>check the password</blockquote>",
	} {
		if !strings.Contains(msgs[0].Text, want) {
			t.Errorf("prompt lacks %q:\n%s", want, msgs[0].Text)
		}
	}
	for _, not := range []string{"hunter2", "ENC[", "owner@example.com", "admins", "user"} {
		if strings.Contains(msgs[0].Text, not) {
			t.Errorf("prompt has %q:\n%s", not, msgs[0].Text)
		}
	}
	e.Tap(t, 1, "Approve")
	r := <-ch
	if r.eb != nil {
		t.Fatalf("run: %+v", r.eb)
	}
	if r.out.ExitCode == nil || *r.out.ExitCode != 0 || r.out.Stdout != "hunter2" || r.out.CoveredBy != codes.CoveredOneOff || r.out.StdoutTruncated {
		t.Fatalf("result %+v", r.out)
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Op != "decrypt" || calls[0].Key != sopstest.KeyProd {
		t.Fatalf("KMS calls %+v", calls)
	}
	if !strings.HasPrefix(calls[0].Reason, "nyyrikki run="+r.out.RunID+" human=owner covered_by=approval:apr_") {
		t.Fatalf("request reason %q for run %s", calls[0].Reason, r.out.RunID)
	}
	var fin map[string]any
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindRunFinished && rec["run_id"] == r.out.RunID {
			fin = rec
		}
	}
	if fin == nil || len(fin["kms_keys"].([]any)) != 1 || fin["kms_keys"].([]any)[0] != sopstest.KeyProd ||
		fin["run_as"].(map[string]any)["user"] != "Nyyrikki's Google credential, for owner" {
		t.Fatalf("run_finished %v", fin)
	}
	if a := e.Audit.String(); strings.Contains(a, "hunter2") || strings.Contains(a, "fake-access-token") {
		t.Fatalf("the audit log holds a secret")
	}

	// Denied: nothing is called.
	ch = runAsync(t, cs, api.RunIn{Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: enc, Reason: "everything"})
	msg := e.Tap(t, 2, "Deny")
	if !strings.Contains(msg.Text, "<b>Decrypt and return the whole file (2 encrypted values)</b>") {
		t.Errorf("prompt:\n%s", msg.Text)
	}
	if r := <-ch; r.eb == nil || r.eb.Code != codes.Denied || r.out.Stdout != "" {
		t.Fatalf("a denied run: %+v %+v", r.eb, r.out)
	}
	if n := len(f.Calls()); n != 1 {
		t.Fatalf("%d KMS calls after a denial", n-1)
	}
}

// TestSOPSRefusedBeforeApproval covers docs/10 D2 and D4 through the
// tool (G1, G2): what a sops target can't take is refused, audited, and
// nobody is asked; a failed run gives the agent a fixed code and none of
// the library's text.
func TestSOPSRefusedBeforeApproval(t *testing.T) {
	e, f, enc := startSOPS(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	for name, in := range map[string]api.RunIn{
		"kubectl arguments":                     {Target: "sops-prod", Args: []string{"get", "secrets"}, Reason: "x"},
		"a command not offered":                 {Target: "sops-prod", Args: sopsArgs("rotate"), Stdin: enc, Reason: "x"},
		"ignore-mac":                            {Target: "sops-prod", Args: sopsArgs("decrypt", "--ignore-mac"), Stdin: enc, Reason: "x"},
		"an interactive run":                    {Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: enc, Interactive: true, Reason: "x"},
		"no file":                               {Target: "sops-prod", Args: sopsArgs("decrypt"), Reason: "x"},
		"a file that isn't SOPS's":              {Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: sopsPlain, Reason: "x"},
		"a key outside the target":              {Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: strings.Replace(enc, sopstest.KeyProd, sopstest.KeyForeign, 1), Reason: "x"},
		"encrypt with a key outside the target": {Target: "sops-prod", Args: sopsArgs("encrypt", "--gcp-kms", sopstest.KeyOther), Stdin: sopsPlain, Reason: "x"},
	} {
		var out api.RunOut
		eb := call(t, cs, api.ToolRun, in, &out)
		if eb == nil || eb.Code != codes.InvalidRequest {
			t.Errorf("%s: %+v", name, eb)
		}
	}
	if n := len(e.Telegram.Sent()); n != 0 {
		t.Fatalf("%d prompts for requests nobody could run", n)
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("%d KMS calls", n)
	}
	invalid := 0
	for _, rec := range e.Audit.Records() {
		if rec["kind"] == codes.KindInvalidRequest {
			invalid++
		}
	}
	if invalid != 8 {
		t.Fatalf("%d of 8 refusals audited", invalid)
	}

	// A tampered file passes the check, is approved, and fails closed.
	tampered := strings.Replace(enc, "name: db-creds", "name: test-creds", 1)
	ch := runAsync(t, cs, api.RunIn{Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: tampered, Reason: "x"})
	msg := e.Tap(t, 1, "Approve")
	if !strings.Contains(msg.Text, `["metadata"]["name"] = "test-creds"`) {
		t.Errorf("prompt:\n%s", msg.Text)
	}
	r := <-ch
	if r.eb == nil || r.eb.Code != codes.InvalidRequest || !strings.Contains(r.eb.Message, "mac_mismatch") || r.out.Stdout != "" {
		t.Fatalf("a tampered file: %+v %+v", r.eb, r.out)
	}
	for _, bad := range []string{"MAC mismatch", "File has", "computed"} {
		if strings.Contains(r.eb.Message, bad) {
			t.Fatalf("the agent got SOPS's text: %s", r.eb.Message)
		}
	}
}

// TestSOPSElevationAndCLI covers docs/10 D8 and D7 under an elevation,
// through the CLI's client (CODE-REVIEW.md: MCP and CLI stay in step):
// the elevation message names the keys, runs under it ask nobody, and
// each call's reason names the elevation.
func TestSOPSElevationAndCLI(t *testing.T) {
	e, f, enc := startSOPS(t)
	path := filepath.Join(t.TempDir(), "login.json")
	e.AS.AutoApprove = true
	if _, err := client.SignIn(context.Background(), client.LoginOptions{Server: e.URL(), CAFile: e.CAFile, Path: path}); err != nil {
		t.Fatal(err)
	}
	l, err := client.LoadLogin(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.Connect(context.Background(), l, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	done := make(chan error, 1)
	var el api.ElevateOut
	go func() {
		done <- s.Call(context.Background(), api.ToolElevate, api.ElevateIn{Targets: []string{"sops-prod"}, Duration: "5m", Reason: "rotate secrets"}, &el)
	}()
	msg := e.Tap(t, 1, "Approve")
	if !strings.Contains(msg.Text, "<b>On</b> <code>sops-prod</code>: <b>decrypts and changes any file encrypted with:</b> <code>"+sopstest.KeyProd+"</code>") ||
		strings.Contains(msg.Text, "owner@example.com") {
		t.Errorf("elevation prompt:\n%s", msg.Text)
	}
	if err := <-done; err != nil || el.Handle == "" {
		t.Fatalf("elevate: %v %+v", err, el)
	}

	// set, then read the result back: two runs, no prompts.
	var set, got api.RunOut
	if err := s.Call(context.Background(), api.ToolRun, api.RunIn{Target: "sops-prod", Elevation: el.Handle,
		Args: sopsArgs("set", `["stringData"]["password"]`, `"n3w-pass"`), Stdin: enc, Reason: "rotate"}, &set); err != nil {
		t.Fatal(err)
	}
	if set.CoveredBy != codes.CoveredElevation || strings.Contains(set.Stdout, "n3w-pass") || !strings.Contains(set.Stdout, "name: db-creds") {
		t.Fatalf("set: %+v", set)
	}
	if err := s.Call(context.Background(), api.ToolRun, api.RunIn{Target: "sops-prod", Elevation: el.Handle,
		Args: sopsArgs("decrypt"), Stdin: set.Stdout, Reason: "check"}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Stdout != strings.Replace(sopsPlain, "hunter2", "n3w-pass", 1) {
		t.Fatalf("decrypt of the set: %q", got.Stdout)
	}
	if n := len(e.Telegram.Sent()); n != 1 {
		t.Fatalf("%d prompts; the elevation's only", n)
	}
	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("KMS calls %+v", calls)
	}
	for i, runID := range []string{set.RunID, got.RunID} {
		if want := "nyyrikki run=" + runID + " human=owner covered_by=elevation:" + el.ElevationID; calls[i].Reason != want {
			t.Errorf("call %d: reason %q; want %q", i, calls[i].Reason, want)
		}
	}
	// The value set is in no audit record, and each run is audited.
	a := e.Audit.String()
	if strings.Contains(a, "n3w-pass") || strings.Contains(a, "hunter2") {
		t.Fatal("the audit log holds a secret value")
	}
	if !strings.Contains(a, "‹redacted: 10 bytes, sha256:") || strings.Count(a, `"kind":"run_finished"`) != 2 {
		t.Fatalf("audit:\n%s", a)
	}
}

// TestSOPSCredentialUnavailable covers docs/10 D12: a broken credential
// file doesn't stop the server; runs on the target are unavailable.
func TestSOPSCredentialUnavailable(t *testing.T) {
	e, f, enc := startSOPS(t, func(c *config.Config) {
		c.Targets[len(c.Targets)-1].SOPS.GCPKMS.CredentialsFile = filepath.Join(t.TempDir(), "missing.json")
	})
	cs := mcpAgent(t, e, "claude-code", "s1")
	ch := runAsync(t, cs, api.RunIn{Target: "sops-prod", Args: sopsArgs("decrypt"), Stdin: enc, Reason: "x"})
	e.Tap(t, 1, "Approve")
	r := <-ch
	if r.eb == nil || r.eb.Code != codes.Unavailable || !strings.Contains(r.eb.Message, "credentials_unavailable") || r.out.Stdout != "" {
		t.Fatalf("a run without a credential: %+v %+v", r.eb, r.out)
	}
	if n := len(f.Calls()); n != 0 {
		t.Fatalf("%d KMS calls", n)
	}
	// The Kubernetes targets are unaffected.
	ch = runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"get", "pod", "api-7f", "-n", "shop", "-o", "jsonpath={.metadata.uid}"}, Reason: "check"})
	e.Tap(t, 2, "Approve")
	if r := <-ch; r.eb != nil || r.out.Stdout != "u-api-7f" {
		t.Fatalf("a kubectl run next to a broken sops target: %+v %+v", r.eb, r.out)
	}
}
