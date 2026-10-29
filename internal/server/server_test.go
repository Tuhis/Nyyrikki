package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Tuhis/Nyyrikki/internal/api"
	"github.com/Tuhis/Nyyrikki/internal/authn/authntest"
	"github.com/Tuhis/Nyyrikki/internal/client"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/server/servertest"
	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

func TestMain(m *testing.M) { servertest.Main(m) }

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// mcpAgent connects as an MCP client (Bearer, keyed by azp and sid).
func mcpAgent(t *testing.T, e *servertest.Env, azp, sid string) *mcp.ClientSession {
	t.Helper()
	tok := e.AS.Token(t, authntest.Claims{AZP: azp, SID: sid, Expiry: time.Now().Add(time.Hour)})
	hc := &http.Client{Transport: &bearer{token: tok, base: e.Client.Transport}}
	c := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "1"}, nil)
	cs, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: e.URL() + "/mcp", HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args, out any) *api.ErrorBody {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if testing.Verbose() {
		rb, _ := json.Marshal(res)
		t.Logf("%s → %s", name, rb)
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			t.Fatalf("decode %s: %v", b, err)
		}
	}
	if res.IsError {
		var e api.ErrorResult
		if json.Unmarshal(b, &e) == nil && e.Error.Code != "" {
			return &e.Error
		}
	}
	return nil
}

func TestListTargetsMCP(t *testing.T) {
	e := servertest.Start(t)
	names := func(cs *mcp.ClientSession) []string {
		var out api.ListTargetsOut
		if eb := call(t, cs, api.ToolListTargets, map[string]any{}, &out); eb != nil {
			t.Fatal(eb)
		}
		var n []string
		for _, x := range out.Targets {
			n = append(n, x.Name)
		}
		return n
	}
	if got := names(mcpAgent(t, e, "claude-code", "s1")); !slices.Equal(got, []string{"prod", "lab", "claude-only"}) {
		t.Fatalf("claude-code sees %v", got)
	}
	if got := names(mcpAgent(t, e, "codex", "s2")); !slices.Equal(got, []string{"prod", "lab"}) {
		t.Fatalf("codex sees %v", got)
	}
	if len(e.Telegram.Sent()) != 0 || len(e.API.Seen()) != 0 {
		t.Fatal("listing reached Telegram or a target")
	}
}

func TestOnlyThreeTools(t *testing.T) {
	e := servertest.Start(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"elevate", "list_targets", "run"}) {
		t.Fatalf("tools %v", names)
	}
	caps := cs.InitializeResult().Capabilities
	//lint:ignore SA1019 asserting the deprecated feature is off
	if caps.Resources != nil || caps.Prompts != nil || caps.Logging != nil || caps.Completions != nil {
		t.Fatalf("capabilities beyond tools: %+v", caps)
	}
	if _, err := cs.ListResources(context.Background(), nil); err == nil {
		t.Fatal("resources/list answered")
	}
}

func TestUnauthenticated(t *testing.T) {
	e := servertest.Start(t)
	resp, err := e.Client.Post(e.URL()+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("status %d, %v", resp.StatusCode, resp.Header)
	}
	resp, err = e.Client.Get(e.URL() + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	var prm map[string]any
	json.NewDecoder(resp.Body).Decode(&prm)
	resp.Body.Close()
	if prm["resource"] != e.URL()+"/mcp" || prm["authorization_servers"].([]any)[0] != e.AS.Issuer() {
		t.Fatalf("metadata %v", prm)
	}
	// Anything else on the main port is 404.
	resp, _ = e.Client.Get(e.URL() + "/debug/pprof/")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("unexpected handler: %d", resp.StatusCode)
	}
}

func runAsync(t *testing.T, cs *mcp.ClientSession, in api.RunIn) chan struct {
	out api.RunOut
	eb  *api.ErrorBody
} {
	ch := make(chan struct {
		out api.RunOut
		eb  *api.ErrorBody
	}, 1)
	go func() {
		var out api.RunOut
		eb := call(t, cs, api.ToolRun, in, &out)
		ch <- struct {
			out api.RunOut
			eb  *api.ErrorBody
		}{out, eb}
	}()
	return ch
}

func TestRunOneOffApprovedMCP(t *testing.T) {
	e := servertest.Start(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	ch := runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"delete", "pod", "api-7f", "-n", "shop"}, Reason: "restart <b>stuck</b> pod"})
	msg := e.Tap(t, 1, "Approve")
	for _, want := range []string{"kubectl delete --namespace=shop pod api-7f", "owner@example.com", "&lt;b&gt;stuck&lt;/b&gt;", "unverified"} {
		if !strings.Contains(msg.Text, want) {
			t.Fatalf("prompt lacks %q:\n%s", want, msg.Text)
		}
	}
	r := <-ch
	if r.eb != nil {
		t.Fatalf("run: %+v", r.eb)
	}
	if r.out.ExitCode == nil || *r.out.ExitCode != 0 || !strings.Contains(r.out.Stdout, `pod "api-7f" deleted`) || r.out.CoveredBy != codes.CoveredOneOff {
		t.Fatalf("result %+v", r.out)
	}
	seen := e.API.Seen()
	var del *servertest.APIRequest
	for i := range seen {
		if seen[i].Method == "DELETE" {
			del = &seen[i]
		}
		if seen[i].User != "owner@example.com" || !slices.Equal(seen[i].Groups, []string{"admins"}) || seen[i].Bearer != servertest.FakeSAToken {
			t.Fatalf("request not impersonating the human: %+v", seen[i])
		}
	}
	if del == nil || del.Path != "/api/v1/namespaces/shop/pods/api-7f" {
		t.Fatalf("no delete reached the target: %+v", seen)
	}
}

func TestRunDeniedAndExpired(t *testing.T) {
	e := servertest.Start(t, func(c *config.Config) { c.Approval.Timeout = config.Duration(2 * time.Second) })
	cs := mcpAgent(t, e, "claude-code", "s1")
	ch := runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"get", "pods", "-n", "shop"}, Reason: "look"})
	e.Tap(t, 1, "Deny")
	if r := <-ch; r.eb == nil || r.eb.Code != codes.Denied {
		t.Fatalf("got %+v", r)
	}
	ch = runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"get", "pods", "-n", "shop"}, Reason: "look"})
	if r := <-ch; r.eb == nil || r.eb.Code != codes.Expired {
		t.Fatalf("got %+v", r)
	}
	if n := len(e.API.Seen()); n != 0 {
		t.Fatalf("%d requests reached the target", n)
	}
}

func TestRunRefusedRequests(t *testing.T) {
	e := servertest.Start(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	for name, in := range map[string]api.RunIn{
		"impersonation flag": {Target: "prod", Args: []string{"get", "pods", "--as", "system:admin"}, Reason: "x"},
		"kubeconfig":         {Target: "prod", Args: []string{"--kubeconfig=/etc/passwd", "get", "pods"}, Reason: "x"},
		"config view":        {Target: "prod", Args: []string{"config", "view", "--raw"}, Reason: "x"},
		"file from disk":     {Target: "prod", Args: []string{"apply", "-f", "/var/run/secrets/kubernetes.io/serviceaccount/token"}, Reason: "x"},
		"no reason":          {Target: "prod", Args: []string{"get", "pods"}},
		"not a target":       {Target: "../prod", Args: []string{"get", "pods"}, Reason: "x"},
	} {
		var out api.RunOut
		if eb := call(t, cs, api.ToolRun, in, &out); eb == nil || eb.Code != codes.InvalidRequest {
			t.Fatalf("%s: %+v", name, eb)
		}
	}
	var out api.RunOut
	if eb := call(t, cs, api.ToolRun, api.RunIn{Target: "claude-only", Args: []string{"get", "pods"}, Reason: "x"}, &out); eb != nil {
		// claude-code may use claude-only; a codex agent may not.
		t.Logf("claude-only for claude-code: %+v", eb)
	}
	cx := mcpAgent(t, e, "codex", "s2")
	if eb := call(t, cx, api.ToolRun, api.RunIn{Target: "claude-only", Args: []string{"get", "pods"}, Reason: "x"}, &out); eb == nil || eb.Code != codes.TargetNotAllowed {
		t.Fatalf("invisible target: %+v", eb)
	}
	if n := len(e.Telegram.Sent()); n > 1 {
		t.Fatalf("refused requests reached the approver (%d prompts)", n)
	}
}

func TestElevationMCP(t *testing.T) {
	e := servertest.Start(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	done := make(chan api.ElevateOut, 1)
	go func() {
		var out api.ElevateOut
		if eb := call(t, cs, api.ToolElevate, api.ElevateIn{Targets: []string{"prod"}, Duration: "2h", Reason: "rollout"}, &out); eb != nil {
			t.Error(eb)
		}
		done <- out
	}()
	msg := e.Tap(t, 1, "Approve")
	if !strings.Contains(msg.Text, "30m") && !strings.Contains(msg.Text, "30 min") {
		t.Logf("elevation prompt:\n%s", msg.Text)
	}
	el := <-done
	exp, _ := time.Parse(time.RFC3339Nano, el.ExpiresAt)
	if d := time.Until(exp); d > 30*time.Minute+5*time.Second || d < 29*time.Minute {
		t.Fatalf("elevation lasts %v", d)
	}
	for i := 0; i < 2; i++ {
		var out api.RunOut
		if eb := call(t, cs, api.ToolRun, api.RunIn{Target: "prod", Args: []string{"get", "pods", "-n", "shop", "-o", "name"}, Reason: "check", Elevation: el.Handle}, &out); eb != nil {
			t.Fatal(eb)
		}
		if out.CoveredBy != codes.CoveredElevation || !strings.Contains(out.Stdout, "pod/api-7f") {
			t.Fatalf("result %+v", out)
		}
	}
	if n := len(e.Telegram.Sent()); n != 1 {
		t.Fatalf("%d prompts; covered requests asked again", n)
	}
	// Another agent key with the handle: denied, not turned into a one-off.
	other := mcpAgent(t, e, "codex", "s9")
	var out api.RunOut
	if eb := call(t, other, api.ToolRun, api.RunIn{Target: "prod", Args: []string{"get", "pods"}, Reason: "x", Elevation: el.Handle}, &out); eb == nil || eb.Code != codes.HandleUnknown {
		t.Fatalf("foreign handle: %+v", eb)
	}
	// End now from the chat.
	e.Telegram.Wait(t, "End now button", func() bool {
		m, _ := e.Telegram.Message(msg.ChatID, msg.MessageID)
		_, ok := m.Button("End now")
		return ok
	})
	cur, _ := e.Telegram.Message(msg.ChatID, msg.MessageID)
	e.Telegram.WaitAnswer(t, e.Telegram.Tap(t, cur, "End now", servertest.ApproverID))
	ch := runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"get", "pods"}, Reason: "after end", Elevation: el.Handle})
	e.Telegram.WaitSent(t, 2) // back to one-off
	e.Tap(t, 2, "Deny")
	if r := <-ch; r.eb == nil || r.eb.Code != codes.Denied {
		t.Fatalf("after end: %+v", r)
	}

	// Nothing secret in the audit stream (docs/03 G4).
	audit := e.Audit.String()
	for _, secret := range []string{el.Handle, servertest.FakeSAToken, "Bearer ", "sid\x00", "s1"} {
		if strings.Contains(audit, secret) {
			t.Fatalf("audit stream contains %q", secret)
		}
	}
	kinds := map[string]bool{}
	for _, r := range e.Audit.Records() {
		kinds[r["kind"].(string)] = true
	}
	for _, k := range []string{codes.KindElevationRequested, codes.KindApprovalSent, codes.KindElevationLive, codes.KindDecision, codes.KindRunStarted, codes.KindRunFinished, codes.KindElevationEnded} {
		if !kinds[k] {
			t.Errorf("no %s record", k)
		}
	}
}

func TestCLIFlow(t *testing.T) {
	e := servertest.Start(t)
	path := filepath.Join(t.TempDir(), "login.json")
	e.AS.AutoApprove = true
	l, err := client.SignIn(context.Background(), client.LoginOptions{Server: e.URL(), CAFile: e.CAFile, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if l.ClientID != "nyyrikki-cli" || l.DPoPKey == "" {
		t.Fatalf("login %+v", l)
	}
	if _, err := client.SignIn(context.Background(), client.LoginOptions{Server: e.URL(), CAFile: e.CAFile, Path: path}); err == nil {
		t.Fatal("replaced a login without --force")
	}
	l, err = client.LoadLogin(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.Connect(context.Background(), l, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var targets api.ListTargetsOut
	if err := s.Call(context.Background(), api.ToolListTargets, api.ListTargetsIn{}, &targets); err != nil || len(targets.Targets) != 2 {
		t.Fatalf("targets %v %v", targets, err)
	}
	done := make(chan error, 1)
	var out api.RunOut
	go func() {
		done <- s.Call(context.Background(), api.ToolRun, api.RunIn{Target: "prod", Args: []string{"get", "pod", "api-7f", "-n", "shop", "-o", "jsonpath={.metadata.uid}"}, Reason: "check"}, &out)
	}()
	e.Tap(t, 1, "Approve")
	if err := <-done; err != nil || out.Stdout != "u-api-7f" {
		t.Fatalf("run: %v %+v", err, out)
	}
	// A revoked session stops run at once, even with a valid token
	// (docs/01 OD13).
	for _, rec := range e.Audit.Records() {
		_ = rec
	}
	e.AS.Revoke("sid-1")
	err = s.Call(context.Background(), api.ToolRun, api.RunIn{Target: "prod", Args: []string{"get", "pods"}, Reason: "x"}, &out)
	if te, ok := err.(*client.ToolError); !ok || te.Code != codes.SessionInactive {
		t.Fatalf("revoked session: %v", err)
	}
}

func TestMCPHeadersLogin(t *testing.T) {
	e := servertest.Start(t)
	path := filepath.Join(t.TempDir(), "mcp-login.json")
	e.AS.AutoApprove = true
	l, err := client.SignIn(context.Background(), client.LoginOptions{Server: e.URL(), CAFile: e.CAFile, Path: path, MCP: true, ClientName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !l.MCP || l.DPoPKey != "" || !strings.HasPrefix(l.ClientID, "dcr-") {
		t.Fatalf("login %+v", l)
	}
	h, err := l.Header(context.Background(), "POST", l.MCPURL, time.Now)
	if err != nil || !strings.HasPrefix(h.Get("Authorization"), "Bearer ") {
		t.Fatal(err)
	}
}

// TestDeviceGrantPKCE: Keycloak requires PKCE in the device grant for a
// client whose PKCE method is set, which a pkce-enforcer client policy
// does for every registered client. Both logins send S256 PKCE, so both
// work there (found by the e2e test of docs/01 M9).
func TestDeviceGrantPKCE(t *testing.T) {
	e := servertest.Start(t)
	e.AS.AutoApprove = true
	e.AS.RequirePKCE = true
	for _, mcp := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "login.json")
		if _, err := client.SignIn(context.Background(), client.LoginOptions{Server: e.URL(), CAFile: e.CAFile, Path: path, MCP: mcp, ClientName: "test"}); err != nil {
			t.Fatalf("login (mcp=%v) against an AS requiring PKCE: %v", mcp, err)
		}
	}
}

// TestDeviceGrantWrongVerifier: the test authorization server's PKCE
// check isn't vacuous: a device code issued for one challenge gives no
// token for another verifier.
func TestDeviceGrantWrongVerifier(t *testing.T) {
	e := servertest.Start(t)
	e.AS.AutoApprove = true
	hc := e.AS.Client()
	sum := sha256.Sum256([]byte("right-verifier"))
	resp, err := hc.PostForm(e.AS.URL+"/device", url.Values{"client_id": {"dcr-x"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}})
	if err != nil {
		t.Fatal(err)
	}
	var da struct {
		DeviceCode string `json:"device_code"`
	}
	json.NewDecoder(resp.Body).Decode(&da)
	resp.Body.Close()
	// Wrong, then right: the fake keeps a device code after a failed
	// verifier (whether Keycloak does isn't measured).
	for _, v := range []struct {
		verifier string
		ok       bool
	}{{"wrong-verifier", false}, {"right-verifier", true}} {
		resp, err := hc.PostForm(e.AS.URL+"/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {da.DeviceCode}, "client_id": {"dcr-x"}, "code_verifier": {v.verifier}})
		if err != nil {
			t.Fatal(err)
		}
		var tr struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&tr)
		resp.Body.Close()
		if (resp.StatusCode == http.StatusOK) != v.ok || (!v.ok && tr.Error != "invalid_grant") {
			t.Fatalf("verifier %q: %s %s", v.verifier, resp.Status, tr.Error)
		}
	}
}

// TestTelegramConflictKeepsServingAndDenies: a 409 from getUpdates means
// another poller has the token. Nyyrikki stops polling for good but keeps
// serving, so /readyz can report it, and denies every escalation until it
// is restarted. It must not exit and be restarted into a retry loop
// (docs/05 D2; found in review).
func TestTelegramConflictKeepsServingAndDenies(t *testing.T) {
	e := servertest.Start(t)
	e.Telegram.FailNext("getUpdates", http.StatusConflict)
	// End the current long poll so the next one meets the conflict.
	e.Telegram.PushMessage(telegramtest.TextMessage{FromID: servertest.ApproverID, ChatID: servertest.ApproverID, Text: "hello"})
	e.Telegram.Wait(t, "the poller to hit the conflict", func() bool { return e.Telegram.Calls("getUpdates") >= 2 })
	time.Sleep(200 * time.Millisecond)
	if e.Stopped() {
		t.Fatal("nyyrikkid exited on a Telegram conflict")
	}
	cs := mcpAgent(t, e, "claude-code", "s1")
	var out api.RunOut
	if eb := call(t, cs, api.ToolRun, api.RunIn{Target: "prod", Args: []string{"get", "pods"}, Reason: "x"}, &out); eb == nil || eb.Code != codes.Unavailable {
		t.Fatalf("escalation with a stopped poller: %+v", eb)
	}
	var targets api.ListTargetsOut
	if eb := call(t, cs, api.ToolListTargets, map[string]any{}, &targets); eb != nil || len(targets.Targets) == 0 {
		t.Fatalf("listing stopped working: %+v", eb)
	}
}

// TestCutRunKeepsPartialOutput: a run cut at its time limit returns what it
// printed so far together with the expired error (docs/04 D7; found in
// review of #10, M2).
func TestCutRunKeepsPartialOutput(t *testing.T) {
	e := servertest.Start(t)
	cs := mcpAgent(t, e, "claude-code", "s1")
	ch := runAsync(t, cs, api.RunIn{Target: "prod", Args: []string{"logs", "-f", "api-7f", "-n", "shop", "-c", "app"}, Reason: "watch", Timeout: "3s"})
	e.Tap(t, 1, "Approve")
	r := <-ch
	if r.eb == nil || r.eb.Code != codes.Expired {
		t.Fatalf("want expired, got %+v", r)
	}
	if !strings.Contains(r.out.Stdout, "partial-log-line") {
		t.Fatalf("partial output lost: %+v", r.out)
	}
}
