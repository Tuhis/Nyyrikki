//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestEndToEnd walks M1–M3 on a real cluster with a real authorization
// server (docs/04 PT5, ROADMAP M1–M3 "done when").
func TestEndToEnd(t *testing.T) {
	e := setup(t)
	prompts := 0
	next := func() int { prompts++; return prompts }

	agent := e.newCLI(t)
	step(t, "M1: sign in, list targets, refuse the unauthenticated", func(t *testing.T) {
		agent.login(t)
		lf := loginFile(agent)
		c := claims(lf["access_token"].(string))
		// docs/01 M9: what Keycloak 26.8 puts in a DPoP-bound CLI token.
		t.Logf("M9 CLI token: typ=%v azp=%v sid=%v cnf=%v aud=%v", c["typ"], c["azp"], c["sid"], c["cnf"], c["aud"])
		if cnf, _ := c["cnf"].(map[string]any); cnf == nil || cnf["jkt"] == nil || cnf["jkt"] == "" {
			t.Fatalf("the CLI's token isn't DPoP-bound: cnf=%v", c["cnf"])
		}
		r := agent.run(t, "", "targets")
		if r.code != 0 || !strings.Contains(r.stdout, "this-cluster") {
			t.Fatalf("targets: %+v", r)
		}
		resp, err := e.httpClient().Post(e.canonical+"/mcp", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("unauthenticated /mcp: %d", resp.StatusCode)
		}
		// A DPoP-bound token presented as Bearer is refused (docs/01 D9).
		req, _ := http.NewRequest("POST", e.canonical+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Authorization", "Bearer "+lf["access_token"].(string))
		req.Header.Set("Content-Type", "application/json")
		resp, err = e.httpClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("a DPoP-bound token as Bearer: %d", resp.StatusCode)
		}
		if n := len(e.tg.Sent(t)); n != 0 {
			t.Fatalf("listing reached the approver (%d prompts)", n)
		}
	})

	step(t, "M2: an approved request runs on the target as the human", func(t *testing.T) {
		ch := agent.async(t, "run", "--reason", "who am I on the cluster", "this-cluster", "--",
			"auth", "whoami", "-o", "jsonpath={.status.userInfo.username}")
		msg := e.tap(t, next(), "Approve")
		if !strings.Contains(msg.Text, "kubectl auth whoami") || !strings.Contains(msg.Text, ownerK8sUser) {
			t.Fatalf("prompt doesn't show the request and the identity:\n%s", msg.Text)
		}
		r := get(t, ch, time.Minute)
		// The apiserver itself reports who the request ran as.
		if r.code != 0 || strings.TrimSpace(r.stdout) != ownerK8sUser {
			t.Fatalf("whoami: %+v", r)
		}
	})

	step(t, "M2: a denied request doesn't run", func(t *testing.T) {
		ch := agent.async(t, "run", "--reason", "delete it", "this-cluster", "--", "delete", "pod", "box", "-n", workNS)
		e.tap(t, next(), "Deny")
		if r := get(t, ch, time.Minute); r.code != 77 || !strings.Contains(r.stderr, "nyyrikki: error: denied:") {
			t.Fatalf("denied run: %+v", r)
		}
		// Not merely still there: a deleted pod stays visible while it
		// terminates, so check no deletion has started.
		if ts := e.kubectl(t, "-n", workNS, "get", "pod", "box", "-o", "jsonpath={.metadata.deletionTimestamp}"); strings.TrimSpace(ts) != "" {
			t.Fatalf("the denied delete ran: pod box is terminating since %s", ts)
		}
	})

	step(t, "M2: a request that leaves the human is refused before any prompt", func(t *testing.T) {
		before := len(e.tg.Sent(t))
		for _, args := range [][]string{
			{"get", "pods", "--as", "system:admin"},
			{"config", "view", "--raw"},
			{"apply", "-f", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		} {
			r := agent.run(t, "", append([]string{"run", "--reason", "x", "this-cluster", "--"}, args...)...)
			// The server's refusal, not a local usage error.
			if r.code != 64 || !strings.Contains(r.stderr, "nyyrikki: error: invalid_request:") {
				t.Errorf("%v: %+v", args, r)
			}
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("a refused request reached the approver")
		}
	})

	step(t, "M2: interactive exec through /stream", func(t *testing.T) {
		cmd := agent.cmd("run", "-t", "--reason", "look inside", "this-cluster", "--",
			"exec", "-it", "box", "-n", workNS, "--", "sh", "-c", "echo e2e-$((40+2))")
		out, wait := startPTY(t, cmd)
		e.tap(t, next(), "Approve")
		code := wait(time.Minute)
		if code != 0 || !strings.Contains(out(), "e2e-42") {
			t.Fatalf("exec: code %d, output %q", code, out())
		}
	})

	step(t, "M3: an elevation covers requests without asking, and cuts a stream at expiry", func(t *testing.T) {
		ch := agent.async(t, "elevate", "--reason", "a burst of work", "--for", "1m", "this-cluster")
		e.tap(t, next(), "Approve")
		approvedAt := time.Now()
		r := get(t, ch, time.Minute)
		handle := strings.TrimSpace(r.stdout)
		if r.code != 0 || !strings.HasPrefix(handle, "nyel_") {
			t.Fatalf("elevate: %+v", r)
		}
		elevated := append([]string{}, agent.env...)
		elevated = append(elevated, "NYYRIKKI_ELEVATION="+handle)
		before := len(e.tg.Sent(t))
		for i := 0; i < 2; i++ {
			cmd := agent.cmd("run", "--reason", "covered", "this-cluster", "--", "get", "pods", "-n", workNS, "-o", "name")
			cmd.Env = elevated
			out, err := cmd.Output()
			if err != nil || !strings.Contains(string(out), "pod/box") {
				t.Fatalf("covered run %d: %v %s", i, err, out)
			}
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("a covered request asked the approver")
		}
		// A long-lived exec under the elevation is cut when it expires.
		cmd := agent.cmd("run", "-t", "--reason", "long session", "this-cluster", "--",
			"exec", "-it", "box", "-n", workNS, "--", "sleep", "600")
		cmd.Env = elevated
		_, wait := startPTY(t, cmd)
		code := wait(2 * time.Minute)
		lasted := time.Since(approvedAt)
		// The stream must stay up until the expiry and be cut then: a quick
		// failure (a refusal, a broken /stream) doesn't count.
		if code == 0 || lasted < 55*time.Second || lasted > 80*time.Second {
			t.Fatalf("stream not cut at expiry: code %d after %v", code, lasted)
		}
		t.Logf("stream cut %v after the approval of a 1m elevation", lasted.Round(time.Second))
		// After expiry the handle no longer covers: back to a one-off.
		ch = agent.asyncEnv(t, []string{"NYYRIKKI_ELEVATION=" + handle}, "run", "--reason", "after expiry", "this-cluster", "--", "get", "pods", "-n", workNS)
		e.tap(t, next(), "Deny")
		if r := get(t, ch, time.Minute); r.code != 77 || !strings.Contains(r.stderr, "nyyrikki: error: denied:") {
			t.Fatalf("after expiry: %+v", r)
		}
	})

	step(t, "M3: End now from the chat ends the elevation at once", func(t *testing.T) {
		ch := agent.async(t, "elevate", "--reason", "short", "--for", "10m", "this-cluster")
		msg := e.tap(t, next(), "Approve")
		r := get(t, ch, time.Minute)
		h := strings.TrimSpace(r.stdout)
		if r.code != 0 || !strings.HasPrefix(h, "nyel_") {
			t.Fatalf("elevate: %+v", r)
		}
		withH := []string{"NYYRIKKI_ELEVATION=" + h}
		// Live before End now: a covered request, no prompt.
		before := len(e.tg.Sent(t))
		if r := agent.runEnv(t, withH, "", "run", "--reason", "covered", "this-cluster", "--", "get", "pods", "-n", workNS, "-o", "name"); r.code != 0 || !strings.Contains(r.stdout, "pod/box") {
			t.Fatalf("covered before End now: %+v", r)
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("the live elevation asked the approver")
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			cur := e.tg.Message(t, msg)
			if _, ok := cur.Button("End now"); ok {
				e.tg.Tap(t, cur, "End now")
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no End now button")
			}
			time.Sleep(300 * time.Millisecond)
		}
		// After End now the same handle no longer covers: a one-off prompt.
		ch = agent.asyncEnv(t, withH, "run", "--reason", "after end", "this-cluster", "--", "get", "pods", "-n", workNS)
		e.tap(t, next(), "Deny")
		if r := get(t, ch, time.Minute); r.code != 77 || !strings.Contains(r.stderr, "nyyrikki: error: denied:") {
			t.Fatalf("after End now: %+v", r)
		}
	})

	step(t, "M3: another agent's live handle is denied, never turned into a one-off", func(t *testing.T) {
		// A live elevation's handle, leaked to another agent (docs/01 D24).
		ch := agent.async(t, "elevate", "--reason", "leak test", "--for", "5m", "this-cluster")
		e.tap(t, next(), "Approve")
		r := get(t, ch, time.Minute)
		live := strings.TrimSpace(r.stdout)
		if r.code != 0 || !strings.HasPrefix(live, "nyel_") {
			t.Fatalf("elevate: %+v", r)
		}
		other := e.newCLI(t)
		other.login(t)
		before := len(e.tg.Sent(t))
		cmd := other.cmd("run", "--reason", "borrowed", "this-cluster", "--", "get", "pods", "-n", workNS)
		cmd.Env = append(append([]string{}, other.env...), "NYYRIKKI_ELEVATION="+live)
		var se bytes.Buffer
		cmd.Stderr = &se
		err := cmd.Run()
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 77 || !strings.Contains(se.String(), "handle_unknown") {
			t.Fatalf("foreign live handle: %v %s", err, se.String())
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("a foreign handle reached the approver")
		}
		// The handle was live: its own agent still runs with it, unprompted.
		cmd = agent.cmd("run", "--reason", "own handle", "this-cluster", "--", "get", "pods", "-n", workNS, "-o", "name")
		cmd.Env = append(append([]string{}, agent.env...), "NYYRIKKI_ELEVATION="+live)
		if out, err := cmd.Output(); err != nil || !strings.Contains(string(out), "pod/box") {
			t.Fatalf("own live handle: %v %s", err, out)
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("the live elevation asked again")
		}
	})

	step(t, "MCP agent with a Bearer token", func(t *testing.T) {
		tok := e.deviceToken(t, mcpClientID)
		c := claims(tok)
		t.Logf("M9 MCP token: typ=%v azp=%v sid=%v aud=%v", c["typ"], c["azp"], c["sid"], c["aud"])
		hc := e.httpClient()
		hc.Transport = &bearer{tok: tok, base: hc.Transport}
		client := mcp.NewClient(&mcp.Implementation{Name: "e2e-agent", Version: "1"}, nil)
		cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
			Endpoint: e.canonical + "/mcp", HTTPClient: hc, MaxRetries: -1, DisableStandaloneSSE: true,
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cs.Close()
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_targets", Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("list_targets: %v %+v", err, res)
		}
		done := make(chan *mcp.CallToolResult, 1)
		go func() {
			r, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "run", Arguments: map[string]any{
				"target": "this-cluster", "args": []string{"auth", "whoami", "-o", "jsonpath={.status.userInfo.username}"},
				"reason": "from an MCP agent",
			}})
			if err != nil {
				t.Error(err)
			}
			done <- r
		}()
		e.tap(t, next(), "Approve")
		r := <-done
		if r == nil {
			t.Fatal("MCP run returned no result")
		}
		b, _ := json.Marshal(r.StructuredContent)
		var out struct {
			Stdout string `json:"stdout"`
		}
		json.Unmarshal(b, &out)
		if strings.TrimSpace(out.Stdout) != ownerK8sUser {
			t.Fatalf("MCP run: %s", b)
		}
	})

	step(t, "a session ended in Keycloak is denied at once", func(t *testing.T) {
		e.admin(t, "POST", "/admin/realms/"+realm+"/users/"+e.ownerID+"/logout", nil)
		before := len(e.tg.Sent(t))
		r := agent.run(t, "", "run", "--reason", "after logout", "this-cluster", "--", "get", "pods")
		if r.code != 77 || !strings.Contains(r.stderr, "session_inactive") {
			t.Fatalf("revoked session: %+v", r)
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("a revoked session reached the approver")
		}
	})
}

// step runs one subtest and stops the walk at the first failure: later
// steps build on earlier ones.
func step(t *testing.T, name string, f func(t *testing.T)) {
	t.Helper()
	if !t.Run(name, f) {
		t.FailNow()
	}
}

type bearer struct {
	tok  string
	base http.RoundTripper
}

func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(r)
}

// startPTY runs cmd on a pseudo-terminal, as an agent's interactive shell
// would. It returns the output so far and a wait function.
func startPTY(t *testing.T, cmd *exec.Cmd) (func() string, func(time.Duration) int) {
	t.Helper()
	f, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var buf bytes.Buffer
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		b := make([]byte, 4096)
		for {
			n, err := f.Read(b)
			mu.Lock()
			buf.Write(b[:n])
			mu.Unlock()
			if err != nil {
				if err != io.EOF {
					return
				}
				return
			}
		}
	}()
	out := func() string { mu.Lock(); defer mu.Unlock(); return buf.String() }
	wait := func(d time.Duration) int {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			f.Close()
			<-copied
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			if err != nil {
				return -1
			}
			return 0
		case <-time.After(d):
			cmd.Process.Kill()
			t.Fatalf("interactive command did not end within %v; output %q", d, out())
			return -1
		}
	}
	return out, wait
}
