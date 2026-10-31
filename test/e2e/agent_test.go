//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

// approveDevice plays the human's part of the device grant: it opens the
// verification URL, signs in as the owner and accepts, like a browser.
func (e *env) approveDevice(t *testing.T, verificationURL string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := e.httpClient()
	hc.Jar = jar
	resp, err := hc.Get(verificationURL)
	if err != nil {
		t.Fatal(err)
	}
	formRE := regexp.MustCompile(`(?s)<form[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	for step := 0; step < 6; step++ {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		page := string(body)
		if strings.Contains(page, "Device Login Successful") || strings.Contains(page, "device-login-success") ||
			strings.Contains(strings.ToLower(page), "you may now close") {
			return
		}
		m := formRE.FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("device approval: no form in page (status %d):\n%.2000s", resp.StatusCode, page)
		}
		// Actions may be relative to the page they are on.
		ref, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		action := resp.Request.URL.ResolveReference(ref).String()
		form := url.Values{}
		switch {
		case strings.Contains(m[2], `name="username"`):
			form.Set("username", ownerUser)
			form.Set("password", ownerPassword)
			form.Set("credentialId", "")
		case strings.Contains(m[2], `name="device_user_code"`):
			um := regexp.MustCompile(`name="device_user_code"[^>]*value="([^"]*)"`).FindStringSubmatch(m[2])
			if um != nil {
				form.Set("device_user_code", um[1])
			}
		default:
			form.Set("accept", "Yes")
		}
		resp, err = hc.PostForm(action, form)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("device approval did not finish")
}

// cli runs the nyyrikki binary as an agent with its own home.
type cli struct {
	e    *env
	home string
	env  []string
}

func (e *env) newCLI(t *testing.T) *cli {
	home := t.TempDir()
	return &cli{e: e, home: home, env: []string{
		"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "PATH=" + os.Getenv("PATH"),
	}}
}

func (c *cli) cmd(args ...string) *exec.Cmd {
	cmd := exec.Command(c.e.cli, args...)
	cmd.Env = c.env
	return cmd
}

// login runs `nyyrikki login`, approves the device code it prints, and
// returns what it printed.
func (c *cli) login(t *testing.T, extra ...string) []string {
	t.Helper()
	cmd := c.cmd(append([]string{"login", "--server", c.e.canonical, "--ca-file", c.e.caFile}, extra...)...)
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(stderr)
	var lines []string
	approved := false
	for sc.Scan() {
		line := sc.Text()
		lines = append(lines, line)
		if !approved && strings.Contains(line, "or open ") {
			u := strings.TrimSpace(line[strings.Index(line, "or open ")+len("or open "):])
			c.e.approveDevice(t, u)
			approved = true
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("login: %v\n%s", err, strings.Join(lines, "\n"))
	}
	return lines
}

type result struct {
	code           int
	stdout, stderr string
}

func (c *cli) run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	return c.runEnv(t, nil, stdin, args...)
}

// runEnv is run with extra environment variables (an elevation handle).
func (c *cli) runEnv(t *testing.T, extra []string, stdin string, args ...string) result {
	t.Helper()
	cmd := c.cmd(args...)
	cmd.Env = append(append([]string{}, c.env...), extra...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{code, so.String(), se.String()}
}

// async runs the CLI in the background.
func (c *cli) async(t *testing.T, args ...string) chan result {
	return c.asyncEnv(t, nil, args...)
}

func (c *cli) asyncEnv(t *testing.T, extra []string, args ...string) chan result {
	ch := make(chan result, 1)
	go func() { ch <- c.runEnv(t, extra, "", args...) }()
	return ch
}

// tap waits for the n-th prompt (1-based) and taps button on it as the
// approver, retrying while the bot hasn't stored the prompt's keys yet.
func (e *env) tap(t *testing.T, n int, button string) telegramtest.Message {
	t.Helper()
	m, _ := e.tapAt(t, n, button)
	return m
}

// tapAt is tap, also returning when the tap that counted was sent: the
// server can't have acted on it before then.
func (e *env) tapAt(t *testing.T, n int, button string) (telegramtest.Message, time.Time) {
	t.Helper()
	return e.tapUnless(t, n, button, nil)
}

// tapUnless is tapAt for a request running in the background: every
// caller expects a prompt first, so a result that arrives before the tap
// counted, a refusal or an error, fails the test with that result rather
// than with "prompt n never arrived".
func (e *env) tapUnless(t *testing.T, n int, button string, early func() (any, bool)) (telegramtest.Message, time.Time) {
	t.Helper()
	if early == nil {
		early = func() (any, bool) { return nil, false }
	}
	finished := func() {
		t.Helper()
		if r, ok := early(); ok {
			t.Fatalf("waiting to tap %q on prompt %d: the request finished first: %+v", button, n, r)
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	for len(e.tg.Sent(t)) < n {
		finished()
		if time.Now().After(deadline) {
			t.Fatalf("prompt %d never arrived", n)
		}
		time.Sleep(200 * time.Millisecond)
	}
	m := e.tg.Sent(t)[n-1]
	for try := 0; try < 20; try++ {
		finished()
		cur := e.tg.Message(t, m)
		if _, ok := cur.Button(button); !ok {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		sent := time.Now()
		if e.tg.Tap(t, cur, button) != "No longer valid" {
			return cur, sent
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("tap %q on prompt %d never counted", button, n)
	return telegramtest.Message{}, time.Time{}
}

// pending is a request running in the background, sending its one result
// on a channel buffered for it.
type pending[T any] struct {
	ch  chan T
	got *T
}

// peek returns the result if it has arrived, without waiting.
func (p *pending[T]) peek() (any, bool) {
	if p.got == nil {
		select {
		case v := <-p.ch:
			p.got = &v
		default:
			return nil, false
		}
	}
	return *p.got, true
}

// wait waits for the result for at most d.
func (p *pending[T]) wait(t *testing.T, d time.Duration) T {
	t.Helper()
	if p.got == nil {
		select {
		case v := <-p.ch:
			p.got = &v
		case <-time.After(d):
			t.Fatalf("the request didn't finish within %v", d)
		}
	}
	return *p.got
}

func get(t *testing.T, ch chan result, within time.Duration) result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(within):
		t.Fatalf("command did not finish within %v", within)
		return result{}
	}
}

// deviceToken runs the device grant for a public client without DPoP, as an
// MCP harness signed in through its own registration would, and returns the
// access token.
func (e *env) deviceToken(t *testing.T, clientID string) string {
	t.Helper()
	hc := e.httpClient()
	resp, err := hc.PostForm(e.issuer+"/protocol/openid-connect/auth/device", url.Values{"client_id": {clientID}, "scope": {"nyyrikki"}})
	if err != nil {
		t.Fatal(err)
	}
	var da struct {
		DeviceCode string `json:"device_code"`
		Complete   string `json:"verification_uri_complete"`
	}
	json.NewDecoder(resp.Body).Decode(&da)
	resp.Body.Close()
	e.approveDevice(t, da.Complete)
	for i := 0; i < 30; i++ {
		resp, err := hc.PostForm(e.issuer+"/protocol/openid-connect/token", url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {da.DeviceCode}, "client_id": {clientID},
		})
		if err != nil {
			t.Fatal(err)
		}
		var tr struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&tr)
		resp.Body.Close()
		if tr.AccessToken != "" {
			return tr.AccessToken
		}
		time.Sleep(time.Second)
	}
	t.Fatal("device token never issued")
	return ""
}

// claims decodes a JWT's payload without checking it (for recording what
// Keycloak puts in its tokens: docs/01 M9).
func claims(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return nil
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func loginFile(c *cli) map[string]any {
	b, _ := os.ReadFile(filepath.Join(c.home, ".config", "nyyrikki", "login.json"))
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

// fakeBot drives the fake Bot API container through its control API.
type fakeBot struct {
	api, control string
}

func (b *fakeBot) getJSON(t *testing.T, path string, v any) bool {
	t.Helper()
	resp, err := http.Get(b.control + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
	return true
}

func (b *fakeBot) Sent(t *testing.T) []telegramtest.Message {
	var m []telegramtest.Message
	b.getJSON(t, "/sent", &m)
	return m
}

func (b *fakeBot) Message(t *testing.T, m telegramtest.Message) telegramtest.Message {
	var cur telegramtest.Message
	b.getJSON(t, fmt.Sprintf("/message?chat=%d&id=%d", m.ChatID, m.MessageID), &cur)
	return cur
}

// Tap pushes a tap on button of msg by the approver and returns the bot's
// answer text.
func (b *fakeBot) Tap(t *testing.T, msg telegramtest.Message, button string) string {
	t.Helper()
	btn, ok := msg.Button(button)
	if !ok {
		t.Fatalf("message %d has no %q button (has %v)", msg.MessageID, button, msg.ButtonTexts())
	}
	body, _ := json.Marshal(telegramtest.Callback{FromID: approverID, ChatID: msg.ChatID, MessageID: msg.MessageID, Data: btn.CallbackData})
	resp, err := http.Post(b.control+"/callback", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&r)
	resp.Body.Close()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var a telegramtest.Answer
		if b.getJSON(t, "/answer?id="+r.ID, &a) {
			return a.Text
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("tap %q was never answered", button)
	return ""
}
