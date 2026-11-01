//go:build quickstart

// Command quickstart brings up a local Nyyrikki to try, on one Linux host
// (docs/09 D6, docs/setup/quickstart.md): a kind cluster, Keycloak and
// nyyrikkid from this checkout, approving through a real Telegram bot the
// user made, and an agent pod in the cluster to run the CLI in.
// dev/quickstart.sh runs it; run that, not this.
//
//	printf '%s\n' "$token" | go run -tags quickstart ./dev/quickstart up -telegram-user ID
//	go run -tags quickstart ./dev/quickstart down
//
// up reads the bot token from stdin and puts it only into the cluster's
// Secret: it is written to no file and is never printed or logged.
//
// The host is the human's machine: it holds kind's admin kubeconfig,
// which can read that Secret and is itself an admin credential for the
// target. No agent runs there (CLAUDE.md). The agent's machine is the
// pod nyyrikki-agent, which holds the CLI, the stack's CA and, once
// signed in, its own Nyyrikki login, and nothing else: no ServiceAccount
// token and no rights in the cluster.
//
// Everything up makes is named nyyrikki-quickstart or lives in that
// cluster, and down removes exactly that.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Tuhis/Nyyrikki/test/stack"
)

const (
	name = "nyyrikki-quickstart"
	// Not the e2e's 10.231.0.0/24: the two can run side by side.
	subnet = "10.232.0.0/24"
	// playNS is the one namespace where the human, and so an approved
	// request or an elevation, may change anything (stack.OwnerNamespaces).
	playNS = "quickstart"
	// The agent's pod, its namespace and its image.
	agentNS    = "nyyrikki-agent"
	agentPod   = "nyyrikki-agent"
	agentImage = "nyyrikki-agent:quickstart"
	// Where the stack's CA is in the agent pod.
	agentCA = "/etc/nyyrikki/ca.crt"
	// The agent image's base: a shell, for dev/quickstart.sh agent.
	agentBase = "busybox:1.36"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = up(os.Args[2:])
	case "down":
		err = down()
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "quickstart:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dev/quickstart.sh up|agent|down")
	os.Exit(2)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "== "+format+"\n", args...)
}

// paths are the checkout and the state directory in it.
func paths() (root, state string, err error) {
	root, err = os.Getwd()
	if err != nil {
		return "", "", err
	}
	if _, err := os.Stat(filepath.Join(root, "deploy", "chart", "nyyrikki")); err != nil {
		return "", "", errors.New("run from the checkout's root (dev/quickstart.sh does)")
	}
	return root, filepath.Join(root, "dev", ".quickstart"), nil
}

func config(root, state string) stack.Config {
	return stack.Config{Name: name, Subnet: subnet, Dir: state, Root: root, ImageTag: "quickstart",
		OwnerNamespaces: []string{playNS}, CertValidity: 30 * 24 * time.Hour, Logf: logf}
}

// tokenRE is the shape of a Bot API token: the bot's ID, a colon, a secret.
var tokenRE = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]{30,}$`)

// readToken reads the bot token from stdin, where dev/quickstart.sh puts
// it.
func readToken() (string, error) {
	if fi, err := os.Stdin.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return "", errors.New("the bot token is read from stdin; run dev/quickstart.sh up")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", errors.New("no bot token on stdin")
	}
	token := strings.TrimSpace(line)
	// The token is never part of an error or a log line.
	if !tokenRE.MatchString(token) {
		return "", errors.New("that doesn't look like a bot token (BotFather gives one like 123456789:AA…)")
	}
	return token, nil
}

func up(args []string) (err error) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	approver := fs.Int64("telegram-user", 0, "the approver's Telegram user ID (docs/setup/telegram.md)")
	checkBot := fs.Bool("check-bot", true, "ask Telegram whether the bot token is valid before building anything")
	fs.Parse(args)
	if *approver <= 0 {
		return errors.New("-telegram-user must be your Telegram user ID, a positive number (docs/setup/telegram.md)")
	}
	root, state, err := paths()
	if err != nil {
		return err
	}
	if out, _ := exec.Command("kind", "get", "clusters").Output(); strings.Contains("\n"+string(out), "\n"+name+"\n") {
		return errors.New("a quickstart is already up; remove it with dev/quickstart.sh down first")
	}
	token, err := readToken()
	if err != nil {
		return err
	}
	cfg := config(root, state)
	var s *stack.Stack
	// Whatever fails from here on, nothing stays behind, unless asked to
	// keep it for a look.
	defer func() {
		if err == nil {
			return
		}
		if s != nil && s.Kubeconfig != "" {
			fmt.Fprintln(os.Stderr, s.Diagnostics())
		}
		if os.Getenv("NYYRIKKI_QUICKSTART_KEEP") != "" {
			fmt.Fprintln(os.Stderr, "NYYRIKKI_QUICKSTART_KEEP is set: left in place. Remove it with dev/quickstart.sh down.")
			return
		}
		logf("removing what was made")
		cleanup(cfg)
	}()
	bot := ""
	if *checkBot {
		if bot, err = getMe(token); err != nil {
			return err
		}
		logf("Telegram knows the token: bot @%s", bot)
	}

	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(state, 0o700); err != nil {
		return err
	}
	if cfg.OwnerPassword, err = secret(state, "owner-password"); err != nil {
		return err
	}
	if cfg.KeycloakAdminPassword, err = secret(state, "keycloak-admin-password"); err != nil {
		return err
	}
	if cfg.IntrospectionSecret, err = randomString(); err != nil {
		return err
	}

	if s, err = build(cfg, []byte(token), *approver); err != nil {
		return err
	}
	info := instructions(s, root, *approver, bot)
	if _, err := stack.WriteFile(state, "info.txt", []byte(info), 0o600); err != nil {
		return err
	}
	fmt.Print(info)
	return nil
}

// build makes the stack; on an error the caller tears it down.
func build(cfg stack.Config, token []byte, approver int64) (*stack.Stack, error) {
	s, err := stack.Create(cfg)
	if err != nil {
		return s, err
	}
	for _, step := range []func() error{
		s.BuildImage,
		s.BuildCLI,
		func() error { return s.ConfigureKeycloak() },
		func() error { return s.PrepareCluster(token) },
		// The chart's default Bot API URL is the real one.
		func() error { return s.Install(s.Values(stack.Values{ApproverID: approver}), false) },
		func() error { return startAgent(s) },
		func() error { return waitReady(s) },
		func() error { return s.WaitCanonical(90 * time.Second) },
		func() error { return checkAgent(s) },
	} {
		if err := step(); err != nil {
			return s, err
		}
	}
	return s, nil
}

// agentDockerfile is the agent's image: a shell and the CLI.
const agentDockerfile = `FROM ` + agentBase + `
COPY nyyrikki /usr/local/bin/nyyrikki
USER 65532:65532
`

// agentManifest is the agent's machine: a pod with the CLI and the
// stack's CA, no ServiceAccount token and no rights in the cluster. Its
// home is an emptyDir, so its login lasts as long as the pod.
const agentManifest = `apiVersion: v1
kind: Namespace
metadata: {name: ` + agentNS + `}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: ` + agentPod + `, namespace: ` + agentNS + `}
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata: {name: ` + agentPod + `, namespace: ` + agentNS + `}
spec:
  serviceAccountName: ` + agentPod + `
  automountServiceAccountToken: false
  enableServiceLinks: false
  terminationGracePeriodSeconds: 2
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: agent
      image: ` + agentImage + `
      imagePullPolicy: Never
      command: [sh, -c, "trap 'exit 0' TERM; while :; do sleep 3600 & wait; done"]
      env: [{name: HOME, value: /home/agent}]
      workingDir: /home/agent
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
      volumeMounts:
        - {name: home, mountPath: /home/agent}
        - {name: tmp, mountPath: /tmp}
        - {name: ca, mountPath: /etc/nyyrikki, readOnly: true}
  volumes:
    - {name: home, emptyDir: {}}
    - {name: tmp, emptyDir: {}}
    - {name: ca, configMap: {name: ` + stack.CAConfigMap + `}}
`

// startAgent builds the agent's image from the CLI that BuildCLI made,
// and starts its pod.
func startAgent(s *stack.Stack) error {
	logf("starting the agent pod %s/%s", agentNS, agentPod)
	ctx := filepath.Join(s.Dir, "agent-image")
	if err := os.MkdirAll(ctx, 0o700); err != nil {
		return err
	}
	b, err := os.ReadFile(s.CLI)
	if err != nil {
		return err
	}
	if _, err := stack.WriteFile(ctx, "nyyrikki", b, 0o755); err != nil {
		return err
	}
	if _, err := stack.WriteFile(ctx, "Dockerfile", []byte(agentDockerfile), 0o644); err != nil {
		return err
	}
	if _, err := stack.Run("docker", "build", "-q", "-t", agentImage, ctx); err != nil {
		return err
	}
	if _, err := stack.Run("kind", "load", "docker-image", agentImage, "--name", s.Cluster()); err != nil {
		return err
	}
	mf, err := stack.WriteFile(s.Dir, "agent.yaml", []byte(agentManifest), 0o600)
	if err != nil {
		return err
	}
	if _, err := s.Kubectl("apply", "-f", mf); err != nil {
		return err
	}
	// The CA, in the agent's namespace; the CLI is told of it at login.
	if _, err := s.Kubectl("-n", agentNS, "create", "configmap", stack.CAConfigMap, "--from-file=ca.crt="+s.CAFile); err != nil {
		return err
	}
	_, err = s.Kubectl("-n", agentNS, "wait", "--for=condition=Ready", "pod/"+agentPod, "--timeout=120s")
	return err
}

// checkAgent checks that the agent's pod reaches nyyrikkid's canonical
// URL and Keycloak's issuer, both addresses on the docker network. It
// checks the route only: busybox's TLS can't talk to the stack's ECDSA
// certificates, and the CLI checks them at login.
func checkAgent(s *stack.Stack) error {
	logf("checking that the agent pod reaches Nyyrikki and Keycloak")
	for _, raw := range []string{s.Canonical, s.Issuer} {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		if _, err := s.Kubectl("-n", agentNS, "exec", agentPod, "--", "nc", "-z", "-w", "10", u.Hostname(), u.Port()); err != nil {
			return fmt.Errorf("the agent pod can't reach %s: %v", u.Host, err)
		}
	}
	return nil
}

// waitReady waits for nyyrikkid to be ready. Ready means its Telegram
// poller runs; a token Telegram refuses, or a second program polling the
// same bot, stops the poller for good (docs/05 D2) and nyyrikkid never
// becomes ready, so that is reported at once.
func waitReady(s *stack.Stack) error {
	logf("waiting for nyyrikkid to be ready (it polls Telegram)")
	deadline := time.Now().Add(3 * time.Minute)
	for {
		out, _ := s.Kubectl("-n", stack.Namespace, "get", "deploy", stack.Deployment, "-o", "jsonpath={.status.readyReplicas}")
		if strings.TrimSpace(out) == "1" {
			return nil
		}
		logs, _ := s.Kubectl("-n", stack.Namespace, "logs", "deploy/"+stack.Deployment, "--tail=200")
		if strings.Contains(logs, "telegram poller stopped") {
			return errors.New("nyyrikkid stopped polling Telegram: Telegram refused the bot token, or another program polls the same bot (only one may)")
		}
		if time.Now().After(deadline) {
			return errors.New("nyyrikkid did not become ready within 3 minutes")
		}
		time.Sleep(3 * time.Second)
	}
}

// getMe asks Telegram whether token is a bot's, and returns its username.
// getMe reads no updates, so it takes none away from nyyrikkid.
func getMe(token string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.telegram.org/bot"+token+"/getMe", nil)
	if err != nil {
		return "", errors.New("could not build the getMe request")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// A *url.Error carries the URL, which carries the token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("could not reach api.telegram.org, which nyyrikkid needs too: %v", err)
	}
	defer resp.Body.Close()
	var r struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("the bot token was refused by Telegram (%s): check it, or make a new bot with @BotFather", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !r.OK {
		return "", fmt.Errorf("getMe at Telegram answered %s", resp.Status)
	}
	return r.Result.Username, nil
}

// secret makes a random password and keeps it in state/name, 0600.
func secret(state, name string) (string, error) {
	s, err := randomString()
	if err != nil {
		return "", err
	}
	_, err = stack.WriteFile(state, name, []byte(s+"\n"), 0o600)
	return s, err
}

func randomString() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func instructions(s *stack.Stack, root string, approver int64, bot string) string {
	rel := func(p string) string {
		if r, err := filepath.Rel(root, p); err == nil {
			return r
		}
		return p
	}
	botName := "your bot"
	if bot != "" {
		botName = "@" + bot
	}
	return fmt.Sprintf(`
Nyyrikki is up. This is a stack for trying Nyyrikki, with Keycloak in
development mode. Use a throwaway bot, never the bot of a real
deployment.

  Nyyrikki   %s
  Keycloak   %s (realm %s)
  Approver   Telegram user %d, through %s

THIS MACHINE IS THE HUMAN'S. It holds kind's admin kubeconfig
(%s), which can read the bot token's Secret and
administers the target. Run no AI agent on it while the quickstart is
up. The agent's machine is the pod %s/%s, which holds
only the CLI and, once signed in, its own login.

1. In Telegram, send /start to %s. It answers with your user ID,
   which shows that Nyyrikki is polling. Nyyrikki can only write to you
   once you have written to the bot.

2. Open the agent's shell, and sign in from it:

     dev/quickstart.sh agent
     nyyrikki login --server %s --ca-file %s

   It prints a URL and a code. Open the URL in a browser on this
   machine, accept the warning about the certificate (the stack's own
   CA, %s), and sign in as the human:

     user      %s
     password  %s

3. In the agent's shell, list the targets and make a first request:

     nyyrikki targets
     nyyrikki run --reason "first try" %s -- auth whoami

   The run waits for you: Telegram shows you the request as it will be
   forwarded, and the agent's reason as its claim. Tap Approve, and it
   prints %s, the user it ran as on the cluster. Deny,
   and it exits with 77.

   That user may change things only in the namespace %s, where
   Pod Security forbids privileged pods: try
     nyyrikki run --reason "a write" %s -- create configmap hello -n %s --from-literal=greeting=hi
   Nyyrikki's own namespace and the rest of the cluster are out of its
   reach, and so out of any request's or elevation's.

To try an AI agent, run it in the agent's shell, or on another machine
that holds nothing but its Nyyrikki login (docs/setup/agents.md).

The admin console is %s/admin/, user admin, password in
%s.
This is kept in %s.
Remove everything with dev/quickstart.sh down, then delete the bot.
`,
		s.Canonical, s.KeycloakBase(), stack.Realm, approver, botName,
		rel(s.Kubeconfig), agentNS, agentPod,
		botName,
		s.Canonical, agentCA,
		rel(s.CAFile),
		stack.OwnerUser, s.OwnerPassword,
		stack.Target,
		stack.OwnerK8sUser,
		playNS, stack.Target, playNS,
		s.KeycloakBase(), rel(filepath.Join(s.Dir, "keycloak-admin-password")),
		rel(filepath.Join(s.Dir, "info.txt")))
}

// cleanup removes the stack (the agent pod with the cluster), its images
// and the state directory.
func cleanup(cfg stack.Config) {
	stack.Teardown(cfg)
	exec.Command("docker", "image", "rm", "-f", cfg.Image(), agentImage).Run()
	os.RemoveAll(cfg.Dir)
}

func down() error {
	root, state, err := paths()
	if err != nil {
		return err
	}
	cfg := config(root, state)
	logf("removing the kind cluster (with the agent pod), Keycloak, the docker network, the images and %s", filepath.Join("dev", ".quickstart"))
	cleanup(cfg)
	// Say what is left, if anything: nothing should be.
	var left []string
	if out, _ := exec.Command("kind", "get", "clusters").Output(); strings.Contains("\n"+string(out), "\n"+name+"\n") {
		left = append(left, "kind cluster "+name)
	}
	if out, _ := exec.Command("docker", "ps", "-aq", "--filter", "name=^"+name).Output(); strings.TrimSpace(string(out)) != "" {
		left = append(left, "containers named "+name+"*")
	}
	if exec.Command("docker", "network", "inspect", cfg.Network()).Run() == nil {
		left = append(left, "docker network "+cfg.Network())
	}
	for _, img := range []string{cfg.Image(), agentImage} {
		if exec.Command("docker", "image", "inspect", img).Run() == nil {
			left = append(left, "image "+img)
		}
	}
	if _, err := os.Stat(state); err == nil {
		left = append(left, state)
	}
	if len(left) > 0 {
		return fmt.Errorf("could not remove: %s", strings.Join(left, ", "))
	}
	logf("removed")
	return nil
}
