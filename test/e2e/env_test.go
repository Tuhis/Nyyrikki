//go:build e2e

// Package e2e runs Nyyrikki end to end (docs/01 §5.8, layer 3; docs/04 PT5):
// a kind cluster running Kubernetes 1.35 with nyyrikkid installed from its
// chart, Keycloak 26.8 as the authorization server, a fake Telegram Bot API
// driven by the test as the approver, and the real CLI binary as the agent.
//
//	go test -tags e2e -timeout 30m -v ./test/e2e/
//
// It needs docker, kind, helm and kubectl on PATH, and a Linux host from
// which the docker network's addresses are reachable.
package e2e

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
	"github.com/Tuhis/Nyyrikki/test/stack"
)

// The stack (test/stack) is shared with the local quickstart
// (dev/quickstart, docs/09 D6), so the e2e keeps it working. What is the
// e2e's own stays here: the fake Bot API, the workload, the SSH host.
const (
	clusterName = "nyyrikki-e2e"
	fakebotName = "nyyrikki-e2e-fakebot"
	// The stack's docker network: its name is the cluster's.
	networkName   = clusterName
	networkSubnet = "10.231.0.0/24"
	networkPrefix = "10.231.0"
	distroless    = "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
	busyboxImage  = "busybox:1.36"
	namespace     = stack.Namespace
	workNS        = "e2e"
	realm         = stack.Realm
	ownerUser     = stack.OwnerUser
	ownerPassword = "owner-e2e-password"
	ownerK8sUser  = stack.OwnerK8sUser
	approverID    = 4242
	introspectSec = "e2e-introspection-secret"
	mcpClientID   = "nyyrikki-mcp-e2e"
)

// boxPod is the workload, in workNS: restricted Pod Security's demands
// (non-root, no privilege escalation, no capabilities, a seccomp
// profile) and nothing more.
const boxPod = `apiVersion: v1
kind: Pod
metadata: {name: box, namespace: %s}
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: box
      image: %s
      imagePullPolicy: Never
      command: [sleep, "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
`

// env is the running environment.
type env struct {
	st         *stack.Stack
	dir        string
	kubeconfig string
	nodeIP     string
	issuer     string
	canonical  string
	caFile     string // trusts Keycloak, nyyrikkid and the fake Bot API
	caPool     *x509.CertPool
	cli        string // the nyyrikki binary
	tg         *fakeBot
	ownerID    string // the owner's Keycloak user ID (the token sub)
	root       string // the checkout
	values     string // the chart values installed
	ssh        *sshEnv
}

func run(t testing.TB, name string, args ...string) string {
	t.Helper()
	out, err := stack.Run(name, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) kubectl(t testing.TB, args ...string) string {
	t.Helper()
	return run(t, "kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...)
}

// must fails the test on err.
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// setup builds the whole environment. It is torn down when the test ends,
// unless NYYRIKKI_E2E_KEEP is set.
func setup(t *testing.T) *env {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := stack.Config{
		Name: clusterName, Subnet: networkSubnet, Dir: dir, Root: root, ImageTag: "e2e",
		OwnerPassword: ownerPassword, KeycloakAdminPassword: "admin", IntrospectionSecret: introspectSec,
		// The human's rights: edit in the workload's namespace, and
		// nowhere else (checkHumanRights).
		OwnerNamespaces: []string{workNS},
		ExtraContainers: []string{fakebotName},
		Logf:            t.Logf,
	}

	// During setup, a Ctrl-C or SIGTERM ends the running stack step, with
	// its process group, and so fails the setup; the cleanups then remove
	// the stack (go test waits for them). Without this, the steps' own
	// process groups would keep running after the test binary died, and
	// the stack would stay up. After setup, signals act as they did:
	// stop restores the default, and the stack's context is cleared,
	// since stop also cancels it.
	sigCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	cfg.Context = sigCtx
	var st *stack.Stack
	defer func() {
		stopSignals()
		if st != nil {
			st.Context = nil
		}
	}()

	// The network, the cluster on it, the CA and Keycloak.
	if os.Getenv("NYYRIKKI_E2E_KEEP") == "" {
		t.Cleanup(func() { stack.Teardown(cfg) })
	}
	st, err = stack.Create(cfg)
	must(t, err)
	e := &env{st: st, dir: dir, root: root, kubeconfig: st.Kubeconfig, nodeIP: st.NodeIP, issuer: st.Issuer,
		canonical: st.Canonical, caFile: st.CAFile, caPool: st.CAPool}

	// The fake Bot API, also on the stack's network: a container can
	// reach another container, but a host firewall may stop it reaching
	// the host.
	botIP := networkPrefix + ".251"
	tgCert, tgKey, err := st.CA.Issue(botIP)
	must(t, err)
	botDir := filepath.Join(e.dir, "fakebot")
	os.MkdirAll(botDir, 0o755)
	writeFileMode(t, botDir, "tls.crt", tgCert, 0o644)
	writeFileMode(t, botDir, "tls.key", tgKey, 0o644)
	bb := exec.Command("go", "build", "-tags", "e2e", "-o", filepath.Join(botDir, "fakebot"), "./test/e2e/fakebot")
	bb.Dir = root
	bb.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := bb.CombinedOutput(); err != nil {
		t.Fatalf("build fakebot: %v\n%s", err, out)
	}
	os.Chmod(filepath.Join(botDir, "fakebot"), 0o755)
	run(t, "docker", "run", "-d", "--name", fakebotName, "--network", networkName, "--ip", botIP,
		"-v", botDir+":/app:ro", distroless, "/app/fakebot", "-cert", "/app/tls.crt", "-key", "/app/tls.key")
	e.tg = &fakeBot{api: "https://" + botIP + ":8443", control: "http://" + botIP + ":9000"}

	// The image and the CLI, built from this checkout.
	must(t, st.BuildImage())
	// busybox is pulled here, for the node's platform, and imported as an
	// archive: kind load docker-image can't import multi-platform images,
	// and the node pulling it itself failed on CI runners whose network's
	// DNS misbehaved ("lookup registry-1.docker.io on 10.231.0.1:53:
	// server misbehaving", #50).
	platform := "linux/" + runtime.GOARCH
	run(t, "docker", "pull", "-q", "--platform", platform, busyboxImage)
	bbTar := filepath.Join(e.dir, "busybox.tar")
	if out, err := exec.Command("docker", "save", "--platform", platform, "-o", bbTar, busyboxImage).CombinedOutput(); err != nil {
		// Older Docker has no save --platform; the pull above already
		// chose the platform.
		t.Logf("docker save --platform: %v %s; saving without it", err, out)
		run(t, "docker", "save", "-o", bbTar, busyboxImage)
	}
	run(t, "kind", "load", "image-archive", bbTar, "--name", clusterName)
	must(t, st.BuildCLI())
	e.cli = st.CLI

	// Stands in for an MCP harness's own registration (Bearer, keyed by sid).
	must(t, st.ConfigureKeycloak(stack.DeviceClient(mcpClientID, false)))
	e.ownerID = st.OwnerID

	// The cluster side: Nyyrikki's namespace, Secrets and NodePort, the
	// human's own rights, and a workload.
	must(t, st.PrepareCluster([]byte(telegramtest.DefaultToken)))
	// The namespace's default ServiceAccount is made by a controller after
	// the namespace; a pod created before it is refused. On a busy runner
	// that gap was long enough to fail the setup (2026-10-30).
	e.kubectl(t, "-n", workNS, "wait", "--for=create", "serviceaccount/default", "--timeout=120s")
	// The workload, fit for the restricted Pod Security its namespace
	// enforces: busybox runs as nobody.
	box := exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "apply", "-f", "-")
	box.Stdin = strings.NewReader(fmt.Sprintf(boxPod, workNS, busyboxImage))
	if out, err := box.CombinedOutput(); err != nil {
		t.Fatalf("the workload pod: %v\n%s", err, out)
	}

	t.Cleanup(func() {
		if t.Failed() {
			// The workload pod, and the node's state: box timing out at
			// Ready showed nothing of why (#50).
			t.Log(st.Diagnostics(
				[]string{"-n", workNS, "describe", "pods"},
				[]string{"get", "events", "-A", "--sort-by=.lastTimestamp"},
				[]string{"describe", "nodes"},
			))
		}
	})
	e.ssh = e.setupSSH(t)
	e.values = st.Values(stack.Values{
		ApproverID: approverID, TelegramAPI: e.tg.api, ApprovalTimeout: "2m",
		Extra: e.ssh.values(e.nodeIP, nil),
	})
	must(t, st.Install(e.values, true))
	e.kubectl(t, "-n", workNS, "wait", "--for=condition=Ready", "pod/box", "--timeout=120s")
	e.waitCanonical(t)
	return e
}

// waitCanonical waits until the canonical URL answers.
func (e *env) waitCanonical(t *testing.T) {
	t.Helper()
	must(t, e.st.WaitCanonical(90*time.Second))
}

// httpClient trusts the test CA and follows no redirect unless told to.
func (e *env) httpClient() *http.Client { return e.st.HTTPClient() }

func (e *env) admin(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	out, err := e.st.Admin(method, path, body)
	must(t, err)
	return out
}

func writeFile(t testing.TB, dir, name string, b []byte) string {
	return writeFileMode(t, dir, name, b, 0o600)
}

func writeFileMode(t testing.TB, dir, name string, b []byte, mode os.FileMode) string {
	t.Helper()
	p, err := stack.WriteFile(dir, name, b, mode)
	must(t, err)
	return p
}
