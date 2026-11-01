//go:build e2e || quickstart

// Package stack builds a local Nyyrikki stack on one Linux host: a docker
// network of its own, a kind cluster on it, Keycloak with the realm
// docs/setup/keycloak.md describes, one CA for every TLS endpoint, the
// image and the CLI built from the checkout, the Secrets, and the chart.
//
// Two callers share it, so that the e2e keeps the quickstart working
// (docs/09 D6, §5.6): the end-to-end test (test/e2e), which points
// nyyrikkid at its fake Bot API, and the local quickstart
// (dev/quickstart), which points it at the real one with the user's bot.
//
// It is built only with the e2e or quickstart tag. No product binary is
// built with either, so nothing here can reach the image or the CLI: an
// import of it from cmd/ fails to compile.
//
// Everything a stack makes is named after Config.Name, and Teardown
// removes by those names only, so two stacks with different names (the
// e2e's and the quickstart's) can't remove each other.
package stack

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	// KeycloakImage is the authorization server the stack runs.
	KeycloakImage = "quay.io/keycloak/keycloak:26.8.1"
	// Namespace is nyyrikkid's namespace and Release its Helm release.
	Namespace = "nyyrikki"
	Release   = "nyyrikki"
	// Deployment is the chart's Deployment for Release.
	Deployment = Release + "-nyyrikki"
	// NodePort serves the canonical URL on the kind node's address.
	NodePort = 30443
	// Realm is the Keycloak realm.
	Realm = "nyyrikki"
	// OwnerUser is the human's Keycloak user name, and OwnerK8sUser who
	// the requests run as on the cluster.
	OwnerUser    = "owner"
	OwnerK8sUser = "owner@example.com"
	// CLIClientID is the CLI's public, DPoP-bound client.
	CLIClientID = "nyyrikki-cli"
	// Target is the in-cluster target's name.
	Target = "this-cluster"
	// CAConfigMap holds the stack's CA for nyyrikkid (trustedCA).
	CAConfigMap = "stack-ca"
)

// Config names and parameterises a stack.
type Config struct {
	// Name names the kind cluster and the docker network, and prefixes
	// every container.
	Name string
	// Subnet is the docker network's, a /24 such as "10.231.0.0/24". A
	// network with a configured subnet is needed for docker to pin a
	// container's address (--ip); the network kind makes for itself may
	// not have one (it doesn't on GitHub's runners).
	Subnet string
	// Dir holds the stack's files: the kubeconfig, the CA, the
	// certificates, the CLI. Keycloak's certificate is bind-mounted from
	// it.
	Dir string
	// Root is the checkout the image, the CLI and the chart come from.
	Root string
	// ImageTag tags the image as nyyrikki:ImageTag.
	ImageTag string
	// OwnerPassword is the Keycloak user's password.
	OwnerPassword string
	// KeycloakAdminPassword is the master realm's admin password.
	KeycloakAdminPassword string
	// IntrospectionSecret is nyyrikkid's client secret at Keycloak.
	IntrospectionSecret string
	// CertValidity is how long the CA and certificates are valid.
	CertValidity time.Duration
	// OwnerNamespaces are the only places the human has rights in the
	// cluster, and so the only places a request approved one-off or
	// covered by an elevation can change anything. PrepareCluster makes
	// each, binds the human to the ClusterRole edit there, and labels it
	// for restricted Pod Security, so no pod in it can be privileged or
	// mount the node (root on the host, since kind's nodes are privileged
	// containers). Nyyrikki's own namespace is refused: SECURITY.md
	// (Accepted risks) and docs/06 §6 give the human no write and no
	// Secret read there, and nothing cluster-wide.
	OwnerNamespaces []string
	// ExtraContainers are the caller's own containers on the network,
	// removed by Teardown before the network.
	ExtraContainers []string
	// Logf reports progress.
	Logf func(format string, args ...any)
	// Context, if set, ends the stack's commands and waits when it is
	// done (the quickstart's Ctrl-C). Teardown ignores it.
	Context context.Context
}

func (c Config) ctx() context.Context {
	if c.Context != nil {
		return c.Context
	}
	return context.Background()
}

// sleep waits for d, or less if the config's context ends.
func (c Config) sleep(d time.Duration) error {
	select {
	case <-c.ctx().Done():
		return c.ctx().Err()
	case <-time.After(d):
		return nil
	}
}

// Network is the docker network's name.
func (c Config) Network() string { return c.Name }

// Cluster is the kind cluster's name.
func (c Config) Cluster() string { return c.Name }

// KeycloakContainer is Keycloak's container name.
func (c Config) KeycloakContainer() string { return c.Name + "-keycloak" }

// Prefix is the subnet's first three octets ("10.231.0").
func (c Config) Prefix() string {
	ip := strings.SplitN(c.Subnet, "/", 2)[0]
	return ip[:strings.LastIndex(ip, ".")]
}

// Image is the image reference the stack builds and installs.
func (c Config) Image() string { return "nyyrikki:" + c.ImageTag }

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Stack is a running stack.
type Stack struct {
	Config
	Kubeconfig string
	NodeIP     string
	GatewayIP  string
	KeycloakIP string
	Issuer     string
	Canonical  string
	CA         *CA
	CAFile     string // trusts Keycloak, nyyrikkid and anything else CA issued for
	CAPool     *x509.CertPool
	CLI        string // the nyyrikki binary, once BuildCLI ran
	OwnerID    string // the owner's Keycloak user ID (the token sub), once ConfigureKeycloak ran

	nyCert, nyKey []byte
}

// Run runs a command and returns its combined output. The error carries
// the command and its output, so neither may hold a secret.
func Run(name string, args ...string) (string, error) {
	return runEnv(context.Background(), nil, name, args...)
}

// stopGrace is how long a cancelled step's processes have, after
// SIGTERM, before they are killed.
const stopGrace = 10 * time.Second

// command is a step's command. It runs in a process group of its own, and
// when ctx ends the whole group gets SIGTERM, then SIGKILL after
// stopGrace: a step's children (kind create cluster's docker run, a
// docker build) end with it, before any cleanup runs. Being in its own
// group, it doesn't get the terminal's Ctrl-C itself; the context brings
// it. A context that never ends (Run's, the e2e's) changes nothing.
func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = stopGrace
	return cmd
}

func runEnv(ctx context.Context, env []string, name string, args ...string) (string, error) {
	cmd := command(ctx, name, args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String(), nil
}

// Exec is Run, ended when the config's context is.
func (c Config) Exec(name string, args ...string) (string, error) {
	return runEnv(c.ctx(), nil, name, args...)
}

// Kubectl runs kubectl against the stack's cluster.
func (s *Stack) Kubectl(args ...string) (string, error) {
	return runEnv(s.ctx(), nil, "kubectl", append([]string{"--kubeconfig", s.Kubeconfig}, args...)...)
}

// WriteFile writes b to dir/name with mode and returns the path.
func WriteFile(dir, name string, b []byte, mode os.FileMode) (string, error) {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		return "", err
	}
	// WriteFile keeps the mode of a file that exists.
	return p, os.Chmod(p, mode)
}

// teardownSettle is how long Teardown must see nothing of the stack
// before it believes it: docker finishes a container whose creation was
// under way when its client died. Measured 2026-11-01: kind create
// cluster ended by SIGTERM within half a second, and its node container
// appeared about four seconds later, never started.
const teardownSettle = 12 * time.Second

// kindConfig is the cluster's: the API server also runs the admission
// plugin DenyServiceExternalIPs, so that the human's edit rights can't
// make a Service with externalIPs, which would take over traffic for any
// address it names, the API server's included (CVE-2020-8554).
// NodeRestriction is kubeadm's default, kept.
const kindConfig = `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        enable-admission-plugins: NodeRestriction,DenyServiceExternalIPs
`

// Teardown removes everything a stack named cfg.Name makes, and nothing
// else. It ignores what isn't there, and cfg.Context: it is what runs
// after a Ctrl-C. It repeats until nothing of the stack has been seen for
// teardownSettle, for at most a minute and a half.
func Teardown(cfg Config) {
	start := time.Now()
	lastSeen := start
	for {
		if cfg.teardownOnce() {
			lastSeen = time.Now()
		}
		if time.Since(lastSeen) >= teardownSettle {
			return
		}
		if time.Since(start) > 90*time.Second {
			cfg.logf("could not remove all of %s; see docker ps -a and docker network ls", cfg.Name)
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// teardownOnce removes what it finds of the stack, and reports whether it
// found anything.
func (c Config) teardownOnce() bool {
	found := false
	// kind's own view: the stack's kubeconfig, so kind leaves the user's
	// (~/.kube/config, $KUBECONFIG) alone. A missing file is fine.
	if out, _ := Detached("kind", "get", "clusters").Output(); strings.Contains("\n"+string(out), "\n"+c.Cluster()+"\n") {
		found = true
		Detached("kind", "delete", "cluster", "--name", c.Cluster(), "--kubeconfig", filepath.Join(c.Dir, "kubeconfig")).Run()
	}
	if left := c.containers(); len(left) > 0 {
		found = true
		Detached("docker", append([]string{"rm", "-f"}, left...)...).Run()
	}
	if Detached("docker", "network", "inspect", c.Network()).Run() == nil {
		found = true
		Detached("docker", "network", "rm", c.Network()).Run()
	}
	return found
}

// containers lists the IDs of the stack's containers that exist: kind's
// nodes (by kind's label), Keycloak and the caller's extra ones.
func (c Config) containers() []string {
	args := []string{"ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + c.Cluster()}
	var ids []string
	add := func(out []byte) {
		ids = append(ids, strings.Fields(string(out))...)
	}
	out, _ := Detached("docker", args...).Output()
	add(out)
	for _, n := range append([]string{c.KeycloakContainer()}, c.ExtraContainers...) {
		out, _ := Detached("docker", "ps", "-aq", "--filter", "name=^/"+n+"$").Output()
		add(out)
	}
	return ids
}

// Detached is a command in a process group of its own, so that a Ctrl-C
// at the terminal doesn't reach it: for cleaning up after one.
func Detached(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// Create removes what a stack of the same name left behind, then makes
// the network, the cluster on it, the CA and the certificates, and starts
// Keycloak (ConfigureKeycloak waits for it). On an error what was made is
// left in place: the caller tears it down, or keeps it to look at.
func Create(cfg Config) (*Stack, error) {
	for _, tool := range []string{"docker", "kind", "helm", "kubectl", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("%s not on PATH", tool)
		}
	}
	if cfg.CertValidity == 0 {
		cfg.CertValidity = 24 * time.Hour
	}
	if cfg.Name == "" || cfg.Subnet == "" || cfg.Dir == "" || cfg.Root == "" || cfg.ImageTag == "" ||
		cfg.OwnerPassword == "" || cfg.KeycloakAdminPassword == "" || cfg.IntrospectionSecret == "" {
		return nil, errors.New("stack: incomplete config")
	}
	s := &Stack{Config: cfg, Kubeconfig: filepath.Join(cfg.Dir, "kubeconfig")}

	Teardown(cfg)
	cfg.logf("creating the docker network %s (%s) and the kind cluster %s", cfg.Network(), cfg.Subnet, cfg.Cluster())
	if _, err := runEnv(cfg.ctx(), nil, "docker", "network", "create", "--subnet", cfg.Subnet, cfg.Network()); err != nil {
		return s, err
	}
	kindFile, err := WriteFile(cfg.Dir, "kind.yaml", []byte(kindConfig), 0o600)
	if err != nil {
		return s, err
	}
	if _, err := runEnv(cfg.ctx(), []string{"KIND_EXPERIMENTAL_DOCKER_NETWORK=" + cfg.Network()},
		"kind", "create", "cluster", "--name", cfg.Cluster(), "--kubeconfig", s.Kubeconfig, "--config", kindFile, "--wait", "180s"); err != nil {
		return s, err
	}
	out, err := runEnv(cfg.ctx(), nil, "docker", "inspect", "-f", `{{with index .NetworkSettings.Networks "`+cfg.Network()+`"}}{{.IPAddress}} {{.Gateway}}{{end}}`, cfg.Cluster()+"-control-plane")
	if err != nil {
		return s, err
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return s, fmt.Errorf("the kind node's address on %s: %q", cfg.Network(), out)
	}
	s.NodeIP, s.GatewayIP = f[0], f[1]
	s.KeycloakIP = cfg.Prefix() + ".250"
	s.Issuer = fmt.Sprintf("https://%s:8443/realms/%s", s.KeycloakIP, Realm)
	s.Canonical = fmt.Sprintf("https://%s:%d", s.NodeIP, NodePort)
	cfg.logf("node %s, gateway %s, keycloak %s", s.NodeIP, s.GatewayIP, s.KeycloakIP)

	// One CA for every TLS endpoint.
	if s.CA, err = NewCA(cfg.Name+" CA", cfg.CertValidity); err != nil {
		return s, err
	}
	s.CAPool = x509.NewCertPool()
	s.CAPool.AddCert(s.CA.Cert)
	if s.CAFile, err = WriteFile(cfg.Dir, "ca.crt", s.CA.CertPEM, 0o644); err != nil {
		return s, err
	}
	kcCert, kcKey, err := s.CA.Issue(s.KeycloakIP)
	if err != nil {
		return s, err
	}
	if s.nyCert, s.nyKey, err = s.CA.Issue(s.NodeIP); err != nil {
		return s, err
	}

	// Keycloak, on the stack's network so the pod reaches it at the same
	// address as the host. The key is world-readable for the container's
	// user; Dir itself should not be.
	kcDir := filepath.Join(cfg.Dir, "keycloak")
	if err := os.MkdirAll(kcDir, 0o755); err != nil {
		return s, err
	}
	if _, err := WriteFile(kcDir, "tls.crt", kcCert, 0o644); err != nil {
		return s, err
	}
	if _, err := WriteFile(kcDir, "tls.key", kcKey, 0o644); err != nil {
		return s, err
	}
	cfg.logf("starting Keycloak")
	// The admin password goes in through docker's environment, not its
	// argv, which errors would print.
	if _, err := runEnv(cfg.ctx(), []string{"KC_BOOTSTRAP_ADMIN_PASSWORD=" + cfg.KeycloakAdminPassword},
		"docker", "run", "-d", "--name", cfg.KeycloakContainer(), "--network", cfg.Network(), "--ip", s.KeycloakIP,
		"-v", kcDir+":/certs:ro",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD",
		KeycloakImage, "start-dev",
		"--https-port=8443", "--http-enabled=false",
		"--https-certificate-file=/certs/tls.crt", "--https-certificate-key-file=/certs/tls.key",
		"--hostname=https://"+s.KeycloakIP+":8443"); err != nil {
		return s, err
	}
	return s, nil
}

// BuildImage builds the image from the checkout and loads it into kind.
func (s *Stack) BuildImage() error {
	s.logf("building the image %s and loading it into kind", s.Image())
	if _, err := runEnv(s.ctx(), nil, "docker", "build", "-q", "-t", s.Image(), s.Root); err != nil {
		return err
	}
	_, err := runEnv(s.ctx(), nil, "kind", "load", "docker-image", s.Image(), "--name", s.Cluster())
	return err
}

// LoadImage loads a local image into the kind cluster, for the node's
// platform, as an archive: kind load docker-image can't import a
// multi-platform image, which the containerd image store may make.
func (s *Stack) LoadImage(image string) error {
	platform := "linux/" + runtime.GOARCH
	tar := filepath.Join(s.Dir, "image.tar")
	defer os.Remove(tar)
	if _, err := runEnv(s.ctx(), nil, "docker", "save", "--platform", platform, "-o", tar, image); err != nil {
		// Older Docker has no save --platform; the image was built or
		// pulled for the platform already.
		if _, err := runEnv(s.ctx(), nil, "docker", "save", "-o", tar, image); err != nil {
			return err
		}
	}
	_, err := runEnv(s.ctx(), nil, "kind", "load", "image-archive", tar, "--name", s.Cluster())
	return err
}

// BuildCLI builds the nyyrikki binary from the checkout into Dir.
func (s *Stack) BuildCLI() error {
	s.logf("building the CLI")
	cli := filepath.Join(s.Dir, "nyyrikki")
	build := command(s.ctx(), "go", "build", "-o", cli, "./cmd/nyyrikki")
	build.Dir = s.Root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("build CLI: %v\n%s", err, out)
	}
	s.CLI = cli
	return nil
}

// PrepareCluster makes nyyrikkid's namespace, the human's own rights
// (OwnerNamespaces), nyyrikkid's Secrets, the CA ConfigMap and a NodePort for the canonical
// URL. The bot token goes to kubectl on its stdin: it is written to no
// file and is in no command line.
func (s *Stack) PrepareCluster(botToken []byte) error {
	s.logf("creating the namespace, the Secrets and the NodePort")
	sdir := filepath.Join(s.Dir, "secrets")
	if err := os.MkdirAll(sdir, 0o700); err != nil {
		return err
	}
	tlsCrt, err := WriteFile(sdir, "tls.crt", s.nyCert, 0o600)
	if err != nil {
		return err
	}
	tlsKey, err := WriteFile(sdir, "tls.key", s.nyKey, 0o600)
	if err != nil {
		return err
	}
	clientSecret, err := WriteFile(sdir, "client-secret", []byte(s.IntrospectionSecret), 0o600)
	if err != nil {
		return err
	}
	svc := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata: {name: nyyrikki-nodeport, namespace: %s}
spec:
  type: NodePort
  selector: {app.kubernetes.io/name: nyyrikki, app.kubernetes.io/instance: %s}
  ports: [{port: 8443, targetPort: https, nodePort: %d}]
`, Namespace, Release, NodePort)
	svcFile, err := WriteFile(s.Dir, "nodeport.yaml", []byte(svc), 0o600)
	if err != nil {
		return err
	}
	cmds := [][]string{{"create", "namespace", Namespace}}
	for _, ns := range s.OwnerNamespaces {
		if ns == Namespace || ns == "" {
			return fmt.Errorf("the human gets no rights in namespace %q", ns)
		}
		cmds = append(cmds,
			[]string{"create", "namespace", ns},
			[]string{"label", "namespace", ns, "pod-security.kubernetes.io/enforce=restricted", "pod-security.kubernetes.io/enforce-version=latest"},
			[]string{"-n", ns, "create", "rolebinding", "owner-edit", "--clusterrole=edit", "--user=" + OwnerK8sUser},
		)
	}
	for _, args := range append(cmds, [][]string{
		{"-n", Namespace, "create", "secret", "tls", "nyyrikki-tls", "--cert=" + tlsCrt, "--key=" + tlsKey},
		{"-n", Namespace, "create", "secret", "generic", "nyyrikki-keycloak", "--from-file=client-secret=" + clientSecret},
		{"-n", Namespace, "create", "configmap", CAConfigMap, "--from-file=ca.crt=" + s.CAFile},
		{"apply", "-f", svcFile},
	}...) {
		if _, err := s.Kubectl(args...); err != nil {
			return err
		}
	}
	tg, err := json.Marshal(map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]string{"name": "nyyrikki-telegram", "namespace": Namespace},
		"data":     map[string][]byte{"bot-token": botToken},
	})
	if err != nil {
		return err
	}
	cmd := command(s.ctx(), "kubectl", "--kubeconfig", s.Kubeconfig, "create", "-f", "-")
	cmd.Stdin = bytes.NewReader(tg)
	if out, err := cmd.CombinedOutput(); err != nil {
		// kubectl's answer names the Secret, never its data.
		return fmt.Errorf("create the Telegram Secret: %v\n%s", err, out)
	}
	return nil
}

// Values is what differs between callers in the chart values.
type Values struct {
	// ApproverID is the approver's Telegram user ID.
	ApproverID int64
	// TelegramAPI is the Bot API's URL; empty keeps the chart's default,
	// the real one.
	TelegramAPI string
	// ApprovalTimeout overrides the chart's, if set.
	ApprovalTimeout string
	// Extra is YAML placed right after the in-cluster target: more
	// targets, then any further top-level keys.
	Extra string
}

// Values renders the chart values for the stack.
func (s *Stack) Values(v Values) string {
	var b strings.Builder
	fmt.Fprintf(&b, "image: {repository: nyyrikki, tag: %s, pullPolicy: Never}\n", s.ImageTag)
	fmt.Fprintf(&b, "canonicalURL: %s\nauth: {issuer: %s}\n", s.Canonical, s.Issuer)
	if v.ApprovalTimeout != "" {
		fmt.Fprintf(&b, "approval: {timeout: %s}\n", v.ApprovalTimeout)
	}
	fmt.Fprintf(&b, `human:
  subject: %s
  kubernetes: {user: %s, groups: []}
  telegramUserID: %d
targets:
  - name: %s
    description: the kind cluster
    inCluster: true
`, s.OwnerID, OwnerK8sUser, v.ApproverID, Target)
	if v.Extra != "" {
		b.WriteString(strings.TrimSuffix(v.Extra, "\n") + "\n")
	}
	if v.TelegramAPI != "" {
		fmt.Fprintf(&b, "telegram: {apiURL: %s}\n", v.TelegramAPI)
	}
	fmt.Fprintf(&b, "trustedCA: {configMap: %s}\n", CAConfigMap)
	return b.String()
}

// Install installs the chart from the checkout with values. With wait,
// Helm waits for the pod to be ready.
func (s *Stack) Install(values string, wait bool) error {
	s.logf("installing the chart")
	vf, err := WriteFile(s.Dir, "values.yaml", []byte(values), 0o600)
	if err != nil {
		return err
	}
	args := []string{"--kubeconfig", s.Kubeconfig, "install", Release, filepath.Join(s.Root, "deploy/chart/nyyrikki"),
		"-n", Namespace, "-f", vf}
	if wait {
		args = append(args, "--wait", "--timeout", "180s")
	}
	_, err = runEnv(s.ctx(), nil, "helm", args...)
	return err
}

// WaitCanonical waits until the canonical URL answers: the pod is ready
// before the NodePort is.
func (s *Stack) WaitCanonical(within time.Duration) error {
	deadline := time.Now().Add(within)
	for {
		req, err := http.NewRequestWithContext(s.ctx(), "GET", s.Canonical+"/.well-known/oauth-protected-resource/mcp", nil)
		if err != nil {
			return err
		}
		resp, err := s.HTTPClient().Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
			err = fmt.Errorf("status %d", resp.StatusCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("canonical URL not reachable: %v", err)
		}
		if err := s.sleep(time.Second); err != nil {
			return err
		}
	}
}

// Diagnostics is what the cluster says about nyyrikkid, for a setup that
// failed. extra adds kubectl invocations of the caller's own.
func (s *Stack) Diagnostics(extra ...[]string) string {
	var b strings.Builder
	for _, args := range append([][]string{
		{"-n", Namespace, "get", "pods", "-o", "wide"},
		{"-n", Namespace, "describe", "pods"},
		{"-n", Namespace, "logs", "deploy/" + Deployment, "--tail=200"},
	}, extra...) {
		out, _ := exec.Command("kubectl", append([]string{"--kubeconfig", s.Kubeconfig}, args...)...).CombinedOutput()
		fmt.Fprintf(&b, "kubectl %v:\n%s\n", args, out)
	}
	return b.String()
}

// HTTPClient trusts the stack's CA and follows no redirect unless told to.
func (s *Stack) HTTPClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: s.CAPool}},
	}
}
