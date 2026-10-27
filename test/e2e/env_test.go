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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

const (
	clusterName   = "nyyrikki-e2e"
	keycloakName  = "nyyrikki-e2e-keycloak"
	fakebotName   = "nyyrikki-e2e-fakebot"
	distroless    = "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
	keycloakImage = "quay.io/keycloak/keycloak:26.8.1"
	image         = "nyyrikki:e2e"
	busyboxImage  = "busybox:1.36"
	namespace     = "nyyrikki"
	workNS        = "e2e"
	nodePort      = 30443
	realm         = "nyyrikki"
	ownerUser     = "owner"
	ownerPassword = "owner-e2e-password"
	ownerK8sUser  = "owner@example.com"
	approverID    = 4242
	introspectSec = "e2e-introspection-secret"
	mcpClientID   = "nyyrikki-mcp-e2e"
)

// env is the running environment.
type env struct {
	dir        string
	kubeconfig string
	nodeIP     string
	gatewayIP  string
	issuer     string
	canonical  string
	caFile     string // trusts Keycloak, nyyrikkid and the fake Bot API
	caPool     *x509.CertPool
	cli        string // the nyyrikki binary
	tg         *fakeBot
	ownerID    string // the owner's Keycloak user ID (the token sub)
	adminToken string
}

func run(t testing.TB, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func (e *env) kubectl(t testing.TB, args ...string) string {
	t.Helper()
	return run(t, "kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...)
}

// setup builds the whole environment. It is torn down when the test ends,
// unless NYYRIKKI_E2E_KEEP is set.
func setup(t *testing.T) *env {
	t.Helper()
	for _, tool := range []string{"docker", "kind", "helm", "kubectl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s not on PATH", tool)
		}
	}
	e := &env{dir: t.TempDir()}
	e.kubeconfig = filepath.Join(e.dir, "kubeconfig")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	// The cluster.
	exec.Command("kind", "delete", "cluster", "--name", clusterName).Run()
	exec.Command("docker", "rm", "-f", keycloakName, fakebotName).Run()
	run(t, "kind", "create", "cluster", "--name", clusterName, "--kubeconfig", e.kubeconfig, "--wait", "180s")
	if os.Getenv("NYYRIKKI_E2E_KEEP") == "" {
		t.Cleanup(func() {
			exec.Command("kind", "delete", "cluster", "--name", clusterName).Run()
			exec.Command("docker", "rm", "-f", keycloakName, fakebotName).Run()
		})
	}
	out := run(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}}{{end}}", clusterName+"-control-plane")
	f := strings.Fields(out)
	e.nodeIP, e.gatewayIP = f[0], f[1]
	prefix := e.gatewayIP[:strings.LastIndex(e.gatewayIP, ".")]
	kcIP, botIP := prefix+".250", prefix+".251"
	e.issuer = fmt.Sprintf("https://%s:8443/realms/%s", kcIP, realm)
	e.canonical = fmt.Sprintf("https://%s:%d", e.nodeIP, nodePort)
	t.Logf("node %s, gateway %s, keycloak %s", e.nodeIP, e.gatewayIP, kcIP)

	// One CA for every TLS endpoint of the test.
	ca := newCA(t)
	e.caPool = x509.NewCertPool()
	e.caPool.AddCert(ca.cert)
	e.caFile = writeFile(t, e.dir, "ca.crt", ca.certPEM)
	kcCert, kcKey := ca.issue(t, kcIP)
	nyCert, nyKey := ca.issue(t, e.nodeIP)
	tgCert, tgKey := ca.issue(t, botIP)

	// Keycloak, on the kind network so the pod reaches it at the same
	// address as the test.
	kcDir := filepath.Join(e.dir, "keycloak")
	os.MkdirAll(kcDir, 0o755)
	writeFileMode(t, kcDir, "tls.crt", kcCert, 0o644)
	writeFileMode(t, kcDir, "tls.key", kcKey, 0o644)
	run(t, "docker", "run", "-d", "--name", keycloakName, "--network", "kind", "--ip", kcIP,
		"-v", kcDir+":/certs:ro",
		"-e", "KC_BOOTSTRAP_ADMIN_USERNAME=admin", "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=admin",
		keycloakImage, "start-dev",
		"--https-port=8443", "--http-enabled=false",
		"--https-certificate-file=/certs/tls.crt", "--https-certificate-key-file=/certs/tls.key",
		"--hostname=https://"+kcIP+":8443")

	// The fake Bot API, also on the kind network: a container can reach
	// another container, but a host firewall may stop it reaching the host.
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
	run(t, "docker", "run", "-d", "--name", fakebotName, "--network", "kind", "--ip", botIP,
		"-v", botDir+":/app:ro", distroless, "/app/fakebot", "-cert", "/app/tls.crt", "-key", "/app/tls.key")
	e.tg = &fakeBot{api: "https://" + botIP + ":8443", control: "http://" + botIP + ":9000"}

	// The image and the CLI, built from this checkout.
	run(t, "docker", "build", "-q", "-t", image, root)
	run(t, "kind", "load", "docker-image", image, "--name", clusterName)
	// busybox is pulled by the node itself: kind load can't import
	// multi-platform images.
	e.cli = filepath.Join(e.dir, "nyyrikki")
	build := exec.Command("go", "build", "-o", e.cli, "./cmd/nyyrikki")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}

	e.configureKeycloak(t)

	// The cluster side: the human's own rights, a workload, Nyyrikki's
	// Secrets, and a NodePort for the canonical URL.
	e.kubectl(t, "create", "namespace", namespace)
	e.kubectl(t, "create", "namespace", workNS)
	e.kubectl(t, "create", "clusterrolebinding", "e2e-owner-edit", "--clusterrole=edit", "--user="+ownerK8sUser)
	e.kubectl(t, "-n", workNS, "run", "box", "--image="+busyboxImage, "--image-pull-policy=IfNotPresent", "--restart=Never", "--", "sleep", "3600")
	sdir := filepath.Join(e.dir, "secrets")
	os.MkdirAll(sdir, 0o700)
	e.kubectl(t, "-n", namespace, "create", "secret", "tls", "nyyrikki-tls",
		"--cert="+writeFile(t, sdir, "tls.crt", nyCert), "--key="+writeFile(t, sdir, "tls.key", nyKey))
	e.kubectl(t, "-n", namespace, "create", "secret", "generic", "nyyrikki-telegram",
		"--from-file=bot-token="+writeFile(t, sdir, "bot-token", []byte(telegramtest.DefaultToken)))
	e.kubectl(t, "-n", namespace, "create", "secret", "generic", "nyyrikki-keycloak",
		"--from-file=client-secret="+writeFile(t, sdir, "client-secret", []byte(introspectSec)))
	e.kubectl(t, "-n", namespace, "create", "configmap", "e2e-ca", "--from-file=ca.crt="+e.caFile)
	svc := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata: {name: nyyrikki-e2e-nodeport, namespace: %s}
spec:
  type: NodePort
  selector: {app.kubernetes.io/name: nyyrikki, app.kubernetes.io/instance: nyyrikki}
  ports: [{port: 8443, targetPort: https, nodePort: %d}]
`, namespace, nodePort)
	e.kubectl(t, "apply", "-f", writeFile(t, e.dir, "nodeport.yaml", []byte(svc)))

	t.Cleanup(func() {
		if t.Failed() {
			for _, args := range [][]string{
				{"-n", namespace, "get", "pods", "-o", "wide"},
				{"-n", namespace, "describe", "pods"},
				{"-n", namespace, "logs", "deploy/nyyrikki-nyyrikki", "--tail=200"},
			} {
				out, _ := exec.Command("kubectl", append([]string{"--kubeconfig", e.kubeconfig}, args...)...).CombinedOutput()
				t.Logf("kubectl %v:\n%s", args, out)
			}
		}
	})
	values := fmt.Sprintf(`image: {repository: nyyrikki, tag: e2e, pullPolicy: Never}
canonicalURL: %s
auth: {issuer: %s}
approval: {timeout: 2m}
human:
  subject: %s
  kubernetes: {user: %s, groups: []}
  telegramUserID: %d
targets:
  - name: this-cluster
    description: the kind cluster
    inCluster: true
telegram: {apiURL: %s}
trustedCA: {configMap: e2e-ca}
`, e.canonical, e.issuer, e.ownerID, ownerK8sUser, approverID, e.tg.api)
	run(t, "helm", "--kubeconfig", e.kubeconfig, "install", "nyyrikki", filepath.Join(root, "deploy/chart/nyyrikki"),
		"-n", namespace, "-f", writeFile(t, e.dir, "values.yaml", []byte(values)), "--wait", "--timeout", "180s")
	e.kubectl(t, "-n", workNS, "wait", "--for=condition=Ready", "pod/box", "--timeout=120s")
	// The pod is ready before the NodePort is: wait for the canonical URL.
	deadline := time.Now().Add(90 * time.Second)
	for {
		resp, err := e.httpClient().Get(e.canonical + "/.well-known/oauth-protected-resource/mcp")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("canonical URL not reachable: %v", err)
		}
		time.Sleep(time.Second)
	}
	return e
}

// httpClient trusts the test CA and follows no redirect unless told to.
func (e *env) httpClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: e.caPool}},
	}
}

func (e *env) kcBase() string { return strings.TrimSuffix(e.issuer, "/realms/"+realm) }

// configureKeycloak waits for Keycloak and sets up the realm as
// docs/setup/keycloak.md describes, through the admin REST API.
func (e *env) configureKeycloak(t *testing.T) {
	t.Helper()
	hc := e.httpClient()
	deadline := time.Now().Add(4 * time.Minute)
	for {
		resp, err := hc.Get(e.kcBase() + "/realms/master/.well-known/openid-configuration")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if time.Now().After(deadline) {
			out, _ := exec.Command("docker", "logs", "--tail", "50", keycloakName).CombinedOutput()
			t.Fatalf("keycloak did not start: %v\n%s", err, out)
		}
		time.Sleep(2 * time.Second)
	}
	e.adminToken = e.adminLogin(t)
	e.admin(t, "POST", "/admin/realms", map[string]any{
		"realm": realm, "enabled": true, "accessTokenLifespan": 300,
	})
	r := "/admin/realms/" + realm
	e.admin(t, "POST", r+"/client-scopes", map[string]any{
		"name": "nyyrikki", "protocol": "openid-connect",
		"attributes": map[string]string{"include.in.token.scope": "true", "display.on.consent.screen": "false"},
		"protocolMappers": []any{map[string]any{
			"name": "nyyrikki audience", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{
				"included.custom.audience": e.canonical + "/mcp",
				"access.token.claim":       "true", "id.token.claim": "false", "introspection.token.claim": "true",
			},
		}},
	})
	deviceClient := func(id string, dpop bool) map[string]any {
		return map[string]any{
			"clientId": id, "publicClient": true, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
			"implicitFlowEnabled": false, "consentRequired": false,
			"attributes": map[string]string{
				"oauth2.device.authorization.grant.enabled": "true",
				"dpop.bound.access.tokens":                  fmt.Sprint(dpop),
			},
			// No "roles": its audience-resolve mapper adds "account" to aud,
			// and Nyyrikki accepts only its own audience (docs/01 D9).
			"defaultClientScopes":  []string{"basic", "profile", "email", "web-origins", "acr"},
			"optionalClientScopes": []string{"nyyrikki"},
		}
	}
	e.admin(t, "POST", r+"/clients", deviceClient("nyyrikki-cli", true))
	// Stands in for an MCP harness's own registration (Bearer, keyed by sid).
	e.admin(t, "POST", r+"/clients", deviceClient(mcpClientID, false))
	// Named after Nyyrikki's audience: Keycloak introspects a token only
	// for a client in its aud (docs/setup/keycloak.md).
	e.admin(t, "POST", r+"/clients", map[string]any{
		"clientId": e.canonical + "/mcp", "publicClient": false, "secret": introspectSec,
		"standardFlowEnabled": false, "directAccessGrantsEnabled": false, "serviceAccountsEnabled": false,
	})
	e.admin(t, "POST", r+"/users", map[string]any{
		"username": ownerUser, "enabled": true, "email": "owner@example.com", "emailVerified": true,
		"firstName": "Owner", "lastName": "E2E",
		"credentials": []any{map[string]any{"type": "password", "value": ownerPassword, "temporary": false}},
	})
	var users []struct {
		ID string `json:"id"`
	}
	json.Unmarshal(e.admin(t, "GET", r+"/users?username="+ownerUser+"&exact=true", nil), &users)
	if len(users) != 1 {
		t.Fatalf("owner user not found")
	}
	e.ownerID = users[0].ID
}

func (e *env) adminLogin(t *testing.T) string {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"}}
	resp, err := e.httpClient().PostForm(e.kcBase()+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || tr.AccessToken == "" {
		t.Fatalf("admin login: %v", err)
	}
	return tr.AccessToken
}

func (e *env) admin(t *testing.T, method, path string, body any) []byte {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.kcBase()+path, rd)
	// Admin tokens from the master realm live a minute: sign in per call.
	req.Header.Set("Authorization", "Bearer "+e.adminLogin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("keycloak %s %s: %s %s", method, path, resp.Status, out)
	}
	return out
}

type testCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

func newCA(t *testing.T) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "nyyrikki e2e CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

var serial int64 = 1

func (ca *testCA) issue(t *testing.T, ip string) (certPEM, keyPEM []byte) {
	serial++
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
}

func writeFile(t testing.TB, dir, name string, b []byte) string {
	return writeFileMode(t, dir, name, b, 0o600)
}

func writeFileMode(t testing.TB, dir, name string, b []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	return p
}
