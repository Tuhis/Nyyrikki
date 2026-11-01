//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The SSH host of docs/07 G7: an OpenSSH container on the e2e network,
// set up by the setup script Nyyrikki serves. It has no systemd, so it
// does no session kill (docs/07 D11).
const (
	sshHostName  = "nyyrikki-e2e-sshhost"
	sshHostImage = "nyyrikki-e2e-sshhost:latest"
	sshTarget    = "db-1"
)

const sshHostDockerfile = `FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd && ssh-keygen -A
CMD ["/usr/sbin/sshd", "-D", "-e", "-o", "LogLevel=VERBOSE"]
`

// sshEnv is the SSH host's side of the environment.
type sshEnv struct {
	ip string
	// caSecret is the CA Secret as the install hook made it (docs/08 D16).
	caSecret *caSecret
}

// setupSSH starts the SSH host. It runs before the chart is installed;
// the chart's install hook makes the CA Secret (docs/08 D16).
func (e *env) setupSSH(t *testing.T) *sshEnv {
	t.Helper()
	exec.Command("docker", "rm", "-f", sshHostName).Run()
	build := exec.Command("docker", "build", "-q", "-t", sshHostImage, "-")
	build.Stdin = strings.NewReader(sshHostDockerfile)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the SSH host image: %v\n%s", err, out)
	}
	s := &sshEnv{ip: networkPrefix + ".252"}
	run(t, "docker", "run", "-d", "--name", sshHostName, "--network", networkName, "--ip", s.ip,
		"-v", e.caFile+":/ca.crt:ro", sshHostImage)
	if os.Getenv("NYYRIKKI_E2E_KEEP") == "" {
		t.Cleanup(func() { exec.Command("docker", "rm", "-f", sshHostName).Run() })
	}
	return s
}

// caSecretName is the chart's default secrets.sshCA.name.
const caSecretName = "nyyrikki-ssh-ca"

// caSecret is what of the CA Secret must never change behind anyone's
// back: its data, labels, annotations and UID.
type caSecret struct {
	UID         string
	Labels      map[string]string
	Annotations map[string]string
	Data        map[string]string
}

func (e *env) getCASecret(t *testing.T) *caSecret {
	t.Helper()
	var obj struct {
		Metadata struct {
			UID         string            `json:"uid"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(e.kubectl(t, "-n", namespace, "get", "secret", caSecretName, "-o", "json")), &obj); err != nil {
		t.Fatal(err)
	}
	return &caSecret{UID: obj.Metadata.UID, Labels: obj.Metadata.Labels, Annotations: obj.Metadata.Annotations, Data: obj.Data}
}

// sameCASecret fails unless the CA Secret is the one recorded, byte for
// byte (docs/08 G15).
func (e *env) sameCASecret(t *testing.T, s *sshEnv, when string) {
	t.Helper()
	got := e.getCASecret(t)
	if !reflect.DeepEqual(got, s.caSecret) {
		t.Fatalf("%s changed the CA Secret: UID %s -> %s, data keys %d -> %d", when, s.caSecret.UID, got.UID, len(s.caSecret.Data), len(got.Data))
	}
}

// values is the chart values for the SSH target and the ssh block.
// Pod traffic leaves the kind node with the node's address.
func (s *sshEnv) values(nodeIP string, hostKeys []string) string {
	keys := "[]"
	if len(hostKeys) > 0 {
		keys = "[" + strings.Join(quoteAll(hostKeys), ", ") + "]"
	}
	return fmt.Sprintf(`  - name: %s
    description: an OpenSSH container
    ssh: {address: "%s:22", hostKeys: %s, sudo: true, sessionKill: false}
ssh:
  sourceAddresses: [%s/32]
`, sshTarget, s.ip, keys, nodeIP)
}

func quoteAll(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = fmt.Sprintf("%q", x)
	}
	return out
}

func (s *sshEnv) exec(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", sshHostName}, args...)...).CombinedOutput()
	return string(out), err
}

func sshdLog(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("docker", "logs", sshHostName).CombinedOutput()
	return string(out)
}

var hostKeyLine = regexp.MustCompile(`(?m)^\s*-?\s*"?(ssh-ed25519 [A-Za-z0-9+/=]+)`)

// sshSteps are the SSH target's end-to-end checks (docs/07 G6 e2e, G7,
// G11 e2e, G14 e2e for SSH).
func (e *env) sshSteps(t *testing.T, s *sshEnv, agent *cli, next func() int) {
	step(t, "SE1: the install hook made the CA Secret, and its grant is gone", func(t *testing.T) {
		c := e.getCASecret(t)
		want := map[string]string{"nyyrikki.dev/release": "nyyrikki", "nyyrikki.dev/component": "ssh-ca", "app.kubernetes.io/managed-by": "nyyrikki-ssh-ca"}
		if !reflect.DeepEqual(c.Labels, want) {
			t.Fatalf("labels %v", c.Labels)
		}
		if c.Annotations["helm.sh/resource-policy"] != "keep" || c.Annotations["argocd.argoproj.io/compare-options"] != "IgnoreExtraneous" {
			t.Fatalf("annotations %v", c.Annotations)
		}
		if len(c.Data) != 2 || c.Data["user-ca"] == "" || c.Data["host-ca"] == "" {
			t.Fatalf("data keys: %d", len(c.Data))
		}
		s.caSecret = c
		for _, k := range []string{"job", "serviceaccount", "role", "rolebinding"} {
			if out, err := exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "-n", namespace, "get", k, "nyyrikki-ssh-ca-init").CombinedOutput(); err == nil {
				t.Fatalf("the hook's %s is still there: %s", k, out)
			}
		}
	})
	step(t, "SH6: the host is set up by the script Nyyrikki serves", func(t *testing.T) {
		// docs/07 §5.7: dry run first, then for real; both from the URL.
		url := fmt.Sprintf("%s/hosts/%s/setup.sh", e.canonical, sshTarget)
		if out, err := s.exec(t, "sh", "-c", "curl -fsSL --cacert /ca.crt "+url+" | sh -s -- --dry-run"); err != nil {
			t.Fatalf("dry run: %v\n%s", err, out)
		}
		if out, _ := s.exec(t, "id", "ny-owner"); !strings.Contains(out, "no such user") {
			t.Fatalf("the dry run changed the host: %s", out)
		}
		out, err := s.exec(t, "sh", "-c", "curl -fsSL --cacert /ca.crt "+url+" | sh")
		if err != nil {
			t.Fatalf("setup: %v\n%s", err, out)
		}
		t.Logf("setup output:\n%s", out)
		var keys []string
		for _, m := range hostKeyLine.FindAllStringSubmatch(out, -1) {
			keys = append(keys, m[1])
		}
		pub, _ := s.exec(t, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		want := strings.Join(strings.Fields(pub)[:2], " ")
		if len(keys) == 0 || !contains(keys, want) {
			t.Fatalf("the script printed host keys %v; the host's ed25519 key is %s", keys, want)
		}
		if !strings.Contains(out, "session_kill: false") {
			t.Errorf("a host without systemd reported session kill:\n%s", out)
		}
		// Runs are refused until the host keys are pinned (docs/07 §5.5):
		// approved, and still unavailable, without a connection.
		logins := strings.Count(sshdLog(t), "Accepted publickey")
		ch := agent.async(t, "run", "--reason", "before pinning", sshTarget, "--", "id")
		e.tap(t, next(), "Approve")
		if r := get(t, ch, time.Minute); r.code != 69 || !strings.Contains(r.stderr, "host keys are not configured") {
			t.Fatalf("before pinning: %+v", r)
		}
		if strings.Count(sshdLog(t), "Accepted publickey") != logins {
			t.Fatal("an unpinned host was logged in to")
		}
		e.upgradeSSH(t, s, []string{want})
		// The pre-upgrade hook ran again, and left the Secret alone.
		e.sameCASecret(t, s, "helm upgrade")
	})

	step(t, "SH6: an approved command runs as ny-owner with sudo; the host logs the run's key ID", func(t *testing.T) {
		ch := agent.async(t, "run", "--reason", "who am I on the host", sshTarget, "--", "id", "-un", "&&", "sudo", "-n", "id", "-u")
		msg := e.tap(t, next(), "Approve")
		for _, want := range []string{"id -un &amp;&amp; sudo -n id -u", "ny-owner", s.ip + ":22", "root via sudo", "doesn't finish cuts"} {
			if !strings.Contains(msg.Text, want) {
				t.Errorf("prompt lacks %q:\n%s", want, msg.Text)
			}
		}
		r := get(t, ch, time.Minute)
		if r.code != 0 || r.stdout != "ny-owner\n0\n" {
			t.Fatalf("run: %+v", r)
		}
		runID := e.lastRunID(t, sshTarget)
		if !strings.Contains(sshdLog(t), "ID nyyrikki:"+runID+" (serial ") {
			t.Fatalf("sshd's log doesn't name run %s:\n%s", runID, sshdLog(t))
		}
	})

	step(t, "SH6: a denied command never connects", func(t *testing.T) {
		logins := strings.Count(sshdLog(t), "Accepted publickey")
		ch := agent.async(t, "run", "--reason", "remove it", sshTarget, "--", "sudo", "touch", "/denied")
		e.tap(t, next(), "Deny")
		if r := get(t, ch, time.Minute); r.code != 77 {
			t.Fatalf("denied: %+v", r)
		}
		if n := strings.Count(sshdLog(t), "Accepted publickey"); n != logins {
			t.Fatalf("a denied run logged in (%d → %d)", logins, n)
		}
		if out, err := s.exec(t, "test", "-e", "/denied"); err == nil {
			t.Fatalf("the denied command ran: %s", out)
		}
	})

	step(t, "SH6: stdin reaches the host but not the approver", func(t *testing.T) {
		const marker = "e2e stdin marker"
		ch := make(chan result, 1)
		go func() {
			ch <- agent.run(t, marker, "run", "-i", "--reason", "write a file", sshTarget, "--", "sudo", "tee", "/tmp/e2e-stdin")
		}()
		msg := e.tap(t, next(), "Approve")
		if strings.Contains(msg.Text, marker) || !strings.Contains(msg.Text, "stdin is not shown") {
			t.Fatalf("stdin on Telegram:\n%s", msg.Text)
		}
		if r := get(t, ch, time.Minute); r.code != 0 {
			t.Fatalf("tee: %+v", r)
		}
		if out, _ := s.exec(t, "cat", "/tmp/e2e-stdin"); out != marker {
			t.Fatalf("the host got %q", out)
		}
	})

	step(t, "SH6: End now cuts an interactive SSH session", func(t *testing.T) {
		cmd := agent.cmd("run", "-t", "--reason", "a shell", sshTarget)
		out, wait := startPTY(t, cmd)
		n := next()
		e.tap(t, n, "Approve")
		deadline := time.Now().Add(30 * time.Second)
		for !strings.Contains(out(), "$") && time.Now().Before(deadline) {
			time.Sleep(200 * time.Millisecond)
		}
		e.tap(t, n, "End now")
		code := wait(30 * time.Second)
		if code != 75 || !strings.Contains(out(), "the approver ended it") {
			t.Fatalf("End now: code %d, output %q", code, out())
		}
		// The prompt is settled in its own goroutine after the cut, so the
		// edit can land after the CLI has exited.
		sent := e.tg.Sent(t)[n-1]
		msg := e.tg.Message(t, sent)
		for deadline := time.Now().Add(10 * time.Second); !strings.Contains(msg.Text, "Session ended at") && time.Now().Before(deadline); msg = e.tg.Message(t, sent) {
			time.Sleep(200 * time.Millisecond)
		}
		if _, ok := msg.Button("End now"); ok || !strings.Contains(msg.Text, "Session ended at") {
			t.Fatalf("message after End now:\n%s", msg.Text)
		}
	})

	step(t, "SH6: an elevation covers the host, and its end cuts a command", func(t *testing.T) {
		ch := agent.async(t, "elevate", "--reason", "host work", "--for", "1m", sshTarget)
		msg := e.tap(t, next(), "Approve")
		if !strings.Contains(msg.Text, "root via sudo") {
			t.Errorf("elevation prompt lacks the sudo marker:\n%s", msg.Text)
		}
		r := get(t, ch, time.Minute)
		h := strings.TrimSpace(r.stdout)
		if r.code != 0 || !strings.HasPrefix(h, "nyel_") {
			t.Fatalf("elevate: %+v", r)
		}
		withH := []string{"NYYRIKKI_ELEVATION=" + h}
		before := len(e.tg.Sent(t))
		for i := 0; i < 2; i++ {
			if r := agent.runEnv(t, withH, "", "run", "--reason", "covered", sshTarget, "--", "hostname"); r.code != 0 {
				t.Fatalf("covered %d: %+v", i, r)
			}
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("a covered command asked the approver")
		}
		// A long command and its background job are cut at expiry; on a
		// host without session kill, the signals reach the process group
		// (docs/07 D11, M24).
		r = agent.runEnv(t, withH, "", "run", "--timeout", "5m", "--reason", "long", sshTarget, "--", "sleep 600 & sleep 601; wait")
		if r.code != 75 || !strings.Contains(r.stderr, "the elevation expired") {
			t.Fatalf("not cut at expiry: %+v", r)
		}
		time.Sleep(3 * time.Second)
		if out, _ := s.exec(t, "pgrep", "-u", "ny-owner", "sleep"); strings.TrimSpace(out) != "" {
			t.Fatalf("processes outlived the cut: %s", out)
		}
	})
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// upgradeSSH pins the host keys and waits for the new pod.
func (e *env) upgradeSSH(t *testing.T, s *sshEnv, keys []string) {
	t.Helper()
	e.values = strings.Replace(e.values, s.values(e.nodeIP, nil), s.values(e.nodeIP, keys), 1)
	run(t, "helm", "--kubeconfig", e.kubeconfig, "upgrade", "nyyrikki", filepath.Join(e.root, "deploy/chart/nyyrikki"),
		"-n", namespace, "-f", writeFile(t, e.dir, "values.yaml", []byte(e.values)), "--wait", "--timeout", "180s")
	e.kubectl(t, "-n", namespace, "rollout", "status", "deploy/nyyrikki-nyyrikki", "--timeout=180s")
	e.waitCanonical(t)
}

// lastRunID returns the run ID of the last run_started on target, from
// nyyrikkid's audit stream on stdout.
func (e *env) lastRunID(t *testing.T, target string) string {
	t.Helper()
	logs := e.kubectl(t, "-n", namespace, "logs", "deploy/nyyrikki-nyyrikki")
	re := regexp.MustCompile(`"kind":"run_started"[^\n]*"targets":\["` + target + `"\][^\n]*"run_id":"(run_[A-Z0-9]+)"`)
	m := re.FindAllStringSubmatch(logs, -1)
	if len(m) == 0 {
		t.Fatalf("no run_started for %s in the logs", target)
	}
	return m[len(m)-1][1]
}

// caSecretSurvives checks docs/08 G15's last part, at the end of the run:
// helm upgrade --force and helm uninstall leave the CA Secret byte for
// byte.
func (e *env) caSecretSurvives(t *testing.T, s *sshEnv) {
	chart := filepath.Join(e.root, "deploy/chart/nyyrikki")
	values := writeFile(t, e.dir, "values.yaml", []byte(e.values))
	step(t, "SE1: helm upgrade --force leaves the CA Secret", func(t *testing.T) {
		// --force replaces every object of the release. The chart's PVC
		// can't be replaced once bound (its spec is immutable), so the
		// upgrade fails there, after the pre-upgrade hook ran and after
		// the objects before it were replaced. That limit of the chart
		// predates docs/08; the Secret must survive either way.
		out, err := exec.Command("helm", "--kubeconfig", e.kubeconfig, "upgrade", "nyyrikki", chart, "-n", namespace, "-f", values,
			"--force", "--wait", "--timeout", "180s").CombinedOutput()
		if err != nil && !(strings.Contains(string(out), `PersistentVolumeClaim "nyyrikki-nyyrikki" is invalid`) && strings.Contains(string(out), "immutable")) {
			t.Fatalf("helm upgrade --force: %v\n%s", err, out)
		}
		t.Logf("helm upgrade --force: %v\n%s", err, out)
		e.sameCASecret(t, s, "helm upgrade --force")
	})
	step(t, "SE1: helm uninstall leaves the CA Secret", func(t *testing.T) {
		run(t, "helm", "--kubeconfig", e.kubeconfig, "uninstall", "nyyrikki", "-n", namespace, "--wait", "--timeout", "180s")
		e.sameCASecret(t, s, "helm uninstall")
	})
}
