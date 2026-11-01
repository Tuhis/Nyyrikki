//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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
	var c caSecret
	e.kubectlJSON(t, &c, namespace, caSecretName)
	return &c
}

// kubectlJSON reads the Secret ns/name into c.
func (e *env) kubectlJSON(t *testing.T, c *caSecret, ns, name string) {
	t.Helper()
	var obj struct {
		Metadata struct {
			UID         string            `json:"uid"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal([]byte(e.kubectl(t, "-n", ns, "get", "secret", name, "-o", "json")), &obj); err != nil {
		t.Fatal(err)
	}
	*c = caSecret{UID: obj.Metadata.UID, Labels: obj.Metadata.Labels, Annotations: obj.Metadata.Annotations, Data: obj.Data}
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

// sshSteps are the SSH target's end-to-end checks (docs/07 G6 e2e, G7,
// G11 e2e, G14 e2e for SSH; docs/08 G7 e2e, and G15's rotation).
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
	step(t, "SE6: a run on a host that isn't enrolled is refused before any prompt", func(t *testing.T) {
		// docs/08 D9, D10: no pins, and host-ca exists, so the host must
		// present Nyyrikki's certificate; the check before the prompt
		// fails, and no approver is asked.
		before := len(e.tg.Sent(t))
		logins := strings.Count(sshdLog(t), "Accepted publickey")
		r := agent.run(t, "", "run", "--reason", "before enrolling", sshTarget, "--", "id")
		if r.code != 69 || !strings.Contains(r.stderr, "unavailable") {
			t.Fatalf("a run on a host that isn't enrolled: %+v", r)
		}
		if len(e.tg.Sent(t)) != before {
			t.Fatal("the approver was asked about a host that can't be verified")
		}
		if strings.Count(sshdLog(t), "Accepted publickey") != logins {
			t.Fatal("a host that isn't enrolled was logged in to")
		}
	})
	step(t, "SE6: the host is set up and enrolled by the served script, with one command and one tap", func(t *testing.T) {
		// docs/07 §5.7: dry run first, then for real; both from the URL.
		url := fmt.Sprintf("%s/hosts/%s/setup.sh", e.canonical, sshTarget)
		if out, err := s.exec(t, "sh", "-c", "curl -fsSL --cacert /ca.crt "+url+" | sh -s -- --dry-run --cacert /ca.crt"); err != nil {
			t.Fatalf("dry run: %v\n%s", err, out)
		}
		if out, _ := s.exec(t, "id", "ny-owner"); !strings.Contains(out, "no such user") {
			t.Fatalf("the dry run changed the host: %s", out)
		}
		// docs/08 D6: the token from the pod, by kubectl exec.
		tokOut := e.kubectl(t, "-n", namespace, "exec", "deploy/nyyrikki-nyyrikki", "--", "nyyrikkid", "enroll-token", sshTarget)
		m := regexp.MustCompile(`curl -fsSL (\S+) \| sudo sh -s -- --enroll (nye1\.[A-Za-z0-9_-]+)`).FindStringSubmatch(tokOut)
		if m == nil || m[1] != url {
			t.Fatalf("enroll-token printed:\n%s", tokOut)
		}
		pub, _ := s.exec(t, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		hk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
		if err != nil {
			t.Fatal(err)
		}
		fp := ssh.FingerprintSHA256(hk)
		type res struct {
			out string
			err error
		}
		ch := make(chan res, 1)
		go func() {
			out, err := s.exec(t, "sh", "-c", "curl -fsSL --cacert /ca.crt "+url+" | sh -s -- --cacert /ca.crt --enroll "+m[2])
			ch <- res{out, err}
		}()
		msg := e.tap(t, next(), "Approve")
		for _, want := range []string{"Enroll SSH host", fp, s.ip + ":22", "root via sudo"} {
			if !strings.Contains(msg.Text, want) {
				t.Errorf("the enrollment prompt lacks %q:\n%s", want, msg.Text)
			}
		}
		var r res
		select {
		case r = <-ch:
		case <-time.After(3 * time.Minute):
			t.Fatal("the setup didn't finish after the approval")
		}
		t.Logf("setup output:\n%s", r.out)
		if r.err != nil {
			t.Fatalf("setup with --enroll: %v", r.err)
		}
		for _, want := range []string{"ED25519 " + fp, "Approve on Telegram only if", "pull: none", "check: ny-owner: ok", "Enrolled"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("setup output lacks %q", want)
			}
		}
		if strings.Index(r.out, "ED25519 "+fp) > strings.Index(r.out, "installed /etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub") {
			t.Error("the fingerprint was printed after the certificate arrived")
		}
		if out, err := s.exec(t, "ssh-keygen", "-L", "-f", "/etc/ssh/nyyrikki/ssh_host_ed25519_key-cert.pub"); err != nil || !strings.Contains(out, "nyyrikki-host:"+sshTarget) {
			t.Fatalf("the host certificate: %v\n%s", err, out)
		}
		// The pre-upgrade hook runs again on an upgrade, and leaves the
		// Secret alone.
		e.upgrade(t)
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

// signerKeys are the SIGNER_KEY lines of the target's trust bundle, as
// Nyyrikki serves it now.
func (e *env) signerKeys(t *testing.T) []string {
	t.Helper()
	return e.dataLines(t, "trust", "SIGNER_KEY")
}

// dataLines are the values of the name lines of what Nyyrikki serves at
// /hosts/<target>/<path>.
func (e *env) dataLines(t *testing.T, path, name string) []string {
	t.Helper()
	resp, err := e.httpClient().Get(e.canonical + "/hosts/" + sshTarget + "/" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d", path, resp.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), name+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// waitSigners waits until the bundle has n signers other than not: the
// kubelet updates a mounted Secret within a minute or two.
func (e *env) waitSigners(t *testing.T, n int, not string) []string {
	t.Helper()
	deadline := time.Now().Add(4 * time.Minute)
	for {
		got := e.signerKeys(t)
		if len(got) == n && (not == "" || !slices.Contains(got, not)) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("the bundle's signers are %v, not %d without %q", got, n, not)
		}
		time.Sleep(5 * time.Second)
	}
}

// hostKeys are the lines of a key file on the SSH host, without comments.
func (s *sshEnv) hostKeys(t *testing.T, path string) []string {
	t.Helper()
	out, err := s.exec(t, "cat", path)
	if err != nil {
		t.Fatalf("%s: %v\n%s", path, err, out)
	}
	var keys []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Fields(l); len(f) >= 2 {
			keys = append(keys, f[0]+" "+f[1])
		}
	}
	return keys
}

// rotation covers docs/08 §5.4 and G15's rotation on kind, with G14's
// path automated: stage and promote through the chart's CronJobs, each
// reaching the host by its pull (run by hand, as this host has no cron),
// then a run signed by the new key.
func (e *env) rotation(t *testing.T, s *sshEnv, agent *cli, next func() int) {
	step(t, "SE6: a CA rotation through the CronJobs reaches the host by its pull", func(t *testing.T) {
		old := e.signerKeys(t)
		if len(old) != 1 {
			t.Fatalf("signers before the stage: %v", old)
		}
		job := func(cronjob, name string) string {
			t.Helper()
			e.kubectl(t, "-n", namespace, "create", "job", "--from=cronjob/nyyrikki-ssh-ca-"+cronjob, name)
			e.kubectl(t, "-n", namespace, "wait", "--for=condition=complete", "job/"+name, "--timeout=180s")
			return e.kubectl(t, "-n", namespace, "logs", "job/"+name)
		}
		pull := func(want []string) {
			t.Helper()
			if out, err := s.exec(t, "/etc/ssh/nyyrikki/pull.sh"); err != nil {
				t.Fatalf("the pull: %v\n%s", err, out)
			}
			if got := s.hostKeys(t, "/etc/ssh/nyyrikki/signers.pub"); !slices.Equal(got, want) {
				t.Fatalf("the host's signers %v, want %v", got, want)
			}
		}
		job("stage", "e2e-ssh-ca-stage")
		staged := e.waitSigners(t, 2, "")
		if staged[0] != old[0] {
			t.Fatalf("after the stage, the signers are %v", staged)
		}
		pull(staged)
		log := job("promote", "e2e-ssh-ca-promote")
		if !strings.Contains(log, strings.Fields(old[0])[1]) {
			t.Errorf("promote didn't print the old public key:\n%s", log)
		}
		promoted := e.waitSigners(t, 1, old[0])
		if promoted[0] != staged[1] {
			t.Fatalf("after the promote, the signers are %v, want the staged key", promoted)
		}
		pull(promoted)
		if got := s.hostKeys(t, "/etc/ssh/nyyrikki/user_ca.pub"); !slices.Equal(got, promoted) {
			t.Fatalf("the host trusts %v after the promote", got)
		}
		if slices.Contains(e.dataLines(t, "setup.sh", "CA_KEY"), old[0]) {
			t.Fatal("the old key is still a CA_KEY after the promote")
		}
		// A run now carries a certificate of the new key, which the host
		// trusts only through its pull.
		ch := agent.async(t, "run", "--reason", "after the rotation", sshTarget, "--", "id", "-un")
		e.tap(t, next(), "Approve")
		if r := get(t, ch, time.Minute); r.code != 0 || r.stdout != "ny-owner\n" {
			t.Fatalf("a run after the rotation: %+v", r)
		}
		s.caSecret = e.getCASecret(t)
		if s.caSecret.Data["user-ca-next"] != "" || s.caSecret.Data["host-ca"] == "" {
			t.Fatalf("the Secret after the promote has keys %v", keysOf(s.caSecret.Data))
		}
	})
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// upgrade upgrades the release with its values and waits for the pod.
func (e *env) upgrade(t *testing.T) {
	t.Helper()
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
