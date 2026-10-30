// Package chart_test renders the Helm chart and checks what docs/06 G2
// requires. It needs helm; the chart gate runs it with
// NYYRIKKI_CHART_TESTS=1 (scripts/gates.sh), so a missing helm there fails
// instead of skipping.
package chart_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Tuhis/Nyyrikki/internal/config"
)

type object = map[string]any

func render(t *testing.T, extra ...string) []object {
	t.Helper()
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1 (the chart gate does)")
	}
	// Helm's offline default Kubernetes is the one it was built against,
	// which may be older than the chart's kubeVersion.
	args := append([]string{"template", "t", "nyyrikki", "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0"}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	var objs []object
	dec := yaml.NewDecoder(bytes.NewReader(out))
	for {
		var o object
		if err := dec.Decode(&o); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if o != nil {
			objs = append(objs, o)
		}
	}
	return objs
}

func kind(objs []object, k string) []object {
	var out []object
	for _, o := range objs {
		if o["kind"] == k {
			out = append(out, o)
		}
	}
	return out
}

func TestChartConfigIsValid(t *testing.T) {
	cms := kind(render(t), "ConfigMap")
	if len(cms) != 1 {
		t.Fatalf("%d ConfigMaps", len(cms))
	}
	src := cms[0]["data"].(map[string]any)["config.yaml"].(string)
	c, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("the chart renders a config nyyrikkid refuses: %v\n%s", err, src)
	}
	if len(c.Targets) != 2 || c.Targets[1].Kubernetes.TokenFile != "/etc/nyyrikki/targets/lab/token" {
		t.Fatalf("targets: %+v", c.Targets)
	}
}

func TestChartRBAC(t *testing.T) {
	for name, extra := range map[string][]string{
		"with groups":    nil,
		"without groups": {"--set", "human.kubernetes.groups=null"},
	} {
		t.Run(name, func(t *testing.T) {
			roles := kind(render(t, extra...), "ClusterRole")
			if len(roles) != 1 {
				t.Fatalf("%d ClusterRoles", len(roles))
			}
			if len(kind(render(t, extra...), "Role")) != 0 {
				t.Fatal("unexpected Role")
			}
			rules := roles[0]["rules"].([]any)
			for _, r := range rules {
				rule := r.(map[string]any)
				verbs := rule["verbs"].([]any)
				names, _ := rule["resourceNames"].([]any)
				if len(verbs) != 1 || verbs[0] != "impersonate" || len(names) == 0 {
					t.Fatalf("rule beyond impersonating named identities: %v", rule)
				}
				for _, res := range rule["resources"].([]any) {
					if res != "users" && res != "groups" {
						t.Fatalf("impersonates %v", res)
					}
				}
			}
			if want := map[string]int{"with groups": 2, "without groups": 1}[name]; len(rules) != want {
				t.Fatalf("%d rules, want %d", len(rules), want)
			}
		})
	}
}

func TestChartNoSecretEnv(t *testing.T) {
	for _, d := range kind(render(t), "Deployment") {
		spec := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		for _, c := range spec["containers"].([]any) {
			ctr := c.(map[string]any)
			// Credentials are files (docs/01 D15): no env var may take its
			// value from a Secret.
			if env, ok := ctr["env"].([]any); ok {
				for _, e := range env {
					if vf, ok := e.(map[string]any)["valueFrom"].(map[string]any); ok && vf["secretKeyRef"] != nil {
						t.Fatalf("env %v takes a Secret", e)
					}
				}
			}
			if _, ok := ctr["envFrom"]; ok {
				t.Fatal("container has envFrom")
			}
			sc := ctr["securityContext"].(map[string]any)
			if sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false {
				t.Fatalf("securityContext %v", sc)
			}
		}
		if r := d["spec"].(map[string]any)["replicas"]; r != 1 {
			t.Fatalf("replicas %v", r)
		}
	}
}

func TestChartRequiresValues(t *testing.T) {
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	out, err := exec.Command("helm", "template", "t", "nyyrikki", "--kube-version", "1.35.0").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "required") {
		t.Fatalf("rendered without required values: %s", out)
	}
}

// TestChartTwoInClusterTargets: the ServiceAccount token is mounted when
// any target is in-cluster, however many are (found in review of #11).
func TestChartTwoInClusterTargets(t *testing.T) {
	for name, c := range map[string]struct {
		set  []string
		want bool
	}{
		"two in-cluster": {[]string{"--set", "targets[0].name=a", "--set", "targets[0].inCluster=true",
			"--set", "targets[1].name=b", "--set", "targets[1].inCluster=true"}, true},
		// Least privilege: no in-cluster target, no token.
		"remote only": {[]string{"--set", "targets[0].inCluster=false", "--set", "targets[0].server=https://lab0.example.com",
			"--set", "targets[0].secretName=s"}, false},
	} {
		deps := kind(render(t, c.set...), "Deployment")
		if len(deps) != 1 {
			t.Fatalf("%s: %d Deployments", name, len(deps))
		}
		spec := deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		if spec["automountServiceAccountToken"] != c.want {
			t.Errorf("%s: automountServiceAccountToken = %v, want %v", name, spec["automountServiceAccountToken"], c.want)
		}
	}
}

func TestChartPullSecrets(t *testing.T) {
	deps := kind(render(t, "--set", "image.pullSecrets[0].name=ghcr-pull"), "Deployment")
	if len(deps) != 1 {
		t.Fatalf("%d Deployments", len(deps))
	}
	spec := deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	ps, _ := spec["imagePullSecrets"].([]any)
	if len(ps) != 1 || ps[0].(map[string]any)["name"] != "ghcr-pull" {
		t.Fatalf("imagePullSecrets = %v", spec["imagePullSecrets"])
	}
}

// TestChartRefusesNoTelegramID: a missing Telegram user ID fails at render
// time instead of crash-looping the pod (found in review of #11).
func TestChartRefusesNoTelegramID(t *testing.T) {
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	out, err := exec.Command("helm", "template", "t", "nyyrikki", "-f", "nyyrikki/ci/test-values.yaml",
		"--kube-version", "1.35.0", "--set", "human.telegramUserID=0").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "telegramUserID") {
		t.Fatalf("rendered with telegramUserID 0: %s", out)
	}
}

func TestChartTrustedCA(t *testing.T) {
	deps := kind(render(t, "--set", "trustedCA.configMap=corp-ca"), "Deployment")
	if len(deps) != 1 {
		t.Fatalf("%d Deployments", len(deps))
	}
	spec := deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	ctr := spec["containers"].([]any)[0].(map[string]any)
	env, _ := ctr["env"].([]any)
	if len(env) != 1 || env[0].(map[string]any)["value"] != "/etc/ssl/certs:/etc/nyyrikki/trusted-ca" {
		t.Fatalf("env = %v", ctr["env"])
	}
	found := false
	for _, v := range spec["volumes"].([]any) {
		if cm, ok := v.(map[string]any)["configMap"].(map[string]any); ok && cm["name"] == "corp-ca" {
			found = true
		}
	}
	if !found {
		t.Fatal("no trusted-ca volume")
	}
	// Without the value, nothing is added.
	deps = kind(render(t), "Deployment")
	ctr = deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if _, ok := ctr["env"]; ok {
		t.Fatalf("env without trustedCA: %v", ctr["env"])
	}
}

var sshSet = []string{
	"--set", "targets[2].name=db-1", "--set", "targets[2].description=DB",
	"--set", "targets[2].ssh.address=db-1.example.com:2222",
	"--set", "targets[2].ssh.hostKeys[0]=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"--set", "targets[2].ssh.sudo=true", "--set", "targets[2].ssh.sessionKill=true",
	"--set", "ssh.userCAPublicKeys[0]=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y",
	"--set", "ssh.sourceAddresses[0]=203.0.113.10/32", "--set", "ssh.connectTimeout=7s",
	"--set", "secrets.sshUserCA.name=my-ca", "--set", "secrets.sshUserCA.key=ca-key",
}

func podSpec(t *testing.T, objs []object) map[string]any {
	t.Helper()
	deps := kind(objs, "Deployment")
	if len(deps) != 1 {
		t.Fatalf("%d Deployments", len(deps))
	}
	return deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}

// TestChartSSHTarget covers docs/07 §5.5: every SSH field reaches the
// binary's config, and the CA Secret is mounted at the fixed path, only
// when an SSH target exists.
func TestChartSSHTarget(t *testing.T) {
	objs := render(t, sshSet...)
	src := kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	c, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("config refused: %v\n%s", err, src)
	}
	db, ok := c.TargetByName("db-1")
	if !ok || db.SSH == nil || db.SSH.Address != "db-1.example.com:2222" || len(db.SSH.HostKeys) != 1 || !db.SSH.Sudo || !db.SSH.SessionKill || db.Description != "DB" {
		t.Fatalf("db-1 %+v", db)
	}
	if c.SSH.UserCAKeyFile != "/etc/nyyrikki/ssh/user-ca" || len(c.SSH.UserCAPublicKeys) != 1 || c.SSH.SourceAddresses[0] != "203.0.113.10/32" || c.SSH.ConnectTimeout.D().String() != "7s" {
		t.Fatalf("ssh %+v", c.SSH)
	}
	spec := podSpec(t, objs)
	var vol map[string]any
	for _, v := range spec["volumes"].([]any) {
		if v.(map[string]any)["name"] == "ssh-user-ca" {
			vol = v.(map[string]any)["secret"].(map[string]any)
		}
		if v.(map[string]any)["name"] == "target-db-1" {
			t.Error("an SSH target got a Kubernetes target volume")
		}
	}
	if vol == nil || vol["secretName"] != "my-ca" {
		t.Fatalf("CA volume %v", vol)
	}
	items := vol["items"].([]any)
	if it := items[0].(map[string]any); it["key"] != "ca-key" || it["path"] != "user-ca" {
		t.Fatalf("CA items %v", items)
	}
	mounted := false
	for _, m := range spec["containers"].([]any)[0].(map[string]any)["volumeMounts"].([]any) {
		if mm := m.(map[string]any); mm["name"] == "ssh-user-ca" && mm["mountPath"] == "/etc/nyyrikki/ssh" && mm["readOnly"] == true {
			mounted = true
		}
	}
	if !mounted {
		t.Fatal("CA not mounted at /etc/nyyrikki/ssh")
	}

	// Without an SSH target: no CA mount, no ssh block.
	objs = render(t)
	src = kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	if strings.Contains(src, "ssh:") {
		t.Errorf("ssh block without an SSH target:\n%s", src)
	}
	for _, v := range podSpec(t, objs)["volumes"].([]any) {
		if v.(map[string]any)["name"] == "ssh-user-ca" {
			t.Error("CA mounted without an SSH target")
		}
	}
}

// TestChartSSHRequiresShared: an SSH target without the CA keys or the
// source addresses fails at render time.
func TestChartSSHRequiresShared(t *testing.T) {
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	out, err := exec.Command("helm", "template", "t", "nyyrikki", "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0",
		"--set", "targets[2].name=db-1", "--set", "targets[2].ssh.address=db-1.example.com:22").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "ssh.userCAPublicKeys is required") {
		t.Fatalf("rendered without ssh values: %s", out)
	}
}

// TestChartSSHNotes: NOTES names each SSH target's setup command, and
// says runs wait for the host keys.
func TestChartSSHNotes(t *testing.T) {
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	// helm template skips NOTES.txt: render a copy of the chart in which
	// it is an ordinary template, with no cluster involved.
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("nyyrikki")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+"/templates/NOTES.txt", dir+"/notes.txt"); err != nil {
		t.Fatal(err)
	}
	wrap := "notes: |\n{{ tpl (.Files.Get \"notes.txt\") . | indent 2 }}\n"
	if err := os.WriteFile(dir+"/templates/notes-render.yaml", []byte(wrap), 0o644); err != nil {
		t.Fatal(err)
	}
	args := append(append([]string{"template", "t", dir, "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0",
		"--show-only", "templates/notes-render.yaml"}, sshSet...), "--set", "targets[2].ssh.hostKeys=null")
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh") {
		t.Fatalf("NOTES lack the setup command:\n%s", out)
	}
	if !strings.Contains(string(out), "Runs on db-1 are refused until") {
		t.Fatalf("NOTES don't say runs wait for host keys:\n%s", out)
	}
}
