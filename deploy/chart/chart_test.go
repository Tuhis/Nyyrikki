// Package chart_test renders the Helm chart and checks what docs/06 G2
// requires. It needs helm; the chart gate runs it with
// NYYRIKKI_CHART_TESTS=1 (scripts/gates.sh), so a missing helm there fails
// instead of skipping.
package chart_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/Tuhis/Nyyrikki/internal/config"
)

type object = map[string]any

// TestMain pins the release namespace. Without it, helm template takes the
// namespace of the current kube context, which on CI's runners isn't
// "default", and the tests that expect the rendered namespace fail.
func TestMain(m *testing.M) {
	if err := os.Setenv("HELM_NAMESPACE", "default"); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

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
	"--set", "ssh.revokedUserCAKeys[0]=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
	"--set", "ssh.sourceAddresses[0]=203.0.113.10/32", "--set", "ssh.connectTimeout=7s",
	"--set", "secrets.sshCA.name=my-ca",
}

// extraKey sets an extra trusted user CA key (docs/08 D1).
var extraKey = []string{"--set", "ssh.userCAPublicKeys[0]=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y"}

// compatSet is sshSet with R10's deprecated secrets.sshUserCA and its CA
// key listed, as an R10 release has it (docs/08 D14).
var compatSet = append(append(append([]string(nil), sshSet...), extraKey...), "--set", "secrets.sshUserCA.name=old-ca", "--set", "secrets.sshUserCA.key=ca-key")

func podSpec(t *testing.T, objs []object) map[string]any {
	t.Helper()
	deps := kind(objs, "Deployment")
	if len(deps) != 1 {
		t.Fatalf("%d Deployments", len(deps))
	}
	return deps[0]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
}

// TestChartSSHTarget covers docs/07 §5.5 and docs/08 D14 (G12, Secret
// part): every SSH field reaches the binary's config, the three key files
// point into the mount, and the CA Secret is mounted whole at the fixed
// path, only when an SSH target exists.
func TestChartSSHTarget(t *testing.T) {
	objs := render(t, append(append(append([]string(nil), sshSet...), extraKey...), "--set", "ssh.generateCA=true")...)
	src := kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	c, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("config refused: %v\n%s", err, src)
	}
	db, ok := c.TargetByName("db-1")
	if !ok || db.SSH == nil || db.SSH.Address != "db-1.example.com:2222" || len(db.SSH.HostKeys) != 1 || !db.SSH.Sudo || !db.SSH.SessionKill || db.Description != "DB" {
		t.Fatalf("db-1 %+v", db)
	}
	if c.SSH.UserCAKeyFile != "/etc/nyyrikki/ssh/user-ca" || c.SSH.NextUserCAKeyFile != "/etc/nyyrikki/ssh/user-ca-next" ||
		c.SSH.HostCAKeyFile != "/etc/nyyrikki/ssh/host-ca" || len(c.SSH.UserCAPublicKeys) != 1 || len(c.SSH.RevokedUserCAKeys) != 1 ||
		c.SSH.SourceAddresses[0] != "203.0.113.10/32" || c.SSH.ConnectTimeout.D().String() != "7s" {
		t.Fatalf("ssh %+v", c.SSH)
	}
	vol := caVolume(t, objs)
	if vol == nil || vol["secretName"] != "my-ca" {
		t.Fatalf("CA volume %v", vol)
	}
	// Whole: no items, so user-ca-next and host-ca appear when present.
	if _, ok := vol["items"]; ok {
		t.Fatalf("CA volume lists items: %v", vol)
	}
	for _, v := range podSpec(t, objs)["volumes"].([]any) {
		if v.(map[string]any)["name"] == "target-db-1" {
			t.Error("an SSH target got a Kubernetes target volume")
		}
	}

	// user_ca_public_keys is optional now (docs/08 D1); the default Secret
	// name is nyyrikki-ssh-ca.
	objs = render(t, "--set", "targets[2].name=db-1", "--set", "targets[2].ssh.address=db-1.example.com:22",
		"--set", "ssh.sourceAddresses[0]=203.0.113.10/32")
	src = kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	if c, err := config.Parse([]byte(src)); err != nil || len(c.SSH.UserCAPublicKeys) != 0 || len(c.SSH.RevokedUserCAKeys) != 0 {
		t.Fatalf("config without extra keys refused: %v\n%s", err, src)
	}
	if vol := caVolume(t, objs); vol == nil || vol["secretName"] != "nyyrikki-ssh-ca" {
		t.Fatalf("default CA volume %v", vol)
	}

	// Without an SSH target: no CA mount, no ssh block.
	objs = render(t)
	src = kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	if strings.Contains(src, "ssh:") {
		t.Errorf("ssh block without an SSH target:\n%s", src)
	}
	if caVolume(t, objs) != nil {
		t.Error("CA mounted without an SSH target")
	}
}

// caVolume returns the CA Secret volume's secret source after checking
// its mount, or nil when there is none.
func caVolume(t *testing.T, objs []object) map[string]any {
	t.Helper()
	spec := podSpec(t, objs)
	var vol map[string]any
	for _, v := range spec["volumes"].([]any) {
		if v.(map[string]any)["name"] == "ssh-ca" {
			vol = v.(map[string]any)["secret"].(map[string]any)
		}
	}
	if vol == nil {
		return nil
	}
	n := 0
	for _, m := range spec["containers"].([]any)[0].(map[string]any)["volumeMounts"].([]any) {
		mm := m.(map[string]any)
		if mm["mountPath"] == "/etc/nyyrikki/ssh" {
			n++
			if mm["name"] != "ssh-ca" || mm["readOnly"] != true {
				t.Fatalf("mount %v", mm)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d mounts at /etc/nyyrikki/ssh, want exactly 1", n)
	}
	return vol
}

// TestChartSSHCompat covers docs/08 D14 (G12, G15): the deprecated
// secrets.sshUserCA, when set, is mounted as user-ca instead of sshCA (one
// Secret on the directory), no hook renders, no CronJobs by default, and
// an explicit generateCA true is refused.
func TestChartSSHCompat(t *testing.T) {
	objs := render(t, compatSet...)
	vol := caVolume(t, objs)
	if vol == nil || vol["secretName"] != "old-ca" {
		t.Fatalf("CA volume %v", vol)
	}
	items := vol["items"].([]any)
	if it := items[0].(map[string]any); len(items) != 1 || it["key"] != "ca-key" || it["path"] != "user-ca" {
		t.Fatalf("CA items %v", items)
	}
	if n := len(kind(objs, "Job")) + len(kind(objs, "CronJob")) + len(kind(objs, "Role")); n != 0 {
		t.Fatalf("%d hook, CronJob or Role objects in compatibility mode", n)
	}
	src := kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	if _, err := config.Parse([]byte(src)); err != nil {
		t.Fatalf("config refused: %v", err)
	}
	// caJobs can still be asked for, on secrets.sshCA.name.
	if n := len(kind(render(t, append(compatSet, "--set", "ssh.caJobs=true")...), "CronJob")); n != 4 {
		t.Fatalf("%d CronJobs with caJobs=true", n)
	}
	out, err := helmTemplate(t, append(compatSet, "--set", "ssh.generateCA=true")...)
	if err == nil || !strings.Contains(out, "ssh.generateCA can't be true while secrets.sshUserCA is set") {
		t.Fatalf("generateCA=true with sshUserCA rendered: %s", out)
	}
	// An R10 release upgraded without secrets.sshUserCA in its values
	// (it relied on the old default name) lists its CA key: the chart
	// refuses rather than make a CA no host trusts.
	out, err = helmTemplate(t, append(append([]string(nil), sshSet...), extraKey...)...)
	if err == nil || !strings.Contains(out, "set secrets.sshUserCA.name to its old default, nyyrikki-ssh-user-ca") {
		t.Fatalf("an R10-looking release rendered a hook: %s", out)
	}
	for _, v := range []string{"true", "false"} {
		if _, err := helmTemplate(t, append(append(append([]string(nil), sshSet...), extraKey...), "--set", "ssh.generateCA="+v)...); err != nil {
			t.Errorf("extra keys with generateCA=%s refused: %v", v, err)
		}
	}
}

func helmTemplate(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	args := append([]string{"template", "t", "nyyrikki", "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0"}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	return string(out), err
}

func annotations(o object) map[string]any {
	a, _ := o["metadata"].(map[string]any)["annotations"].(map[string]any)
	return a
}

func name(o object) string { return o["metadata"].(map[string]any)["name"].(string) }

func containerOf(t *testing.T, podSpec map[string]any) map[string]any {
	t.Helper()
	cs := podSpec["containers"].([]any)
	if len(cs) != 1 {
		t.Fatalf("%d containers", len(cs))
	}
	return cs[0].(map[string]any)
}

func args(c map[string]any) string {
	var out []string
	for _, a := range c["args"].([]any) {
		out = append(out, a.(string))
	}
	return strings.Join(out, " ")
}

// checkPodSecurity checks a hook or CronJob pod as the Deployment's.
func checkPodSecurity(t *testing.T, spec map[string]any, sa string) {
	t.Helper()
	if spec["serviceAccountName"] != sa || spec["automountServiceAccountToken"] != true || spec["restartPolicy"] != "Never" {
		t.Fatalf("pod spec %v", spec)
	}
	if sc := spec["securityContext"].(map[string]any); sc["runAsNonRoot"] != true {
		t.Fatalf("pod securityContext %v", sc)
	}
	c := containerOf(t, spec)
	if !strings.HasPrefix(c["image"].(string), "ghcr.io/tuhis/nyyrikki:") {
		t.Fatalf("image %v", c["image"])
	}
	if sc := c["securityContext"].(map[string]any); sc["readOnlyRootFilesystem"] != true || sc["allowPrivilegeEscalation"] != false {
		t.Fatalf("container securityContext %v", sc)
	}
	if _, ok := c["env"]; ok {
		t.Fatal("a CA pod has env")
	}
}

// TestChartSSHCAHook covers docs/08 D16 (G15, rendering): with an SSH
// target, a pre-install,pre-upgrade hook Job runs `ssh-ca init --create`
// for secrets.sshCA.name and the release; its ServiceAccount, Role and
// RoleBinding are hooks deleted after success and failure, and the Role
// grants only create on Secrets. The chart never templates the Secret.
func TestChartSSHCAHook(t *testing.T) {
	objs := render(t, sshSet...)
	for _, o := range objs {
		if o["kind"] == "Secret" {
			t.Fatalf("the chart templates a Secret: %v", name(o))
		}
	}
	jobs := kind(objs, "Job")
	if len(jobs) != 1 {
		t.Fatalf("%d Jobs", len(jobs))
	}
	job := jobs[0]
	a := annotations(job)
	if a["helm.sh/hook"] != "pre-install,pre-upgrade" || a["helm.sh/hook-weight"] != "-5" || a["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded" {
		t.Fatalf("Job annotations %v", a)
	}
	spec := job["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
	checkPodSecurity(t, spec, "t-ssh-ca-init")
	if got := args(containerOf(t, spec)); got != "ssh-ca init --create --name my-ca --release t" {
		t.Fatalf("Job args %q", got)
	}
	for _, k := range []string{"ServiceAccount", "Role", "RoleBinding"} {
		var found object
		for _, o := range kind(objs, k) {
			if name(o) == "t-ssh-ca-init" {
				found = o
			}
		}
		if found == nil {
			t.Fatalf("no hook %s", k)
		}
		a := annotations(found)
		if a["helm.sh/hook"] != "pre-install,pre-upgrade" || a["helm.sh/hook-weight"] != "-10" ||
			a["helm.sh/hook-delete-policy"] != "before-hook-creation,hook-succeeded,hook-failed" {
			t.Fatalf("hook %s annotations %v", k, a)
		}
		switch k {
		case "Role":
			rules := found["rules"].([]any)
			r := rules[0].(map[string]any)
			if len(rules) != 1 || fmt.Sprint(r["verbs"]) != "[create]" || fmt.Sprint(r["resources"]) != "[secrets]" || fmt.Sprint(r["apiGroups"]) != "[]" {
				t.Fatalf("hook Role grants %v", rules)
			}
		case "RoleBinding":
			subj := found["subjects"].([]any)[0].(map[string]any)
			if found["roleRef"].(map[string]any)["name"] != "t-ssh-ca-init" || subj["name"] != "t-ssh-ca-init" {
				t.Fatalf("hook RoleBinding %v", found)
			}
		}
	}

	// generateCA: false renders no hook; no SSH target renders none.
	for name, extra := range map[string][]string{
		"generateCA false":                   append(append([]string(nil), sshSet...), "--set", "ssh.generateCA=false"),
		"no SSH target":                      nil,
		"generateCA true without SSH target": {"--set", "ssh.generateCA=true"},
	} {
		objs := render(t, extra...)
		if n := len(kind(objs, "Job")) + len(kind(objs, "CronJob")); n != 0 {
			t.Errorf("%s: %d Jobs or CronJobs", name, n)
		}
	}
}

// TestChartSSHCACronJobs covers docs/08 D16 (G15, rendering and RBAC):
// four suspended CronJobs run the rotation commands in place on
// secrets.sshCA.name, with a ServiceAccount whose Role grants get and
// update on that one Secret only; they render when caJobs, which
// defaults to generateCA.
func TestChartSSHCACronJobs(t *testing.T) {
	objs := render(t, sshSet...)
	cjs := kind(objs, "CronJob")
	var names []string
	for _, cj := range cjs {
		names = append(names, name(cj))
		spec := cj["spec"].(map[string]any)
		if spec["suspend"] != true {
			t.Fatalf("%s is not suspended", name(cj))
		}
		pod := spec["jobTemplate"].(map[string]any)["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		checkPodSecurity(t, pod, "t-ssh-ca-rotate")
		cmd := strings.TrimPrefix(name(cj), "t-ssh-ca-")
		if got := args(containerOf(t, pod)); got != "ssh-ca "+cmd+" --in-cluster --name my-ca" {
			t.Fatalf("%s args %q", name(cj), got)
		}
		if annotations(cj)["helm.sh/hook"] != nil {
			t.Fatalf("%s is a hook", name(cj))
		}
	}
	if strings.Join(names, ",") != "t-ssh-ca-stage,t-ssh-ca-promote,t-ssh-ca-unstage,t-ssh-ca-add-host-ca" {
		t.Fatalf("CronJobs %v", names)
	}
	var role object
	for _, r := range kind(objs, "Role") {
		if name(r) == "t-ssh-ca-rotate" {
			role = r
		}
	}
	if role == nil {
		t.Fatal("no rotation Role")
	}
	rules := role["rules"].([]any)
	r := rules[0].(map[string]any)
	if len(rules) != 1 || fmt.Sprint(r["verbs"]) != "[get update]" || fmt.Sprint(r["resources"]) != "[secrets]" || fmt.Sprint(r["resourceNames"]) != "[my-ca]" {
		t.Fatalf("rotation Role grants %v", rules)
	}
	if len(kind(objs, "Role")) != 2 {
		t.Fatalf("%d Roles, want the hook's and the rotation's", len(kind(objs, "Role")))
	}

	// caJobs follows generateCA, and can be set either way on its own.
	for name, c := range map[string]struct {
		extra []string
		want  int
	}{
		"generateCA false":                 {[]string{"--set", "ssh.generateCA=false"}, 0},
		"generateCA false, caJobs true":    {[]string{"--set", "ssh.generateCA=false", "--set", "ssh.caJobs=true"}, 4},
		"generateCA default, caJobs false": {[]string{"--set", "ssh.caJobs=false"}, 0},
	} {
		objs := render(t, append(append([]string(nil), sshSet...), c.extra...)...)
		if n := len(kind(objs, "CronJob")); n != c.want {
			t.Errorf("%s: %d CronJobs, want %d", name, n, c.want)
		}
	}
}

// TestChartSSHRequiresShared: an SSH target without the source addresses
// fails at render time (the CA public keys are derived now, docs/08 D1).
func TestChartSSHRequiresShared(t *testing.T) {
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
	out, err := exec.Command("helm", "template", "t", "nyyrikki", "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0",
		"--set", "targets[2].name=db-1", "--set", "targets[2].ssh.address=db-1.example.com:22").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "ssh.sourceAddresses is required") {
		t.Fatalf("rendered without ssh values: %s", out)
	}
}

// notes renders NOTES.txt with extra values. helm template skips
// NOTES.txt: render a copy of the chart in which it is an ordinary
// template, with no cluster involved.
func notes(t *testing.T, extra ...string) string {
	t.Helper()
	if os.Getenv("NYYRIKKI_CHART_TESTS") != "1" {
		t.Skip("set NYYRIKKI_CHART_TESTS=1")
	}
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
	args := append([]string{"template", "t", dir, "-f", "nyyrikki/ci/test-values.yaml", "--kube-version", "1.35.0",
		"--show-only", "templates/notes-render.yaml"}, extra...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	return string(out)
}

// TestChartSSHNotes: NOTES names each SSH target's setup command, says
// runs wait for the host keys, and says where the CA Secret comes from,
// how to delete it and how to add a missing host-ca (docs/08 D14, D16).
func TestChartSSHNotes(t *testing.T) {
	out := notes(t, append(append([]string(nil), sshSet...), "--set", "targets[2].ssh.hostKeys=null")...)
	for _, want := range []string{
		"curl -fsSL https://nyyrikki.example.com/hosts/db-1/setup.sh | sudo sh",
		"Runs on db-1 are refused until",
		"The install hook made it",
		"kubectl -n default delete secret -l nyyrikki.dev/release=t,nyyrikki.dev/component=ssh-ca",
		"kubectl -n default create job --from=cronjob/t-ssh-ca-add-host-ca",
		"nyyrikkid enroll-token",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("NOTES lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "deprecated") {
		t.Errorf("NOTES call the new Secret deprecated:\n%s", out)
	}
	// Without the hook or the CronJobs, the workstation commands.
	out = notes(t, append(append([]string(nil), sshSet...), "--set", "ssh.generateCA=false")...)
	for _, want := range []string{"nyyrikkid ssh-ca init --namespace default --name my-ca | kubectl create -f -", "| nyyrikkid ssh-ca add-host-ca | kubectl replace -f -"} {
		if !strings.Contains(out, want) {
			t.Errorf("NOTES lack %q:\n%s", want, out)
		}
	}
}

// TestChartSSHNotesMigrate covers docs/08 D14: with secrets.sshUserCA set,
// NOTES says to migrate, in D14's three steps, in order, and how to
// recover from AlreadyExists.
func TestChartSSHNotesMigrate(t *testing.T) {
	out := notes(t, compatSet...)
	steps := []string{
		"secrets.sshUserCA is deprecated",
		"1. kubectl -n default get secret old-ca -o yaml",
		"nyyrikkid ssh-ca import --key ca-key --name my-ca --release t",
		"kubectl -n default create -f -",
		"2. Remove that key from ssh.userCAPublicKeys and unset secrets.sshUserCA",
		"3. After it, delete the Secret old-ca",
		"AlreadyExists, compare fingerprints",
	}
	at := 0
	for _, s := range steps {
		i := strings.Index(out[at:], s)
		if i < 0 {
			t.Fatalf("NOTES lack %q after the previous step:\n%s", s, out)
		}
		at += i
	}
	if strings.Contains(out, "kubectl apply") {
		t.Errorf("the migration uses apply:\n%s", out)
	}
}

// TestChartSSHDefaultsAndGroups covers docs/08 D11 and D9's config
// (G10): ssh.defaults.sudo, ssh.hostCAs, ssh.revokedHostKeys and groups
// reach the binary's parsed config; a target's sudo, when set, false
// included, wins over the default; an address without a port gets 22.
func TestChartSSHDefaultsAndGroups(t *testing.T) {
	const hostCA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGtQUDaOXFoxZXKtrCeRHnmb3cZC5ezAuP4rsLVI1r7Y org-ca"
	const revoked = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA1pOqjN/QGjUaHqnHAzBVwdRxUIgpdl7Py1pOPRn1Ch old-host"
	objs := render(t, append(sshSet,
		"--set", "targets[2].ssh.sudo=null",
		"--set", "targets[3].name=web-1", "--set", "targets[3].ssh.address=web-1.internal", "--set", "targets[3].ssh.sudo=false",
		"--set", "targets[4].name=web-2", "--set", "targets[4].ssh.address=web-2.internal",
		"--set", "ssh.defaults.sudo=true",
		"--set", "ssh.hostCAs[0]="+hostCA, "--set", "ssh.revokedHostKeys[0]="+revoked,
		"--set", "groups[0].name=web", "--set", "groups[0].targets={web-1,web-2}",
		"--set", "groups[1].name=all", "--set", "groups[1].targets={this-cluster,db-1,web-1}")...)
	src := kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	c, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("config refused: %v\n%s", err, src)
	}
	for name, want := range map[string]bool{"db-1": true, "web-1": false, "web-2": true} {
		tg, ok := c.TargetByName(name)
		if !ok || tg.SSH.Sudo != want {
			t.Errorf("%s: sudo %v, want %v", name, tg.SSH.Sudo, want)
		}
	}
	if w, _ := c.TargetByName("web-1"); w.SSH.Address != "web-1.internal:22" {
		t.Errorf("web-1 address %q", w.SSH.Address)
	}
	if !c.SSH.Defaults.Sudo || len(c.SSH.HostCAs) != 1 || c.SSH.HostCAs[0] != hostCA || len(c.SSH.RevokedHostKeys) != 1 || c.SSH.RevokedHostKeys[0] != revoked {
		t.Fatalf("ssh %+v", c.SSH)
	}
	web, ok := c.GroupByName("web")
	all, ok2 := c.GroupByName("all")
	if !ok || !ok2 || strings.Join(web.Targets, ",") != "web-1,web-2" || strings.Join(all.Targets, ",") != "this-cluster,db-1,web-1" {
		t.Fatalf("groups %+v", c.Groups)
	}

	// Without the new values, nothing changes: the default is false.
	objs = render(t, append(sshSet, "--set", "targets[2].ssh.sudo=null")...)
	c, err = config.Parse([]byte(kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	if db, _ := c.TargetByName("db-1"); db.SSH.Sudo || len(c.Groups) != 0 || len(c.SSH.HostCAs) != 0 {
		t.Fatalf("defaults: sudo %v, groups %v", db.SSH.Sudo, c.Groups)
	}
}

// TestChartGroupUnknownTarget: a group naming a target that doesn't
// exist renders, and nyyrikkid refuses the config (docs/08 D11).
func TestChartGroupUnknownTarget(t *testing.T) {
	objs := render(t, "--set", "groups[0].name=g", "--set", "groups[0].targets={nope}")
	src := kind(objs, "ConfigMap")[0]["data"].(map[string]any)["config.yaml"].(string)
	if _, err := config.Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "unknown target") {
		t.Fatalf("a group naming an unknown target: %v", err)
	}
}

// A quoted generateCA or caJobs ("false" as a string, --set-string) must
// not fall back to the default: rendering without Helm relies on
// generateCA: false to keep the hook's create grant out (docs/08 D16;
// round 1 of #42).
func TestChartSSHCAFlagsMustBeBool(t *testing.T) {
	for _, key := range []string{"ssh.generateCA", "ssh.caJobs"} {
		for _, v := range []string{"false", "true", "yes"} {
			out, err := helmTemplate(t, append(append([]string(nil), sshSet...), "--set-string", key+"="+v)...)
			if err == nil || !strings.Contains(out, key+" must be true, false or null (left unset)") {
				t.Errorf("%s=%q as a string: err %v\n%s", key, v, err, out)
			}
		}
	}
}
