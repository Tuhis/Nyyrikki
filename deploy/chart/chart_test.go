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
			if _, ok := ctr["env"]; ok {
				t.Fatal("container has env; credentials must be files (docs/01 D15)")
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
	objs := render(t, "--set", "targets[0].name=a", "--set", "targets[0].inCluster=true",
		"--set", "targets[1].name=b", "--set", "targets[1].inCluster=true")
	for _, d := range kind(objs, "Deployment") {
		spec := d["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)
		if spec["automountServiceAccountToken"] != true {
			t.Fatalf("automountServiceAccountToken = %v with two in-cluster targets", spec["automountServiceAccountToken"])
		}
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
