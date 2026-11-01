//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// The second release, in a namespace of its own, for the parts of
// docs/08 G15 that need a release of their own history: the upgrade that
// adds the first SSH target, a failed hook, and an R10 release. Its pod
// never starts (its Secrets don't exist there), and nothing here needs
// it: what is checked is what Helm and the hook leave in the namespace.
const (
	secondNS      = "nyyrikki-g15"
	secondRelease = "g15"
)

func (e *env) secondValues(extra string) string {
	return fmt.Sprintf(`image: {repository: nyyrikki, tag: e2e, pullPolicy: Never}
canonicalURL: https://g15.example.com
auth: {issuer: %s}
human:
  subject: %s
  kubernetes: {user: %s, groups: []}
  telegramUserID: %d
telegram: {apiURL: "https://127.0.0.1:9"}
%s`, e.issuer, e.ownerID, ownerK8sUser, approverID, extra)
}

const secondNoSSH = `targets:
  - name: this-cluster
    description: the kind cluster
    inCluster: true
`

const secondSSH = `targets:
  - name: this-cluster
    description: the kind cluster
    inCluster: true
  - name: db-9
    description: a host that doesn't exist
    ssh: {address: "192.0.2.9"}
ssh:
  sourceAddresses: [192.0.2.1/32]
`

// helm2 runs helm on the second release; it returns the output and the
// error, for the caller to judge.
func (e *env) helm2(t *testing.T, verb, values string, extra ...string) (string, error) {
	t.Helper()
	args := []string{"--kubeconfig", e.kubeconfig, verb, secondRelease, filepath.Join(e.root, "deploy/chart/nyyrikki"),
		"-n", secondNS, "-f", writeFile(t, e.dir, "values-g15.yaml", []byte(values))}
	out, err := exec.Command("helm", append(args, extra...)...).CombinedOutput()
	return string(out), err
}

// exists reports whether the namespaced object kind/name exists.
func (e *env) exists(t *testing.T, ns, kind, name string) bool {
	t.Helper()
	return exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "-n", ns, "get", kind, name).Run() == nil
}

func (e *env) noHookRBAC(t *testing.T, when string) {
	t.Helper()
	for _, k := range []string{"serviceaccount", "role", "rolebinding"} {
		if e.exists(t, secondNS, k, secondRelease+"-ssh-ca-init") {
			t.Fatalf("%s: the hook's %s is left", when, k)
		}
	}
}

func (e *env) secondRelease(t *testing.T) {
	e.kubectl(t, "create", "namespace", secondNS)
	t.Cleanup(func() {
		if os.Getenv("NYYRIKKI_E2E_KEEP") == "" {
			exec.Command("helm", "--kubeconfig", e.kubeconfig, "uninstall", secondRelease, "-n", secondNS).Run()
			exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "delete", "namespace", secondNS, "--wait=false").Run()
		}
	})
	step(t, "SE6: a release without an SSH target makes no CA Secret", func(t *testing.T) {
		if out, err := e.helm2(t, "install", e.secondValues(secondNoSSH)); err != nil {
			t.Fatalf("helm install: %v\n%s", err, out)
		}
		if e.exists(t, secondNS, "secret", caSecretName) || e.exists(t, secondNS, "job", secondRelease+"-ssh-ca-init") {
			t.Fatal("a release without an SSH target made the CA Secret or its hook")
		}
	})
	step(t, "SE6: a failed hook leaves no RBAC behind", func(t *testing.T) {
		// The hook's image can't be pulled (pullPolicy Never), so its Job
		// never completes, and the upgrade fails when it times out.
		out, err := e.helm2(t, "upgrade", e.secondValues(secondSSH), "--set", "image.tag=missing", "--timeout", "45s")
		if err == nil {
			t.Fatalf("an upgrade whose hook can't run succeeded:\n%s", out)
		}
		t.Logf("the failed upgrade: %v\n%s", err, out)
		e.noHookRBAC(t, "a failed hook")
		if e.exists(t, secondNS, "secret", caSecretName) {
			t.Fatal("a hook that never ran made the Secret")
		}
	})
	step(t, "SE6: the upgrade that adds the first SSH target makes the CA Secret", func(t *testing.T) {
		if out, err := e.helm2(t, "upgrade", e.secondValues(secondSSH), "--timeout", "180s"); err != nil {
			t.Fatalf("helm upgrade: %v\n%s", err, out)
		}
		var c caSecret
		e.kubectlJSON(t, &c, secondNS, caSecretName)
		want := map[string]string{"nyyrikki.dev/release": secondRelease, "nyyrikki.dev/component": "ssh-ca", "app.kubernetes.io/managed-by": "nyyrikki-ssh-ca"}
		if !reflect.DeepEqual(c.Labels, want) || len(c.Data) != 2 || c.Data["user-ca"] == "" || c.Data["host-ca"] == "" {
			t.Fatalf("the Secret: labels %v, keys %v", c.Labels, keysOf(c.Data))
		}
		e.noHookRBAC(t, "a hook that succeeded")
	})
	step(t, "SE6: an upgrade of an R10 release keeps its user CA and renders no hook", func(t *testing.T) {
		if out, err := exec.Command("helm", "--kubeconfig", e.kubeconfig, "uninstall", secondRelease, "-n", secondNS, "--wait").CombinedOutput(); err != nil {
			t.Fatalf("helm uninstall: %v\n%s", err, out)
		}
		e.kubectl(t, "-n", secondNS, "delete", "secret", "-l", "nyyrikki.dev/release="+secondRelease+",nyyrikki.dev/component=ssh-ca")
		key, pub, err := sshca.GenerateKey("")
		if err != nil {
			t.Fatal(err)
		}
		e.kubectl(t, "-n", secondNS, "create", "secret", "generic", "nyyrikki-ssh-user-ca", "--from-file=user-ca="+writeFile(t, e.dir, "r10-user-ca", key))
		var old caSecret
		e.kubectlJSON(t, &old, secondNS, "nyyrikki-ssh-user-ca")
		r10 := e.secondValues(secondSSH + fmt.Sprintf("  userCAPublicKeys: [%q]\nsecrets:\n  sshUserCA: {name: nyyrikki-ssh-user-ca}\n", sshca.AuthorizedKey(pub)))
		for _, verb := range []string{"install", "upgrade"} {
			if out, err := e.helm2(t, verb, r10); err != nil {
				t.Fatalf("helm %s of an R10 release: %v\n%s", verb, err, out)
			}
			if out, _ := exec.Command("helm", "--kubeconfig", e.kubeconfig, "-n", secondNS, "get", "hooks", secondRelease).CombinedOutput(); strings.Contains(string(out), "ssh-ca-init") {
				t.Fatalf("helm %s of an R10 release rendered the hook:\n%s", verb, out)
			}
			if e.exists(t, secondNS, "secret", caSecretName) || e.exists(t, secondNS, "job", secondRelease+"-ssh-ca-init") {
				t.Fatalf("helm %s of an R10 release made a CA", verb)
			}
			vols := e.kubectl(t, "-n", secondNS, "get", "deploy", secondRelease+"-nyyrikki", "-o", "jsonpath={.spec.template.spec.volumes}")
			if !strings.Contains(vols, `"secretName":"nyyrikki-ssh-user-ca"`) || strings.Contains(vols, `"secretName":"`+caSecretName+`"`) {
				t.Fatalf("helm %s of an R10 release mounts: %s", verb, vols)
			}
			var now caSecret
			e.kubectlJSON(t, &now, secondNS, "nyyrikki-ssh-user-ca")
			if !reflect.DeepEqual(now, old) {
				t.Fatalf("helm %s changed the R10 Secret", verb)
			}
		}
	})
}
