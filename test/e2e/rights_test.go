//go:build e2e

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// privilegedPod is a pod that would be root on the kind node, and so on
// the host: what Pod Security must refuse wherever the human may create
// pods.
const privilegedPod = `apiVersion: v1
kind: Pod
metadata: {name: rights-check, namespace: %NS%}
spec:
  containers:
    - name: c
      image: ` + busyboxImage + `
      securityContext: {privileged: true}
      volumeMounts: [{name: host, mountPath: /host}]
  volumes: [{name: host, hostPath: {path: /}}]
`

// externalIPService takes over traffic for an address it names, the
// API server's included (CVE-2020-8554), if the API server lets it.
const externalIPService = `apiVersion: v1
kind: Service
metadata: {name: rights-check, namespace: %NS%}
spec:
  ports: [{port: 443}]
  externalIPs: [10.96.0.1]
`

// checkHumanRights checks that the stack gives the human no more than
// SECURITY.md's Accepted risks and docs/06 §6 allow: edit in the given
// namespaces under restricted Pod Security, nothing in Nyyrikki's
// namespace, nothing cluster-wide, and no privileged or hostPath pod. An
// elevation runs with exactly these rights.
func (e *env) checkHumanRights(t *testing.T, playground string) {
	t.Helper()
	can := func(args ...string) bool {
		t.Helper()
		// The answer is on stdout; stderr may carry a warning (for a
		// cluster-scoped resource named with -n, for example).
		var stderr strings.Builder
		cmd := exec.Command("kubectl", append([]string{"--kubeconfig", e.kubeconfig, "auth", "can-i", "--as=" + ownerK8sUser}, args...)...)
		cmd.Stderr = &stderr
		out, _ := cmd.Output()
		switch strings.TrimSpace(string(out)) {
		case "yes":
			return true
		case "no":
			return false
		}
		t.Fatalf("kubectl auth can-i %v: %s %s", args, out, stderr.String())
		return false
	}
	for _, args := range [][]string{
		{"get", "secrets", "-n", namespace},
		{"update", "configmaps", "-n", namespace},
		{"patch", "deployments", "-n", namespace},
		{"create", "pods", "-n", namespace},
		{"list", "pods", "--all-namespaces"},
		{"get", "secrets", "--all-namespaces"},
		{"create", "namespaces"},
		{"create", "clusterrolebindings"},
	} {
		if can(args...) {
			t.Errorf("the human can %v", args)
		}
	}
	for _, args := range [][]string{
		{"create", "pods", "-n", playground},
		{"create", "pods/exec", "-n", playground},
		{"delete", "pods", "-n", playground},
	} {
		if !can(args...) {
			t.Errorf("the human can't %v", args)
		}
	}
	for _, c := range []struct{ what, manifest, refusal string }{
		{"a privileged hostPath pod", privilegedPod, `violates PodSecurity "restricted`},
		{"a Service with externalIPs", externalIPService, "Use of external IPs is denied by admission control"},
	} {
		cmd := exec.Command("kubectl", "--kubeconfig", e.kubeconfig, "--as="+ownerK8sUser, "apply", "--dry-run=server", "-f", "-")
		cmd.Stdin = strings.NewReader(strings.ReplaceAll(c.manifest, "%NS%", playground))
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), c.refusal) {
			t.Errorf("%s in %s as the human: %v\n%s", c.what, playground, err, out)
		}
	}
}
