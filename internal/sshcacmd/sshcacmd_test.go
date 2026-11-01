package sshcacmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"

	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

type result struct {
	code           int
	stdout, stderr string
}

func runCmd(t *testing.T, stdin string, client kubernetes.Interface, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		Client: func() (kubernetes.Interface, string, error) {
			if client == nil {
				t.Fatal("the Kubernetes client was used in manifest mode")
			}
			return client, "nyyrikki", nil
		}}
	code := Main(args, env)
	return result{code, out.String(), errb.String()}
}

// parse reads a printed manifest as a generic map, to see every field.
func parse(t *testing.T, s string) (map[string]any, *corev1.Secret) {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("output is not YAML: %v\n%s", err, s)
	}
	var sec corev1.Secret
	if err := yaml.Unmarshal([]byte(s), &sec); err != nil {
		t.Fatal(err)
	}
	return m, &sec
}

func pub(t *testing.T, b []byte) ssh.PublicKey {
	t.Helper()
	s, err := sshca.ParsePrivateKey(b)
	if err != nil {
		t.Fatalf("not a usable CA key: %v", err)
	}
	return s.PublicKey()
}

// noPrivate fails if s holds any private key material of sec.
func noPrivate(t *testing.T, what, s string, secs ...*corev1.Secret) {
	t.Helper()
	if strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "b3BlbnNzaC1rZXktdjE") {
		t.Fatalf("%s holds a private key:\n%s", what, s)
	}
	// An OpenSSH private key file embeds its public key, which promote
	// prints on purpose: strip every public key before looking for slices
	// of the private files, or a line that happens to align with the
	// public key's base64 is a false positive (seen as a flake on #42).
	for _, sec := range secs {
		for _, v := range sec.Data {
			if signer, err := ssh.ParsePrivateKey(v); err == nil {
				s = strings.ReplaceAll(s, base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal()), "")
			}
		}
	}
	for _, sec := range secs {
		for k, v := range sec.Data {
			for _, line := range strings.Split(string(v), "\n") {
				if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(s, line[:16]) {
					t.Fatalf("%s holds part of %s", what, k)
				}
			}
		}
	}
}

// allowedFields checks D2's output rule: only apiVersion, kind,
// metadata.name, metadata.namespace, type and data, plus D16's labels and
// annotations when labelled.
// allowedUpdateFields: a read-modify-write output keeps the read Secret's
// labels, annotations and resourceVersion for kubectl replace, nothing else.
func allowedUpdateFields(t *testing.T, m map[string]any) {
	t.Helper()
	for k := range m {
		if !slices.Contains([]string{"apiVersion", "kind", "metadata", "type", "data"}, k) {
			t.Errorf("output keeps %s", k)
		}
	}
	for k := range m["metadata"].(map[string]any) {
		if !slices.Contains([]string{"name", "namespace", "labels", "annotations", "resourceVersion"}, k) {
			t.Errorf("output keeps metadata.%s", k)
		}
	}
}

func allowedFields(t *testing.T, m map[string]any, labelled bool) {
	t.Helper()
	for k := range m {
		if !slices.Contains([]string{"apiVersion", "kind", "metadata", "type", "data"}, k) {
			t.Errorf("output keeps %s", k)
		}
	}
	allowed := []string{"name", "namespace"}
	if labelled {
		allowed = append(allowed, "labels", "annotations")
	}
	for k := range m["metadata"].(map[string]any) {
		if !slices.Contains(allowed, k) {
			t.Errorf("output keeps metadata.%s", k)
		}
	}
	if !labelled {
		return
	}
	want := map[string]string{LabelRelease: "rel", LabelComponent: "ssh-ca", LabelManagedBy: "nyyrikki-ssh-ca"}
	labels := m["metadata"].(map[string]any)["labels"].(map[string]any)
	if len(labels) != len(want) {
		t.Errorf("labels %v", labels)
	}
	for k, v := range want {
		if labels[k] != v {
			t.Errorf("label %s = %v, want %s", k, labels[k], v)
		}
	}
	if _, ok := labels["app.kubernetes.io/instance"]; ok {
		t.Error("the Secret carries app.kubernetes.io/instance")
	}
	ann := m["metadata"].(map[string]any)["annotations"].(map[string]any)
	if len(ann) != 2 || ann[AnnotationResourcePolicy] != "keep" || ann[AnnotationArgoCompare] != "IgnoreExtraneous" {
		t.Errorf("annotations %v", ann)
	}
}

func dataKeys(s *corev1.Secret) []string {
	var ks []string
	for k := range s.Data {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func initSecret(t *testing.T) (string, *corev1.Secret) {
	t.Helper()
	r := runCmd(t, "", nil, "init", "--namespace", "nyyrikki", "--release", "rel")
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
	_, s := parse(t, r.stdout)
	return r.stdout, s
}

// TestSSHCACommandInit covers docs/08 G2: init prints a Secret with two
// fresh ed25519 keys, user-ca and host-ca, and nothing else; labelled as
// D16 says; fingerprints only on stderr.
func TestSSHCACommandInit(t *testing.T) {
	r := runCmd(t, "", nil, "init", "--namespace", "nyyrikki", "--release", "rel")
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
	m, s := parse(t, r.stdout)
	allowedFields(t, m, true)
	if s.Name != DefaultName || s.Namespace != "nyyrikki" || s.Type != corev1.SecretTypeOpaque || s.Kind != "Secret" || s.APIVersion != "v1" {
		t.Fatalf("secret %+v", s.ObjectMeta)
	}
	if got := dataKeys(s); !slices.Equal(got, []string{"host-ca", "user-ca"}) {
		t.Fatalf("data keys %v", got)
	}
	u, h := pub(t, s.Data["user-ca"]), pub(t, s.Data["host-ca"])
	if bytes.Equal(u.Marshal(), h.Marshal()) {
		t.Fatal("user-ca and host-ca are the same key")
	}
	if !strings.Contains(r.stderr, ssh.FingerprintSHA256(u)) || !strings.Contains(r.stderr, ssh.FingerprintSHA256(h)) {
		t.Fatalf("stderr lacks the fingerprints: %s", r.stderr)
	}
	noPrivate(t, "stderr", r.stderr, s)
	_, s2 := initSecret(t)
	if bytes.Equal(s2.Data["user-ca"], s.Data["user-ca"]) {
		t.Fatal("two inits made the same key")
	}
	// Without --namespace, none is printed: kubectl's context decides.
	r = runCmd(t, "", nil, "init")
	m, _ = parse(t, r.stdout)
	if _, ok := m["metadata"].(map[string]any)["namespace"]; ok || r.code != 0 {
		t.Fatalf("namespace printed without --namespace: %v", m["metadata"])
	}
}

// TestSSHCACommandStagePromote covers G2: stage adds user-ca-next and
// refuses if one exists; promote moves it to user-ca, drops the old key,
// and prints the old public key on stderr; outputs keep only D2's fields
// and stderr never a private key. The input's other fields (as kubectl
// get prints them) are dropped.
func TestSSHCACommandStagePromote(t *testing.T) {
	orig, s0 := initSecret(t)
	// What kubectl get adds.
	got := strings.Replace(orig, "metadata:\n", "metadata:\n  uid: 1234\n  resourceVersion: \"7\"\n  creationTimestamp: \"2026-10-31T00:00:00Z\"\n  managedFields: []\n", 1)
	r := runCmd(t, got, nil, "stage")
	if r.code != 0 {
		t.Fatalf("stage: %d %s", r.code, r.stderr)
	}
	m, s1 := parse(t, r.stdout)
	allowedUpdateFields(t, m)
	if !slices.Equal(dataKeys(s1), []string{"host-ca", "user-ca", "user-ca-next"}) ||
		!bytes.Equal(s1.Data["user-ca"], s0.Data["user-ca"]) || !bytes.Equal(s1.Data["host-ca"], s0.Data["host-ca"]) {
		t.Fatalf("stage changed more than user-ca-next: %v", dataKeys(s1))
	}
	next := pub(t, s1.Data["user-ca-next"])
	if !strings.Contains(r.stderr, ssh.FingerprintSHA256(next)) {
		t.Fatalf("stage stderr %s", r.stderr)
	}
	noPrivate(t, "stage stderr", r.stderr, s1)

	// Stage refuses a second staged key. The refusal prints nothing.
	staged := strings.Replace(r.stdout, "metadata:\n", "metadata:\n  labels:\n    nyyrikki.dev/component: ssh-ca\n", 1)
	if r := runCmd(t, staged, nil, "stage"); r.code == 0 || r.stdout != "" || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("second stage: %+v", r)
	}

	r = runCmd(t, staged, nil, "promote")
	if r.code != 0 {
		t.Fatalf("promote: %d %s", r.code, r.stderr)
	}
	m, s2 := parse(t, r.stdout)
	allowedUpdateFields(t, m)
	if !slices.Equal(dataKeys(s2), []string{"host-ca", "user-ca"}) || !bytes.Equal(s2.Data["user-ca"], s1.Data["user-ca-next"]) ||
		!bytes.Equal(s2.Data["host-ca"], s0.Data["host-ca"]) {
		t.Fatalf("promote: %v", dataKeys(s2))
	}
	old := pub(t, s0.Data["user-ca"])
	if !strings.Contains(r.stderr, sshca.AuthorizedKey(old)) {
		t.Fatalf("promote doesn't print the old public key: %s", r.stderr)
	}
	noPrivate(t, "promote stderr", r.stderr, s0, s1)

	// Promote without a staged key refuses.
	if r := runCmd(t, orig, nil, "promote"); r.code == 0 || r.stdout != "" {
		t.Fatalf("promote without user-ca-next: %+v", r)
	}
}

// TestSSHCACommandUnstageAddHostCA covers G2 and G15's command part:
// unstage removes user-ca-next only (a broken one too); add-host-ca adds
// a missing host-ca only, and refuses when one exists.
func TestSSHCACommandUnstageAddHostCA(t *testing.T) {
	orig, s0 := initSecret(t)
	r := runCmd(t, orig, nil, "stage")
	labelled := strings.Replace(r.stdout, "metadata:\n", "metadata:\n  labels:\n    nyyrikki.dev/component: ssh-ca\n", 1)
	r = runCmd(t, labelled, nil, "unstage")
	_, s := parse(t, r.stdout)
	if r.code != 0 || !slices.Equal(dataKeys(s), []string{"host-ca", "user-ca"}) || !bytes.Equal(s.Data["user-ca"], s0.Data["user-ca"]) {
		t.Fatalf("unstage: %+v", r)
	}
	if r := runCmd(t, orig, nil, "unstage"); r.code == 0 || r.stdout != "" {
		t.Fatalf("unstage with nothing staged: %+v", r)
	}
	// A half-written staged key can be removed: that is the repair.
	broken := strings.Replace(orig, "data:\n", "data:\n  user-ca-next: eA==\n", 1)
	if r := runCmd(t, broken, nil, "unstage"); r.code != 0 {
		t.Fatalf("unstage of a broken key: %+v", r)
	}
	// ...but nothing else accepts it.
	for _, c := range []string{"stage", "promote", "add-host-ca"} {
		if r := runCmd(t, broken, nil, c); r.code == 0 {
			t.Fatalf("%s accepted a broken user-ca-next", c)
		}
	}

	if r := runCmd(t, orig, nil, "add-host-ca"); r.code == 0 || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("add-host-ca with host-ca: %+v", r)
	}
	noHost := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "x", Labels: map[string]string{LabelComponent: ComponentSSHCA}},
		Data:       map[string][]byte{"user-ca": s0.Data["user-ca"]}}
	in, _ := yaml.Marshal(noHost)
	r = runCmd(t, string(in), nil, "add-host-ca")
	m, s := parse(t, r.stdout)
	if r.code != 0 || !slices.Equal(dataKeys(s), []string{"host-ca", "user-ca"}) || !bytes.Equal(s.Data["user-ca"], s0.Data["user-ca"]) {
		t.Fatalf("add-host-ca: %+v", r)
	}
	allowedUpdateFields(t, m)
	pub(t, s.Data["host-ca"])
	noPrivate(t, "add-host-ca stderr", r.stderr, s)
}

// TestSSHCACommandRefusals covers D2: the rotation commands refuse a
// Secret without nyyrikki.dev/component=ssh-ca (an R10 Secret in
// compatibility mode), with other data keys, with stringData, or that
// isn't a Secret; none prints anything on stdout.
func TestSSHCACommandRefusals(t *testing.T) {
	_, s0 := initSecret(t)
	mk := func(mod func(s *corev1.Secret)) string {
		s := s0.DeepCopy()
		mod(s)
		b, _ := yaml.Marshal(s)
		return string(b)
	}
	cases := map[string]string{
		"no label": mk(func(s *corev1.Secret) { delete(s.Labels, LabelComponent) }),
		"R10 Secret": mk(func(s *corev1.Secret) {
			s.Labels = nil
			s.Data = map[string][]byte{"user-ca": s.Data["user-ca"]}
		}),
		"other data key":  mk(func(s *corev1.Secret) { s.Data["ca-key"] = s.Data["user-ca"] }),
		"stringData":      mk(func(s *corev1.Secret) { s.StringData = map[string]string{"user-ca-next": "x"} }),
		"no user-ca":      mk(func(s *corev1.Secret) { delete(s.Data, "user-ca") }),
		"user-ca garbage": mk(func(s *corev1.Secret) { s.Data["user-ca"] = []byte("garbage") }),
		"host-ca garbage": mk(func(s *corev1.Secret) { s.Data["host-ca"] = []byte("garbage") }),
		"wrong kind":      mk(func(s *corev1.Secret) { s.Kind = "ConfigMap" }),
		"wrong type":      mk(func(s *corev1.Secret) { s.Type = corev1.SecretTypeTLS }),
		"not YAML":        "{{{",
		"empty":           "",
		"other component": mk(func(s *corev1.Secret) { s.Labels[LabelComponent] = "ssh-ca-not" }),
	}
	for name, in := range cases {
		for _, c := range []string{"stage", "promote", "unstage", "add-host-ca"} {
			r := runCmd(t, in, nil, c)
			if r.code == 0 || r.stdout != "" {
				t.Errorf("%s: %s accepted: %+v", name, c, r)
			}
			noPrivate(t, name+" "+c+" stderr", r.stderr, s0)
		}
	}
	// An unknown command or stray argument is a usage error.
	if r := runCmd(t, "", nil, "rotate"); r.code != 2 {
		t.Errorf("unknown command: %+v", r)
	}
	if r := runCmd(t, "", nil, "init", "extra"); r.code != 2 || r.stdout != "" {
		t.Errorf("stray argument: %+v", r)
	}
	if r := runCmd(t, "", nil, "init", "--name", "Not_A_Name"); r.code != 2 || r.stdout != "" {
		t.Errorf("bad name: %+v", r)
	}
}

// TestSSHCACommandImport covers D2 and D14: import reads an R10 Secret
// (with R10's configurable key name) and prints a new, labelled Secret
// with that key as user-ca, byte for byte, and a fresh host-ca; stderr
// has the imported key's fingerprint and no private key.
func TestSSHCACommandImport(t *testing.T) {
	keyPEM, keyPub, _ := sshca.GenerateKey("nyyrikki-user-ca")
	r10 := &corev1.Secret{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: "nyyrikki-ssh-user-ca", Namespace: "nyyrikki", UID: "u", ResourceVersion: "3"},
		Type:       corev1.SecretTypeOpaque, Data: map[string][]byte{"ca-key": keyPEM}}
	in, _ := yaml.Marshal(r10)

	r := runCmd(t, string(in), nil, "import", "--key", "ca-key", "--release", "rel")
	if r.code != 0 {
		t.Fatalf("import: %d %s", r.code, r.stderr)
	}
	m, s := parse(t, r.stdout)
	allowedFields(t, m, true)
	if s.Name != DefaultName || s.Namespace != "nyyrikki" || !slices.Equal(dataKeys(s), []string{"host-ca", "user-ca"}) ||
		!bytes.Equal(s.Data["user-ca"], keyPEM) {
		t.Fatalf("import: %+v %v", s.ObjectMeta, dataKeys(s))
	}
	pub(t, s.Data["host-ca"])
	if !strings.Contains(r.stderr, ssh.FingerprintSHA256(keyPub)) {
		t.Fatalf("stderr lacks the imported key's fingerprint: %s", r.stderr)
	}
	noPrivate(t, "import stderr", r.stderr, s)
	// The imported Secret can then be rotated.
	if r := runCmd(t, r.stdout, nil, "stage"); r.code != 0 {
		t.Fatalf("stage after import: %+v", r)
	}

	// Refusals: a missing key, a key that isn't an ed25519 CA key.
	if r := runCmd(t, string(in), nil, "import"); r.code == 0 || r.stdout != "" || !strings.Contains(r.stderr, "--key") {
		t.Fatalf("import without the key: %+v", r)
	}
	bad := r10.DeepCopy()
	bad.Data["ca-key"] = []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nxx\n-----END OPENSSH PRIVATE KEY-----\n")
	in, _ = yaml.Marshal(bad)
	if r := runCmd(t, string(in), nil, "import", "--key", "ca-key"); r.code == 0 || r.stdout != "" {
		t.Fatalf("import of garbage: %+v", r)
	}
}

func fakeClient(objs ...runtime.Object) *fake.Clientset { return fake.NewClientset(objs...) }

// TestSSHCACommandCreate covers D16's hook: init --create creates the
// Secret with two fresh keys and D16's labels, in the pod's namespace,
// and prints only fingerprints. An existing Secret is success and is
// neither read, patched nor changed. Any other API error fails.
func TestSSHCACommandCreate(t *testing.T) {
	c := fakeClient()
	r := runCmd(t, "", c, "init", "--create", "--name", "ca", "--release", "rel")
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("create: %+v", r)
	}
	s, err := c.CoreV1().Secrets("nyyrikki").Get(context.Background(), "ca", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Labels[LabelRelease] != "rel" || s.Labels[LabelComponent] != "ssh-ca" || s.Labels[LabelManagedBy] != "nyyrikki-ssh-ca" || len(s.Labels) != 3 ||
		s.Annotations[AnnotationResourcePolicy] != "keep" || s.Annotations[AnnotationArgoCompare] != "IgnoreExtraneous" || s.Type != corev1.SecretTypeOpaque {
		t.Fatalf("metadata %+v", s.ObjectMeta)
	}
	if !slices.Equal(dataKeys(s), []string{"host-ca", "user-ca"}) {
		t.Fatalf("data %v", dataKeys(s))
	}
	if !strings.Contains(r.stderr, ssh.FingerprintSHA256(pub(t, s.Data["user-ca"]))) || !strings.Contains(r.stderr, ssh.FingerprintSHA256(pub(t, s.Data["host-ca"]))) {
		t.Fatalf("stderr %s", r.stderr)
	}
	noPrivate(t, "create stderr", r.stderr, s)

	// AlreadyExists: success, and nothing but the one create is sent.
	existing := s.DeepCopy()
	c = fakeClient(existing.DeepCopy())
	r = runCmd(t, "", c, "init", "--create", "--name", "ca", "--release", "rel")
	if r.code != 0 || r.stdout != "" || !strings.Contains(r.stderr, "already exists") {
		t.Fatalf("existing: %+v", r)
	}
	for _, a := range c.Actions() {
		if a.GetVerb() != "create" {
			t.Fatalf("the hook sent %s on an existing Secret", a.GetVerb())
		}
	}
	after, _ := c.CoreV1().Secrets("nyyrikki").Get(context.Background(), "ca", metav1.GetOptions{})
	if !bytes.Equal(after.Data["user-ca"], existing.Data["user-ca"]) || !bytes.Equal(after.Data["host-ca"], existing.Data["host-ca"]) || len(after.Data) != 2 {
		t.Fatal("the existing Secret changed")
	}
	noPrivate(t, "existing stderr", r.stderr, existing)

	// Any other error fails the hook.
	for name, e := range map[string]error{
		"forbidden":   apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("no")),
		"unavailable": apierrors.NewServiceUnavailable("down"),
		"conflict":    apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("x")),
	} {
		c := fakeClient()
		c.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, e })
		r := runCmd(t, "", c, "init", "--create")
		if r.code == 0 {
			t.Errorf("%s: succeeded", name)
		}
		if strings.Contains(r.stderr, "PRIVATE KEY") {
			t.Errorf("%s: stderr holds a key", name)
		}
	}
	// No client: fail.
	var errb bytes.Buffer
	if code := Main([]string{"init", "--create"}, Env{Stdout: &bytes.Buffer{}, Stderr: &errb,
		Client: func() (kubernetes.Interface, string, error) { return nil, "", errors.New("not in a pod") }}); code == 0 {
		t.Error("succeeded without a client")
	}
}

// TestSSHCACommandInCluster covers D16's CronJobs: --in-cluster gets the
// Secret, applies the command, and updates it in place with the
// resourceVersion read; it refuses what manifest mode refuses, prints
// nothing on stdout, and never a private key on stderr.
func TestSSHCACommandInCluster(t *testing.T) {
	_, s0 := initSecret(t)
	s0.Name, s0.Namespace, s0.ResourceVersion = "ca", "nyyrikki", "5"
	c := fakeClient(s0.DeepCopy())
	get := func() *corev1.Secret {
		s, err := c.CoreV1().Secrets("nyyrikki").Get(context.Background(), "ca", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	var updatedRV string
	c.PrependReactor("update", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		updatedRV = a.(k8stesting.UpdateAction).GetObject().(*corev1.Secret).ResourceVersion
		return false, nil, nil
	})

	r := runCmd(t, "", c, "stage", "--in-cluster", "--name", "ca")
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("stage: %+v", r)
	}
	s1 := get()
	if updatedRV != "5" || !slices.Equal(dataKeys(s1), []string{"host-ca", "user-ca", "user-ca-next"}) || !bytes.Equal(s1.Data["user-ca"], s0.Data["user-ca"]) {
		t.Fatalf("stage: rv %q, %v", updatedRV, dataKeys(s1))
	}
	if s1.Labels[LabelComponent] != "ssh-ca" || s1.Annotations[AnnotationResourcePolicy] != "keep" {
		t.Fatal("the update dropped the labels")
	}
	noPrivate(t, "stage stderr", r.stderr, s1)

	r = runCmd(t, "", c, "promote", "--in-cluster", "--name", "ca")
	s2 := get()
	if r.code != 0 || !bytes.Equal(s2.Data["user-ca"], s1.Data["user-ca-next"]) || len(s2.Data) != 2 {
		t.Fatalf("promote: %+v", r)
	}
	if !strings.Contains(r.stderr, sshca.AuthorizedKey(pub(t, s0.Data["user-ca"]))) {
		t.Fatalf("promote's log lacks the old public key: %s", r.stderr)
	}
	noPrivate(t, "promote stderr", r.stderr, s0, s1)

	// A refused command changes nothing.
	r = runCmd(t, "", c, "add-host-ca", "--in-cluster", "--name", "ca")
	if r.code == 0 || !bytes.Equal(get().Data["host-ca"], s0.Data["host-ca"]) {
		t.Fatalf("add-host-ca over an existing host-ca: %+v", r)
	}
	// An R10 Secret is refused in place too.
	r10 := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "old", Namespace: "nyyrikki"}, Data: map[string][]byte{"user-ca": s0.Data["user-ca"]}}
	c2 := fakeClient(r10)
	if r := runCmd(t, "", c2, "stage", "--in-cluster", "--name", "old"); r.code == 0 {
		t.Fatal("staged an R10 Secret in place")
	}
	for _, a := range c2.Actions() {
		if a.GetVerb() != "get" {
			t.Fatalf("sent %s to an R10 Secret", a.GetVerb())
		}
	}
	// A missing Secret and a conflicting update fail.
	if r := runCmd(t, "", fakeClient(), "stage", "--in-cluster", "--name", "ca"); r.code == 0 {
		t.Fatal("staged a missing Secret")
	}
	c3 := fakeClient(s0.DeepCopy())
	c3.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, "ca", errors.New("changed"))
	})
	if r := runCmd(t, "", c3, "stage", "--in-cluster", "--name", "ca"); r.code == 0 {
		t.Fatal("a conflicting update succeeded")
	}
}

// The read-modify-write commands are piped into "kubectl replace -f -":
// kubectl apply keeps data keys that aren't in its last-applied annotation,
// so an unstage or promote would report success and leave user-ca-next
// (review of #42). replace needs the labels the commands check, and the
// resourceVersion read, so a concurrent change fails; the last-applied
// annotation, which holds a copy of the private keys, is dropped.
func TestSSHCACommandReplaceKeepsMetadata(t *testing.T) {
	orig, _ := initSecret(t)
	r := runCmd(t, orig, nil, "stage")
	if r.code != 0 {
		t.Fatalf("stage: %d %s", r.code, r.stderr)
	}
	in := strings.Replace(r.stdout, "metadata:\n", "metadata:\n  resourceVersion: \"7\"\n  uid: abc\n"+
		"  labels:\n    nyyrikki.dev/component: ssh-ca\n    nyyrikki.dev/release: rel\n"+
		"  annotations:\n    helm.sh/resource-policy: keep\n    kubectl.kubernetes.io/last-applied-configuration: '{\"data\":{\"user-ca\":\"c2VjcmV0\"}}'\n", 1)
	for _, cmd := range []string{"unstage", "promote"} {
		r := runCmd(t, in, nil, cmd)
		if r.code != 0 {
			t.Fatalf("%s: %d %s", cmd, r.code, r.stderr)
		}
		_, s := parse(t, r.stdout)
		if s.ResourceVersion != "7" {
			t.Errorf("%s: resourceVersion %q, want 7", cmd, s.ResourceVersion)
		}
		if s.UID != "" {
			t.Errorf("%s: keeps uid", cmd)
		}
		if s.Labels[LabelComponent] != ComponentSSHCA || s.Labels[LabelRelease] != "rel" {
			t.Errorf("%s: labels %v", cmd, s.Labels)
		}
		if _, ok := s.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; ok {
			t.Errorf("%s: keeps the last-applied annotation", cmd)
		}
		if s.Annotations["helm.sh/resource-policy"] != "keep" {
			t.Errorf("%s: annotations %v", cmd, s.Annotations)
		}
		if _, ok := s.Data["user-ca-next"]; ok {
			t.Errorf("%s: user-ca-next left", cmd)
		}
	}
}
