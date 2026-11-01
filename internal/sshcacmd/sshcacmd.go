// Package sshcacmd is `nyyrikkid ssh-ca` (docs/08 D2, D16): it makes and
// rotates the SSH CA Secret. By default it reads and writes a Secret
// manifest on stdin and stdout and holds no Kubernetes client, for an
// administrator's machine. `init --create` and `--in-cluster` act on the
// Secret through the Kubernetes API with the pod's ServiceAccount, for the
// chart's install hook and rotation CronJobs.
//
// Private keys go only to stdout in manifest mode, or to the API. Nothing
// private is ever written to stderr, which is what a Job's log holds.
package sshcacmd

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"

	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// Labels and annotations of the CA Secret (docs/08 D16). Deliberately no
// app.kubernetes.io/instance: Argo CD would count the Secret as part of
// the app and prune it.
const (
	LabelRelease   = "nyyrikki.dev/release"
	LabelComponent = "nyyrikki.dev/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"

	ComponentSSHCA = "ssh-ca"
	ManagedBy      = "nyyrikki-ssh-ca"

	AnnotationResourcePolicy = "helm.sh/resource-policy"
	AnnotationArgoCompare    = "argocd.argoproj.io/compare-options"
)

// Defaults of the flags.
const (
	DefaultName    = "nyyrikki-ssh-ca"
	DefaultRelease = "nyyrikki"
)

// Key comments of the generated keys.
const (
	commentUser = "nyyrikki-user-ca"
	commentHost = "nyyrikki-host-ca"
)

// maxManifest bounds what is read from stdin.
const maxManifest = 1 << 20

// apiTimeout bounds every call to the Kubernetes API.
const apiTimeout = time.Minute

// saNamespaceFile holds the pod's namespace.
const saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Env is the command's surroundings, replaceable in tests.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Client returns a Kubernetes client and the pod's namespace; only
	// --create and --in-cluster call it.
	Client func() (kubernetes.Interface, string, error)
}

// InCluster is Env.Client for a pod: its ServiceAccount and namespace.
func InCluster() (kubernetes.Interface, string, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", err
	}
	c, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	ns, err := os.ReadFile(saNamespaceFile)
	if err != nil {
		return nil, "", fmt.Errorf("read the pod's namespace: %w", err)
	}
	return c, strings.TrimSpace(string(ns)), nil
}

const usage = `usage: nyyrikkid ssh-ca COMMAND [flags]

Makes and rotates Nyyrikki's SSH CA Secret (docs/08 D2, D16). The Secret
holds user-ca, and optionally user-ca-next (a staged rotation) and host-ca
(enrollment), each an ed25519 OpenSSH private key.

By default a command reads a Secret manifest on stdin and prints the new
one on stdout; no Kubernetes client is used. Private keys pass only
through that pipe, never through stderr. Use init and import with
"kubectl create -f -", never apply, so an existing Secret is not
overwritten; use the others with "kubectl get secret NAME -o yaml |" in
front and "| kubectl replace -f -" after, never apply, which would keep a
data key the command removed:

  nyyrikkid ssh-ca init --namespace nyyrikki | kubectl create -f -
  kubectl get secret nyyrikki-ssh-user-ca -o yaml | nyyrikkid ssh-ca import | kubectl create -f -
  kubectl get secret nyyrikki-ssh-ca -o yaml | nyyrikkid ssh-ca stage | kubectl replace -f -

Commands:
  init         print a new Secret with fresh user-ca and host-ca
               (no stdin). Flags: --name, --namespace, --release.
               --create: create it through the Kubernetes API instead, with
               the pod's ServiceAccount (the chart's install hook). A Secret
               that already exists is left as it is, unread, and that is
               success. Prints only fingerprints.
  import       read an R10 Secret and print a new one with its key as
               user-ca and a fresh host-ca; prints the imported key's
               fingerprint on stderr. Flags: --key (default user-ca),
               --name, --namespace (default: the input's), --release.
  stage        add a fresh user-ca-next; refuses if one exists.
  promote      move user-ca-next to user-ca and drop the old key; prints
               the old public key on stderr, for ssh.revoked_user_ca_keys
               after a leak.
  unstage      remove user-ca-next.
  add-host-ca  add a fresh host-ca; refuses if one exists.

  stage, promote, unstage and add-host-ca refuse a Secret without the label
  nyyrikki.dev/component=ssh-ca, or with data keys other than user-ca,
  user-ca-next and host-ca. Their output keeps apiVersion, kind,
  metadata.name, metadata.namespace, the labels, the annotations (minus
  kubectl's last-applied one, which holds a copy of the keys), the
  resourceVersion read, type and data: what "kubectl replace -f -" needs.

  --in-cluster (with --name, and --namespace defaulting to the pod's):
  read the Secret through the Kubernetes API, apply the command, and
  update it in place, failing if it changed meanwhile (the chart's
  rotation CronJobs). Nothing is printed on stdout.
`

// Main runs the command with args (after "ssh-ca") and returns the exit
// status.
func Main(args []string, env Env) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(env.Stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet("ssh-ca "+cmd, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() { fmt.Fprint(env.Stderr, usage) }
	name := fs.String("name", DefaultName, "the Secret's name")
	namespace := fs.String("namespace", "", "the Secret's namespace")
	var release, key *string
	var create, inCluster *bool
	switch cmd {
	case "init":
		release = fs.String("release", DefaultRelease, "the value of the nyyrikki.dev/release label")
		create = fs.Bool("create", false, "create the Secret through the Kubernetes API")
	case "import":
		release = fs.String("release", DefaultRelease, "the value of the nyyrikki.dev/release label")
		key = fs.String("key", sshca.KeyUserCA, "the data key of the R10 Secret's user CA key")
	case "stage", "promote", "unstage", "add-host-ca":
		inCluster = fs.Bool("in-cluster", false, "update the Secret in place through the Kubernetes API")
	default:
		fmt.Fprintf(env.Stderr, "ssh-ca: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(env.Stderr, "ssh-ca %s: unexpected arguments %q\n", cmd, fs.Args())
		return 2
	}
	if err := checkName(*name, *namespace, release); err != nil {
		fmt.Fprintf(env.Stderr, "ssh-ca %s: %v\n", cmd, err)
		return 2
	}
	var err error
	switch {
	case cmd == "init" && *create:
		err = createInCluster(env, *name, *namespace, *release)
	case cmd == "init":
		err = initManifest(env, *name, *namespace, *release)
	case cmd == "import":
		err = importManifest(env, *key, *name, *namespace, *release)
	case *inCluster:
		err = updateInCluster(env, cmd, *name, *namespace)
	default:
		err = updateManifest(env, cmd)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "ssh-ca %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func checkName(name, namespace string, release *string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("--name %q: %s", name, strings.Join(errs, "; "))
	}
	if namespace != "" {
		if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
			return fmt.Errorf("--namespace %q: %s", namespace, strings.Join(errs, "; "))
		}
	}
	if release != nil {
		if errs := validation.IsValidLabelValue(*release); len(errs) > 0 || *release == "" {
			return fmt.Errorf("--release %q: must be a label value", *release)
		}
	}
	return nil
}

// newSecret is the Secret init and import make, labelled as D16 says.
func newSecret(name, namespace, release string, data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				LabelRelease:   release,
				LabelComponent: ComponentSSHCA,
				LabelManagedBy: ManagedBy,
			},
			Annotations: map[string]string{
				AnnotationResourcePolicy: "keep",
				AnnotationArgoCompare:    "IgnoreExtraneous",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}
}

// freshKeys makes a fresh key for each of names, into data, and returns
// their fingerprints for stderr.
func freshKeys(data map[string][]byte, names ...string) (string, error) {
	var b strings.Builder
	for _, n := range names {
		comment := commentUser
		if n == sshca.KeyHostCA {
			comment = commentHost
		}
		priv, pub, err := sshca.GenerateKey(comment)
		if err != nil {
			return "", fmt.Errorf("make %s: %w", n, err)
		}
		data[n] = priv
		fmt.Fprintf(&b, "%s: %s\n", n, ssh.FingerprintSHA256(pub))
	}
	return b.String(), nil
}

func initManifest(env Env, name, namespace, release string) error {
	data := map[string][]byte{}
	fps, err := freshKeys(data, sshca.KeyUserCA, sshca.KeyHostCA)
	if err != nil {
		return err
	}
	if err := writeManifest(env.Stdout, newSecret(name, namespace, release, data)); err != nil {
		return err
	}
	fmt.Fprint(env.Stderr, fps)
	return nil
}

// createInCluster is init --create (docs/08 D16): create the Secret, and
// treat AlreadyExists as success without reading or patching anything.
func createInCluster(env Env, name, namespace, release string) error {
	client, podNS, err := env.Client()
	if err != nil {
		return fmt.Errorf("the Kubernetes client: %w", err)
	}
	if namespace == "" {
		namespace = podNS
	}
	data := map[string][]byte{}
	fps, err := freshKeys(data, sshca.KeyUserCA, sshca.KeyHostCA)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	_, err = client.CoreV1().Secrets(namespace).Create(ctx, newSecret(name, namespace, release, data), metav1.CreateOptions{})
	clearData(data)
	switch {
	case apierrors.IsAlreadyExists(err):
		fmt.Fprintf(env.Stderr, "secret %s/%s already exists: left unchanged\n", namespace, name)
		return nil
	case err != nil:
		return fmt.Errorf("create secret %s/%s: %w", namespace, name, err)
	}
	fmt.Fprintf(env.Stderr, "created secret %s/%s\n%s", namespace, name, fps)
	return nil
}

// importManifest reads an R10 Secret and prints the new CA Secret with
// its key as user-ca and a fresh host-ca (docs/08 D2, D14).
func importManifest(env Env, key, name, namespace, release string) error {
	in, err := readManifest(env.Stdin)
	if err != nil {
		return err
	}
	b, ok := in.Data[key]
	if !ok {
		return fmt.Errorf("the input Secret has no data key %q (use --key)", key)
	}
	s, err := sshca.ParsePrivateKey(b)
	if err != nil {
		return fmt.Errorf("data key %q: %v", key, err)
	}
	if namespace == "" {
		namespace = in.Namespace
	}
	data := map[string][]byte{sshca.KeyUserCA: bytes.Clone(b)}
	fps, err := freshKeys(data, sshca.KeyHostCA)
	if err != nil {
		return err
	}
	if err := writeManifest(env.Stdout, newSecret(name, namespace, release, data)); err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "imported %s: %s\n%s", sshca.KeyUserCA, ssh.FingerprintSHA256(s.PublicKey()), fps)
	return nil
}

func updateManifest(env Env, cmd string) error {
	s, err := readManifest(env.Stdin)
	if err != nil {
		return err
	}
	msg, err := apply(cmd, s)
	if err != nil {
		return err
	}
	if err := writeManifest(env.Stdout, s); err != nil {
		return err
	}
	fmt.Fprint(env.Stderr, msg)
	return nil
}

// updateInCluster is --in-cluster: get, apply, update. The update carries
// the resourceVersion read, so a concurrent change fails it.
func updateInCluster(env Env, cmd, name, namespace string) error {
	client, podNS, err := env.Client()
	if err != nil {
		return fmt.Errorf("the Kubernetes client: %w", err)
	}
	if namespace == "" {
		namespace = podNS
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	secrets := client.CoreV1().Secrets(namespace)
	s, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get secret %s/%s: %w", namespace, name, err)
	}
	defer clearData(s.Data)
	msg, err := apply(cmd, s)
	if err != nil {
		return err
	}
	if _, err := secrets.Update(ctx, s, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("update secret %s/%s: %w", namespace, name, err)
	}
	fmt.Fprintf(env.Stderr, "updated secret %s/%s\n%s", namespace, name, msg)
	return nil
}

// allowedKeys are the only data keys a managed Secret may hold.
var allowedKeys = []string{sshca.KeyUserCA, sshca.KeyNextUserCA, sshca.KeyHostCA}

// checkManaged refuses a Secret the rotation commands must not touch
// (docs/08 D2): one not labelled as the CA Secret, such as an R10 Secret
// in compatibility mode, or one with other data.
func checkManaged(s *corev1.Secret) error {
	if s.Labels[LabelComponent] != ComponentSSHCA {
		return fmt.Errorf("the Secret is not labelled %s=%s; an R10 Secret is migrated with import, not rotated in place", LabelComponent, ComponentSSHCA)
	}
	if len(s.StringData) > 0 {
		return errors.New("the Secret has stringData; only data is accepted")
	}
	for k := range s.Data {
		if !slices.Contains(allowedKeys, k) {
			return fmt.Errorf("the Secret has data key %q; only %s are allowed", k, strings.Join(allowedKeys, ", "))
		}
	}
	return nil
}

// parsed checks that key k of s is a usable CA key.
func parsed(s *corev1.Secret, k string) (ssh.Signer, error) {
	b, ok := s.Data[k]
	if !ok {
		return nil, fmt.Errorf("the Secret has no %s", k)
	}
	sig, err := sshca.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", k, err)
	}
	return sig, nil
}

// apply runs a rotation command on s's data and returns what to print on
// stderr: fingerprints, and for promote the old public key. Never a
// private key.
func apply(cmd string, s *corev1.Secret) (string, error) {
	if err := checkManaged(s); err != nil {
		return "", err
	}
	user, err := parsed(s, sshca.KeyUserCA)
	if err != nil {
		return "", err
	}
	_, hasNext := s.Data[sshca.KeyNextUserCA]
	_, hasHost := s.Data[sshca.KeyHostCA]
	if hasHost {
		if _, err := parsed(s, sshca.KeyHostCA); err != nil {
			return "", err
		}
	}
	if hasNext && cmd != "unstage" {
		// unstage may remove a broken staged key: that is a repair.
		if _, err := parsed(s, sshca.KeyNextUserCA); err != nil {
			return "", err
		}
	}
	switch cmd {
	case "stage":
		if hasNext {
			return "", errors.New("user-ca-next already exists; promote or unstage it first")
		}
		return freshKeys(s.Data, sshca.KeyNextUserCA)
	case "promote":
		if !hasNext {
			return "", errors.New("no user-ca-next to promote; stage first")
		}
		next, _ := parsed(s, sshca.KeyNextUserCA)
		clear(s.Data[sshca.KeyUserCA])
		s.Data[sshca.KeyUserCA] = s.Data[sshca.KeyNextUserCA]
		delete(s.Data, sshca.KeyNextUserCA)
		return fmt.Sprintf("%s: %s\nold user-ca public key (after a leak, list it in ssh.revoked_user_ca_keys):\n%s\n",
			sshca.KeyUserCA, ssh.FingerprintSHA256(next.PublicKey()), sshca.AuthorizedKey(user.PublicKey())), nil
	case "unstage":
		if !hasNext {
			return "", errors.New("no user-ca-next to remove")
		}
		fp := "unparseable"
		if next, err := parsed(s, sshca.KeyNextUserCA); err == nil {
			fp = ssh.FingerprintSHA256(next.PublicKey())
		}
		clear(s.Data[sshca.KeyNextUserCA])
		delete(s.Data, sshca.KeyNextUserCA)
		return fmt.Sprintf("removed %s: %s\n", sshca.KeyNextUserCA, fp), nil
	case "add-host-ca":
		if hasHost {
			return "", errors.New("host-ca already exists")
		}
		return freshKeys(s.Data, sshca.KeyHostCA)
	}
	return "", fmt.Errorf("unknown command %q", cmd)
}

// readManifest reads one Secret manifest, YAML or JSON.
func readManifest(r io.Reader) (*corev1.Secret, error) {
	if r == nil {
		return nil, errors.New("no Secret manifest on stdin")
	}
	b, err := io.ReadAll(io.LimitReader(r, maxManifest+1))
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	defer clear(b)
	if len(b) > maxManifest {
		return nil, errors.New("the manifest on stdin is larger than 1 MiB")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("no Secret manifest on stdin")
	}
	var s corev1.Secret
	if err := yaml.Unmarshal(b, &s); err != nil {
		// The parser's message can quote the input, which holds keys.
		return nil, errors.New("stdin is not a Secret manifest")
	}
	if s.Kind != "Secret" || s.APIVersion != "v1" {
		return nil, fmt.Errorf("stdin is a %s %s, not a v1 Secret", s.APIVersion, s.Kind)
	}
	if s.Type != "" && s.Type != corev1.SecretTypeOpaque {
		return nil, fmt.Errorf("the Secret has type %s, not Opaque", s.Type)
	}
	if s.Name == "" {
		return nil, errors.New("the Secret has no name")
	}
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	return &s, nil
}

// manifest is the output: only the fields D2 allows.
type manifest struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   manifestMeta      `json:"metadata"`
	Type       corev1.SecretType `json:"type"`
	Data       map[string][]byte `json:"data"`
}

type manifestMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	// ResourceVersion is kept from the Secret read, so the
	// "kubectl replace -f -" of a read-modify-write command fails on a
	// concurrent change.
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// lastApplied is kubectl apply's annotation; on this Secret it holds a
// copy of the private keys, so it is never printed.
const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// writeManifest prints s with the allowed fields only: labels,
// annotations (minus lastApplied), and the resourceVersion
// read, so the read-modify-write commands can be piped into
// "kubectl replace -f -" (kubectl apply would keep a data key the command
// dropped, review of #42).
func writeManifest(w io.Writer, s *corev1.Secret) error {
	m := manifest{APIVersion: "v1", Kind: "Secret", Type: corev1.SecretTypeOpaque, Data: s.Data,
		Metadata: manifestMeta{Name: s.Name, Namespace: s.Namespace, ResourceVersion: s.ResourceVersion}}
	m.Metadata.Labels = s.Labels
	for k, v := range s.Annotations {
		if k == lastApplied {
			continue
		}
		if m.Metadata.Annotations == nil {
			m.Metadata.Annotations = map[string]string{}
		}
		m.Metadata.Annotations[k] = v
	}
	b, err := yaml.Marshal(m)
	if err != nil {
		return errors.New("could not encode the Secret")
	}
	defer clear(b)
	_, err = w.Write(b)
	return err
}

func clearData(data map[string][]byte) {
	for _, v := range data {
		clear(v)
	}
}
