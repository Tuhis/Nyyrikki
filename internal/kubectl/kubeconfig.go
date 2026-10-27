package kubectl

import (
	"log/slog"
	"os"
	"path/filepath"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
)

// runDir is one run's directory under runtime_dir: the kubeconfig and
// kubectl's cache and home. It is removed when the run ends.
type runDir struct{ dir string }

// kubeconfigFor is the kubeconfig of docs/04 D9: the target's server and
// CA path, a user with tokenFile (the path, never the token) and the
// human's identity as impersonation (D10).
func kubeconfigFor(t Target, as approval.Identity) clientcmdapi.Config {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["target"] = &clientcmdapi.Cluster{
		Server:               t.Server,
		CertificateAuthority: t.CAFile,
	}
	cfg.AuthInfos["nyyrikki"] = &clientcmdapi.AuthInfo{
		TokenFile:         t.TokenFile,
		Impersonate:       as.User,
		ImpersonateGroups: append([]string(nil), as.Groups...),
	}
	cfg.Contexts["target"] = &clientcmdapi.Context{Cluster: "target", AuthInfo: "nyyrikki"}
	cfg.CurrentContext = "target"
	return *cfg
}

// newRunDir makes a fresh 0700 directory under runtime_dir and writes the
// kubeconfig into it, mode 0600. On any failure nothing is left behind.
func (r *Runner) newRunDir(t Target, as approval.Identity) (_ *runDir, err error) {
	// Without a user, kubectl would act as Nyyrikki's own ServiceAccount
	// (docs/04 D10): never.
	if as.User == "" {
		return nil, codes.WithDetail(codes.Internal, DetailNoIdentity, "no identity to run as")
	}
	if t.Name == "" {
		return nil, codes.WithDetail(codes.TargetNotAllowed, DetailUnknownTarget, "unknown target")
	}
	data, err := clientcmd.Write(kubeconfigFor(t, as))
	if err != nil {
		return nil, codes.Wrap(codes.Internal, err, "the run could not be prepared")
	}
	dir, err := os.MkdirTemp(r.runtimeDir, "run-")
	if err != nil {
		return nil, codes.WithDetail(codes.Unavailable, DetailSetup, "the run could not be prepared")
	}
	rd := &runDir{dir: dir}
	defer func() {
		if err != nil {
			rd.remove(r.log)
		}
	}()
	// MkdirTemp makes 0700 already; be explicit in case of an odd umask.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, codes.WithDetail(codes.Unavailable, DetailSetup, "the run could not be prepared")
	}
	f, err := os.OpenFile(filepath.Join(dir, "kubeconfig"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, codes.WithDetail(codes.Unavailable, DetailSetup, "the run could not be prepared")
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, codes.WithDetail(codes.Unavailable, DetailSetup, "the run could not be prepared")
	}
	if err := f.Close(); err != nil {
		return nil, codes.WithDetail(codes.Unavailable, DetailSetup, "the run could not be prepared")
	}
	return rd, nil
}

func (d *runDir) remove(log *slog.Logger) {
	if err := os.RemoveAll(d.dir); err != nil {
		log.Error("removing a run directory failed", "dir", d.dir, "err", err)
	}
}
