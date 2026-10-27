package kubectl

import (
	"fmt"
	"os"

	"k8s.io/cli-runtime/pkg/genericiooptions"
	kcmd "k8s.io/kubectl/pkg/cmd"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

// ChildMain runs kubectl's command tree on args, the canonical argv
// (docs/04 D6). nyyrikkid calls it when os.Args[1] is ChildArg; the
// Runner is its only caller and has set the environment.
//
// The tree comes from NewKubectlCommand with no PluginHandler, so no
// plugin is ever looked up (docs/04 M2), and with no Arguments, so no
// kuberc is applied; KUBERC=off covers the rest (M3). Errors are handled
// as kubectl's own main does: cmdutil.CheckErr prints them and exits with
// kubectl's code, including exec's remote exit status (uexec.CodeExitError).
func ChildMain(args []string) int {
	// Only ever run in the environment the Runner made (docs/04 D6):
	// never against a default kubeconfig or with kuberc on.
	if os.Getenv("KUBERC") != "off" || os.Getenv("KUBECONFIG") == "" {
		fmt.Fprintln(os.Stderr, "nyyrikkid kubectl-child: not started by the runner")
		return 70
	}
	streams := genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	root := kcmd.NewKubectlCommand(kcmd.KubectlOptions{IOStreams: streams})
	root.SetArgs(args)
	// As in k8s.io/component-base/cli: cobra prints nothing itself;
	// CheckErr below prints the error once. The canonical argv always
	// parses, so usage text would only be noise.
	root.SilenceErrors = true
	root.SilenceUsage = true
	if err := root.Execute(); err != nil {
		cmdutil.CheckErr(err) // exits with kubectl's code
		return 1
	}
	return 0
}
