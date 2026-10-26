package kubectl

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/term"
)

// Test-only child modes, chosen by the name the test binary is started
// under (a symlink), so production code has no hidden modes. The runner
// still passes "kubectl-child <argv…>"; these modes ignore the argv.
const (
	modeEnvDump = "env-dump" // print the environment and the kubeconfig
	modeSleeper = "sleeper"  // start a grandchild, print its pid, sleep
	modeLeaf    = "leaf"     // sleep (the grandchild)
	modeEchoTTY = "echo-tty" // interactive echo on a terminal
)

func TestMain(m *testing.M) {
	switch filepath.Base(os.Args[0]) {
	case modeEnvDump:
		os.Exit(envDump())
	case modeSleeper:
		os.Exit(sleeper())
	case modeLeaf:
		time.Sleep(time.Hour)
		os.Exit(0)
	case modeEchoTTY:
		os.Exit(echoTTY())
	}
	if len(os.Args) > 1 && os.Args[1] == ChildArg {
		os.Exit(ChildMain(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func envDump() int {
	env := os.Environ()
	sort.Strings(env)
	for _, e := range env {
		fmt.Println("ENV " + e)
	}
	kc := os.Getenv("KUBECONFIG")
	data, err := os.ReadFile(kc)
	if err != nil {
		fmt.Println("ERR", err)
		return 1
	}
	if fi, err := os.Stat(kc); err == nil {
		fmt.Printf("KUBECONFIG_MODE %o\n", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Dir(kc)); err == nil {
		fmt.Printf("RUNDIR_MODE %o\n", fi.Mode().Perm())
	}
	fmt.Println("ARGS " + strings.Join(os.Args[1:], " "))
	fmt.Println("---")
	os.Stdout.Write(data)
	return 0
}

func sleeper() int {
	leaf := filepath.Join(filepath.Dir(os.Args[0]), modeLeaf)
	c := exec.Command(leaf)
	if err := c.Start(); err != nil {
		fmt.Println("ERR", err)
		return 1
	}
	fmt.Printf("LEAF %d\n", c.Process.Pid)
	time.Sleep(time.Hour)
	return 0
}

// echoTTY answers lines on its terminal: "size" prints the window size,
// "exit N" exits with N, anything else is echoed back as "got:<line>".
func echoTTY() int {
	if !term.IsTerminal(0) {
		fmt.Println("NOT A TTY")
		return 2
	}
	fmt.Print("READY\r\n")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "size":
			w, h, _ := term.GetSize(0)
			fmt.Printf("SIZE %dx%d\r\n", w, h)
		case strings.HasPrefix(line, "exit "):
			var n int
			fmt.Sscanf(line, "exit %d", &n)
			return n
		default:
			fmt.Printf("got:%s\r\n", line)
		}
	}
	return 0
}

// modeExecutable returns a path that starts the test binary in mode.
func modeExecutable(t *testing.T, mode string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, m := range []string{modeEnvDump, modeSleeper, modeLeaf, modeEchoTTY} {
		if err := os.Symlink(self, filepath.Join(dir, m)); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, mode)
}
