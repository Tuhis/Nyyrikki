//go:build sshhost

// Package sshhost_test runs deploy/ssh-host/nyyrikki-host-setup.sh in
// Debian, Ubuntu (24.04 and 22.04), Rocky and Alpine containers and
// checks docs/07 G8, G9 and the script's side of G13 (docs/07 §5.7,
// SH5), and docs/08 G4, G5 and G13 (the trust pull, its schedule,
// enrollment; SE6). It needs docker:
//
//	go test -tags sshhost -count=1 -timeout 60m ./test/ssh-host/
//
// The systemd cases (session kill, docs/07 M18) need a privileged
// container; set NYYRIKKI_SSHHOST_NO_SYSTEMD=1 to skip them.
//
// Every test, and every distribution within it, runs in parallel, each
// in containers of its own; -parallel caps how many run at once (CI uses
// 16: the containers mostly wait). Run in sequence, the tests took ~18
// minutes on CI for ~10 minutes of their longest cases (2026-11-01).
//
// Failures and signals are injected by replacing a command inside the
// container with a shim (installShim), never by anything the script reads:
// the script has no test seam.
package sshhost_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const scriptPath = "../../deploy/ssh-host/nyyrikki-host-setup.sh"

type distro struct {
	name       string
	base       string
	install    string
	systemd    bool
	sshService string
}

// Each image has cron and curl, so the setup installs the trust pull's
// schedule (docs/08 D5): cron.d on Debian, Ubuntu (cron) and Rocky
// (cronie), periodic on Alpine (BusyBox crond, M3).
var distros = []distro{
	{name: "debian", base: "debian:trixie", install: aptInstall("cron curl ca-certificates")},
	{name: "ubuntu", base: "ubuntu:24.04", install: aptInstall("cron curl ca-certificates")},
	// Ubuntu 22.04 has OpenSSH 8.9p1, the oldest the script accepts
	// (docs/07 §5.7 step 1).
	{name: "ubuntu2204", base: "ubuntu:22.04", install: aptInstall("cron curl ca-certificates")},
	// rockylinux/rockylinux:10 needs x86-64-v3, which not every CI runner has.
	// The image's curl-minimal is the curl.
	{name: "rocky", base: "rockylinux:9", install: "dnf install -y -q openssh-server openssh-clients sudo procps-ng util-linux cronie >/dev/null && dnf clean all >/dev/null"},
	// Alpine 3.22's sshd_config starts with the Include line, as the
	// script requires (docs/07 M14). shadow for useradd, findutils,
	// runuser and util-linux-misc (script) for the harness itself.
	{name: "alpine", base: "alpine:3.22", install: "apk add -q --no-cache openssh sudo shadow curl findutils runuser util-linux-misc >/dev/null"},
}

// systemdDistros are the distributions where session kill counts as
// measured (docs/07 M18), each with systemd as PID 1 in a privileged
// container.
var systemdDistros = []distro{
	systemdDistro("debian-systemd", "debian:trixie"),
	systemdDistro("ubuntu-systemd", "ubuntu:24.04"),
	systemdDistro("ubuntu2204-systemd", "ubuntu:22.04"),
}

func systemdDistro(name, base string) distro {
	return distro{
		name:       name,
		base:       base,
		install:    aptInstall("systemd systemd-sysv dbus libpam-systemd cron curl ca-certificates"),
		systemd:    true,
		sshService: "ssh",
	}
}

func aptInstall(extra string) string {
	return "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends openssh-server openssh-client sudo procps util-linux " + extra + " >/dev/null && rm -rf /var/lib/apt/lists/*"
}

var (
	imageMu   sync.Mutex
	imageOnce = map[string]*sync.Once{}
	imageErr  = map[string]error{}
)

func image(t *testing.T, d distro) string {
	t.Helper()
	tag := "nyyrikki-sshhost-" + d.name
	imageMu.Lock()
	o := imageOnce[tag]
	if o == nil {
		o = new(sync.Once)
		imageOnce[tag] = o
	}
	imageMu.Unlock()
	o.Do(func() {
		df := fmt.Sprintf("FROM %s\nRUN %s && ssh-keygen -A && mkdir -p /run/sshd\n", d.base, d.install)
		if d.systemd {
			df += "CMD [\"/sbin/init\"]\n"
		}
		cmd := exec.Command("docker", "build", "-q", "-t", tag, "-")
		cmd.Stdin = strings.NewReader(df)
		out, err := cmd.CombinedOutput()
		imageMu.Lock()
		if err != nil {
			imageErr[tag] = fmt.Errorf("docker build %s: %v\n%s", tag, err, out)
		}
		imageMu.Unlock()
	})
	imageMu.Lock()
	err := imageErr[tag]
	imageMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

func body(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// values are a target's data lines (docs/07 D16, docs/08 D13).
type values struct {
	target  string
	humans  []string
	caKeys  []string
	sources []string
	sudo    bool
	signers []string
	revoked []string
	issued  string
	url     string
}

// lines are the data lines Nyyrikki serves for v, END included: docs/07
// D16's, then docs/08 D13's.
func (v values) lines() []string {
	var l []string
	l = append(l, "TARGET="+v.target)
	for _, h := range v.humans {
		l = append(l, "HUMAN="+h)
	}
	for _, k := range v.caKeys {
		l = append(l, "CA_KEY="+k)
	}
	for _, s := range v.sources {
		l = append(l, "SOURCE="+s)
	}
	l = append(l, fmt.Sprintf("SUDO=%t", v.sudo))
	for _, k := range v.signers {
		l = append(l, "SIGNER_KEY="+k)
	}
	for _, k := range v.revoked {
		l = append(l, "REVOKED_CA_KEY="+k)
	}
	l = append(l, "ISSUED="+v.issued, "URL="+v.url)
	return append(l, fmt.Sprintf("END=%d", len(l)))
}

// fakeURL is the URL data line of the fake Nyyrikki each host can run
// (fake_test.go).
const fakeURL = "https://127.0.0.1:8443"

func nowMillis() string { return strconv.FormatInt(time.Now().UnixMilli(), 10) }

// served builds the served form: body, data lines, terminator, then extra
// (which must never run).
func served(t *testing.T, lines []string, extra string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(body(t))
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	b.WriteString("NYYRIKKI_VALUES_END\n")
	b.WriteString(extra)
	return b.String()
}

// host is one container.
type host struct {
	t  *testing.T
	d  distro
	id string
	ca string // the test CA's public key, "ssh-ed25519 <base64>"
	// issued is the ISSUED of the host's default values: fixed per host,
	// so a re-run with them is the same script, as on a real host.
	issued string
}

// newHost starts a container with sshd running, a test CA, a user key, a
// plain key, a normal user alice, and a global AuthorizedKeysCommand that
// returns the plain key for every user (as EC2 Instance Connect images
// do, docs/07 M16).
func newHost(t *testing.T, d distro) *host {
	t.Helper()
	img := image(t, d)
	args := []string{"run", "-d", "--rm"}
	if d.systemd {
		args = append(args, "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock", img)
	} else {
		args = append(args, "--init", img, "sleep", "infinity")
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	h := &host{t: t, d: d, id: strings.TrimSpace(string(out)), issued: nowMillis()}
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("NYYRIKKI_SSHHOST_KEEP") != "" {
			t.Logf("kept container %s", h.id)
			return
		}
		_ = exec.Command("docker", "rm", "-f", h.id).Run()
	})
	if d.systemd {
		h.waitSystemd()
	}
	h.must(`
set -e
ssh-keygen -q -t ed25519 -N '' -C test-ca -f /root/ca
ssh-keygen -q -t ed25519 -N '' -C user -f /root/u
ssh-keygen -q -t ed25519 -N '' -C plain -f /root/plain
cat > /usr/local/bin/akc <<'EOF'
#!/bin/sh
cat /etc/akc-key
EOF
chmod 0755 /usr/local/bin/akc
cp /root/plain.pub /etc/akc-key
chmod 0644 /etc/akc-key
printf '\nAuthorizedKeysCommand /usr/local/bin/akc\nAuthorizedKeysCommandUser nobody\n' >> /etc/ssh/sshd_config
useradd -m -s /bin/sh alice
usermod -p '*' alice
mkdir -p /nyshim
`)
	h.startSSHD()
	h.ca = strings.Join(strings.Fields(h.must("cat /root/ca.pub"))[:2], " ")
	return h
}

func (h *host) waitSystemd() {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		// Ubuntu 24.04 starts sshd from ssh.socket on the first connection,
		// so ssh.service is inactive until then; startSSHD starts it.
		out, _, _ := h.exec("systemctl is-system-running 2>/dev/null; systemctl is-active ssh.service ssh.socket", "")
		if (strings.HasPrefix(out, "running") || strings.HasPrefix(out, "degraded")) && strings.Contains(out, "\nactive") {
			return
		}
		time.Sleep(time.Second)
	}
	h.t.Fatal("systemd didn't come up in the container")
}

func (h *host) startSSHD() {
	h.t.Helper()
	if h.d.systemd {
		h.must("systemctl restart ssh.service")
		return
	}
	h.must("/usr/sbin/sshd")
}

// exec runs a shell command in the container.
func (h *host) exec(cmd, stdin string) (stdout, stderr string, code int) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, "docker", "exec", "-i", h.id, "sh", "-c", cmd)
	c.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	c.Stdout, c.Stderr = &o, &e
	err := c.Run()
	code = 0
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			code = x.ExitCode()
		} else {
			h.t.Fatalf("docker exec: %v", err)
		}
	}
	return o.String(), e.String(), code
}

func (h *host) must(cmd string) string {
	h.t.Helper()
	o, e, code := h.exec(cmd, "")
	if code != 0 {
		h.t.Fatalf("%s: exit %d\nstdout: %s\nstderr: %s", firstLine(cmd), code, o, e)
	}
	return o
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// result of one run of the script.
type result struct {
	out, err string
	code     int
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.out, r.err)
}

// run copies the served form into the container and runs it as Nyyrikki's
// setup page says: `sh setup.sh [args]`, recording the shell's PID for the
// shims.
func (h *host) run(script string, args ...string) result {
	h.t.Helper()
	h.put("/root/setup.sh", script)
	cmd := `echo $$ > /nyshim/pid; exec sh /root/setup.sh "$@"`
	full := "sh -c " + shellQuote(cmd) + " sh"
	for _, a := range args {
		full += " " + shellQuote(a)
	}
	o, e, code := h.exec(full, "")
	return result{o, e, code}
}

// pipe runs the served form the way `curl … | sudo sh` does.
func (h *host) pipe(script string) result {
	h.t.Helper()
	o, e, code := h.exec("sh", script)
	return result{o, e, code}
}

func (h *host) setup(v values, args ...string) result {
	h.t.Helper()
	return h.run(served(h.t, v.lines(), ""), args...)
}

func (h *host) mustSetup(v values, args ...string) result {
	h.t.Helper()
	r := h.setup(v, args...)
	if r.code != 0 {
		h.t.Fatalf("setup failed: %s", r)
	}
	return r
}

func (h *host) put(path, content string) {
	h.t.Helper()
	if _, e, code := h.exec("cat > "+shellQuote(path), content); code != 0 {
		h.t.Fatalf("writing %s: %s", path, e)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// snapshot is everything the script may touch: paths, types, modes,
// owners and contents under /etc/ssh, sudoers, systemd's configuration,
// homes and mail spools, the account databases, and logind's effective
// values on a systemd host.
func (h *host) snapshot() string {
	h.t.Helper()
	cmd := `P="/etc/ssh /etc/sudoers /etc/sudoers.d /etc/systemd /home /var/mail /var/spool/mail /etc/pam.d /etc/cron.d /etc/periodic"
A="/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid"
# alice's home: logins write into it (pam_motd on Ubuntu).
find $P $A -xdev -path /home/alice -prune -o -printf '%p %y %m %u %g\n' 2>/dev/null | sort
find $P -xdev -path /home/alice -prune -o -type f -print 2>/dev/null | sort | while IFS= read -r f; do md5sum "$f"; done
for f in $A; do [ -f $f ] && sed "s|^|C $f:|" $f; done | sort
if [ -d /run/systemd/system ]; then
  for p in KillUserProcesses KillOnlyUsers; do busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager $p; done
fi`
	return h.must(cmd)
}

func diffSnap(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	in := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			m[x] = true
		}
		return m
	}
	am, bm := in(al), in(bl)
	var d []string
	for _, x := range al {
		if !bm[x] {
			d = append(d, "- "+x)
		}
	}
	for _, x := range bl {
		if !am[x] {
			d = append(d, "+ "+x)
		}
	}
	return strings.Join(d, "\n")
}

func (h *host) sameAs(before string, what string) {
	h.t.Helper()
	if d := diffSnap(before, h.snapshot()); d != "" {
		h.t.Fatalf("%s changed the host:\n%s", what, d)
	}
}

// installShim replaces cmd in the container with a shim that, for the
// skip+1-th invocation whose arguments match the sh pattern, does action:
// "fail" (exit 1 without running the command), "KILL" (SIGKILL the
// script, don't run the command) or a signal name (send it to the
// script, then run the command). With always, every later match too.
func (h *host) installShim(cmd, pattern, action string, skip int, always bool) {
	h.t.Helper()
	mode := "once"
	if always {
		mode = "always"
	}
	shim := `#!/bin/sh
n=${0##*/}
r=/nyshim/rule.$n
if [ -s "$r" ]; then
	{ IFS= read -r pat; IFS= read -r act; IFS= read -r skip; IFS= read -r mode; } < "$r"
	case "$*" in
	$pat)
		if [ "$skip" -gt 0 ]; then
			printf '%s\n%s\n%s\n%s\n' "$pat" "$act" $((skip - 1)) "$mode" > "$r"
		else
			[ "$mode" = always ] || : > "$r"
			echo "$n $*" >> /nyshim/hits
			case $act in
			fail) exit 1 ;;
			KILL) read -r pid < /nyshim/pid; kill -s KILL "$pid"; exit 1 ;;
			*) read -r pid < /nyshim/pid; kill -s "$act" "$pid" ;;
			esac
		fi
		;;
	esac
fi
# A BusyBox applet decides what it is by its name, which .real isn't.
if [ -L "$0.real" ] && [ "$(readlink -f "$0.real")" = /bin/busybox ]; then
	exec /bin/busybox "$n" "$@"
fi
exec "$0.real" "$@"
`
	h.put("/nyshim/shim", shim)
	h.must(fmt.Sprintf(`set -e
p=$(PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v %[1]s)
if [ ! -e "$p.real" ]; then mv "$p" "$p.real"; cp /nyshim/shim "$p"; chmod 0755 "$p"; fi
printf '%%s\n%%s\n%%s\n%%s\n' %[2]s %[3]s %[4]d %[5]s > /nyshim/rule.%[1]s`, cmd, shellQuote(pattern), action, skip, mode))
}

func (h *host) clearShim(cmd string) {
	h.t.Helper()
	h.must(": > /nyshim/rule." + cmd)
}

func (h *host) shimHit(cmd string) bool {
	h.t.Helper()
	o, _, _ := h.exec("cat /nyshim/hits 2>/dev/null", "")
	return strings.Contains(o, cmd+" ")
}

// sign makes /root/u-cert.pub for principal, valid now (docs/07 D5's shape).
func (h *host) sign(principal string) {
	h.t.Helper()
	h.must(fmt.Sprintf("rm -f /root/u-cert.pub && ssh-keygen -q -s /root/ca -I nyyrikki:run-1 -z 1 -n %s -V -1m:+2m /root/u.pub", shellQuote(principal)))
}

// ssh logs in to user with key (a path in the container) and runs cmd.
func (h *host) ssh(user, key, cmd string) (string, int) {
	h.t.Helper()
	o, e, code := h.exec(fmt.Sprintf("ssh -n -i %s -o IdentityAgent=none -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR %s@127.0.0.1 %s",
		key, user, shellQuote(cmd)), "")
	return o + e, code
}

// certLogin signs a certificate for human@target and runs cmd as ny-human.
func (h *host) certLogin(human, target, cmd string) (string, int) {
	h.t.Helper()
	h.sign("nyyrikki:" + human + "@" + target)
	return h.ssh("ny-"+human, "/root/u", cmd)
}

// plainKeyReaches reports whether a plain key reaches account, through its
// authorized_keys or through the global AuthorizedKeysCommand.
func (h *host) plainKeyReaches(account string) bool {
	h.t.Helper()
	h.must(fmt.Sprintf(`home=$(getent passwd %[1]s | cut -d: -f6)
mkdir -p "$home/.ssh" && cp /root/plain.pub "$home/.ssh/authorized_keys" && chown -R %[1]s: "$home/.ssh" && chmod 700 "$home/.ssh" && chmod 600 "$home/.ssh/authorized_keys"`, account))
	out, code := h.ssh(account, "/root/plain", "id -un")
	h.must(fmt.Sprintf(`home=$(getent passwd %s | cut -d: -f6); rm -rf "$home/.ssh"`, account))
	return code == 0 && strings.TrimSpace(out) == account
}

func (h *host) exists(path string) bool {
	h.t.Helper()
	_, _, code := h.exec("test -e "+shellQuote(path)+" || test -L "+shellQuote(path), "")
	return code == 0
}

func (h *host) accountExists(a string) bool {
	h.t.Helper()
	_, _, code := h.exec("getent passwd "+a, "")
	return code == 0
}

func (h *host) values(humans ...string) values {
	return values{target: "db-1", humans: humans, caKeys: []string{h.ca}, sources: []string{"127.0.0.1/32", "::1/128"}, sudo: true,
		signers: []string{h.ca}, issued: h.issued, url: fakeURL}
}

// forEachDistro runs f in parallel for each distribution.
func forEachDistro(t *testing.T, f func(t *testing.T, d distro)) {
	for _, d := range distros {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			f(t, d)
		})
	}
}

// forEachSystemdDistro runs f in parallel for each of systemdDistros.
func forEachSystemdDistro(t *testing.T, f func(t *testing.T, d distro)) {
	needSystemd(t)
	for _, d := range systemdDistros {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			f(t, d)
		})
	}
}

func needSystemd(t *testing.T) {
	t.Helper()
	if os.Getenv("NYYRIKKI_SSHHOST_NO_SYSTEMD") != "" {
		t.Skip("NYYRIKKI_SSHHOST_NO_SYSTEMD is set")
	}
}

// manualFiles reads docs/setup/ssh-hosts.md's listing: each fenced block
// after a `<!-- file: PATH MODE -->` line; each block after a
// `<!-- file-from-script: PATH MODE -->` line, whose first line is the
// command that extracts the file from the setup script into the
// directory it runs in (fromScript); and the data lines block (the one
// ending in the terminator).
func manualFiles(t *testing.T) (files map[string][2]string, fromScript map[string][2]string, data []string) {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "docs", "setup", "ssh-hosts.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files = map[string][2]string{}
	fromScript = map[string][2]string{}
	marker := regexp.MustCompile(`^<!-- (file|file-from-script): (\S+) (0[0-7]{3}) -->$`)
	var kind, path, mode string
	var block []string
	inBlock, want := false, false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case !inBlock && marker.MatchString(l):
			m := marker.FindStringSubmatch(l)
			kind, path, mode, want = m[1], m[2], m[3], true
		case !inBlock && strings.HasPrefix(l, "```"):
			inBlock, block = true, nil
		case inBlock && l == "```":
			inBlock = false
			switch {
			case want && kind == "file":
				files[path] = [2]string{mode, strings.Join(block, "\n") + "\n"}
			case want:
				fromScript[path] = [2]string{mode, block[0]}
			case len(block) > 0 && block[len(block)-1] == "NYYRIKKI_VALUES_END":
				data = block[:len(block)-1]
			}
			want = false
		case inBlock:
			block = append(block, l)
		}
	}
	if len(files) == 0 || len(fromScript) == 0 || data == nil {
		t.Fatal("docs/setup/ssh-hosts.md: no file listing, no file taken from the script, or no data lines block found")
	}
	return files, fromScript, data
}
