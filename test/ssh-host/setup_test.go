//go:build sshhost

package sshhost_test

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

const afterTerminator = "touch /root/after-terminator\n"

// TestBodyShape: the body has exactly one main line, its last, and the
// checksum of a served file up to that line is the body's (docs/07 D16,
// G13). Both shells parse it.
func TestBodyShape(t *testing.T) {
	b := body(t)
	if !strings.HasSuffix(b, "\n") {
		t.Fatal("the body doesn't end in a newline")
	}
	lines := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	re := regexp.MustCompile(`^main .*<<\s*'?"?NYYRIKKI_VALUES_END`)
	var at []int
	for i, l := range lines {
		if re.MatchString(l) || strings.Contains(l, "<<'NYYRIKKI_VALUES_END'") {
			at = append(at, i)
		}
	}
	if len(at) != 1 || at[0] != len(lines)-1 || lines[at[0]] != `main "$@" <<'NYYRIKKI_VALUES_END'` {
		t.Fatalf("main lines at %v of %d; want exactly one, the last, `main \"$@\" <<'NYYRIKKI_VALUES_END'`", at, len(lines))
	}
	s := served(t, []string{"TARGET=x", "END=1"}, afterTerminator)
	cut := s[:strings.Index(s, "main \"$@\" <<'NYYRIKKI_VALUES_END'\n")+len("main \"$@\" <<'NYYRIKKI_VALUES_END'\n")]
	if sha256.Sum256([]byte(cut)) != sha256.Sum256([]byte(b)) {
		t.Fatal("the served file's part up to the main line isn't the body")
	}
	h := newHost(t, distros[0])
	h.put("/root/s.sh", served(t, h.values("owner").lines(), ""))
	for _, sh := range []string{"dash", "bash", "sh"} {
		if o, e, code := h.exec(sh+" -n /root/s.sh", ""); code != 0 {
			t.Errorf("%s -n: %s %s", sh, o, e)
		}
	}
	// docs/setup/ssh-hosts.md's sed command cuts the served file at the
	// same place.
	h.put("/root/served.sh", s)
	h.put("/root/body.sh", b)
	got := h.must(`sed '/^main "\$@" <<.NYYRIKKI_VALUES_END.$/q' /root/served.sh | sha256sum; sha256sum < /root/body.sh`)
	if l := strings.Split(strings.TrimSpace(got), "\n"); len(l) != 2 || l[0] != l[1] {
		t.Fatalf("the setup page's checksum command doesn't give the body's checksum: %q", got)
	}
	t.Logf("body sha256: %x", sha256.Sum256([]byte(b)))
}

// TestSetupAndLogin: the piped form sets a host up; a certificate logs in
// and gets root through sudo; no plain key reaches the account; other
// users are unchanged; re-running is idempotent; the KRL takes §5.6's
// ssh-keygen -k -u; SUDO=false takes sudo away; --uninstall leaves the
// host as it was (G8).
func TestSetupAndLogin(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		pristine := h.snapshot()
		aliceBefore := h.must("sshd -T -C user=alice,host=127.0.0.1,addr=127.0.0.1")
		if !h.plainKeyReaches("alice") {
			t.Fatal("the global AuthorizedKeysCommand doesn't work for alice: the plain-key checks would prove nothing")
		}

		v := h.values("owner")
		r := h.pipe(served(t, v.lines(), afterTerminator))
		if r.code != 0 {
			t.Fatalf("piped setup: %s", r)
		}
		if h.exists("/root/after-terminator") {
			t.Fatal("code after the terminator ran")
		}
		for _, want := range []string{"host_keys:", "- ssh-ed25519 ", "sudo: true", "session_kill: false", "(ED25519)"} {
			if !strings.Contains(r.out, want) {
				t.Errorf("output lacks %q:\n%s", want, r.out)
			}
		}
		hostKey := strings.Join(strings.Fields(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub"))[:2], " ")
		if !strings.Contains(r.out, "        - "+hostKey+"\n") {
			t.Errorf("output lacks the host's own ed25519 key %q", hostKey)
		}

		out, code := h.certLogin("owner", "db-1", "id -un; sudo -n id -u")
		if code != 0 || out != "ny-owner\n0\n" {
			t.Fatalf("certificate login with sudo: exit %d: %q", code, out)
		}
		if h.plainKeyReaches("ny-owner") {
			t.Fatal("a plain key reaches ny-owner")
		}
		if !h.plainKeyReaches("alice") {
			t.Fatal("alice's plain key stopped working: the setup changed another user")
		}
		if after := h.must("sshd -T -C user=alice,host=127.0.0.1,addr=127.0.0.1"); diffWithout(aliceBefore, after, "trustedusercakeys", "authorizedprincipalsfile", "revokedkeys") != "" {
			t.Fatalf("alice's effective sshd configuration changed beyond D4's three keywords:\n%s", diffSnap(aliceBefore, after))
		}
		if out, code := h.certLogin("other", "db-1", "true"); code == 0 {
			t.Fatalf("a certificate for another principal logged in: %q", out)
		}
		h.sign("nyyrikki:owner@db-2")
		if out, code := h.ssh("ny-owner", "/root/u", "true"); code == 0 {
			t.Fatalf("a certificate for another target logged in: %q", out)
		}
		h.sign("nyyrikki:owner@db-1")
		if out, code := h.ssh("alice", "/root/u", "true"); code == 0 {
			t.Fatalf("Nyyrikki's certificate logged in to alice: %q", out)
		}

		// Idempotent.
		once := h.snapshot()
		r = h.setup(v)
		if r.code != 0 {
			t.Fatalf("re-run: %s", r)
		}
		h.sameAs(once, "a re-run")
		if out, code := h.certLogin("owner", "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
			t.Fatalf("after a re-run: exit %d %q", code, out)
		}

		// §5.6: the KRL takes ssh-keygen -k -u, and then refuses the CA.
		h.must("ssh-keygen -k -u -f /etc/ssh/nyyrikki/revoked.krl /root/ca.pub")
		if q := h.must("ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl /root/ca.pub || true"); !strings.Contains(q, "REVOKED") {
			t.Fatalf("ssh-keygen -Q: %q", q)
		}
		if out, code := h.certLogin("owner", "db-1", "true"); code == 0 {
			t.Fatalf("a certificate of a revoked CA logged in: %q", out)
		}
		// A re-run whose values still trust the revoked CA is refused, and
		// the revocation list stays (docs/08 D13, round 1 of #50: a key the
		// values trust that the list names would leave the host refusing
		// Nyyrikki).
		revoked := h.snapshot()
		if r := h.setup(v); r.code == 0 || !strings.Contains(r.err, "revocation list") {
			t.Fatalf("a re-run trusting a revoked CA: %s", r)
		}
		h.sameAs(revoked, "a re-run refused for the revocation list")
		if q := h.must("ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl /root/ca.pub || true"); !strings.Contains(q, "REVOKED") {
			t.Fatalf("a re-run replaced the revocation list: %q", q)
		}
		h.must("rm /etc/ssh/nyyrikki/revoked.krl")
		h.mustSetup(v)

		// SUDO=false takes sudo away.
		v.sudo = false
		r = h.mustSetup(v)
		if !strings.Contains(r.out, "sudo: false") {
			t.Errorf("output lacks sudo: false:\n%s", r.out)
		}
		if h.exists("/etc/sudoers.d/50-nyyrikki-ny-owner") {
			t.Fatal("SUDO=false left the sudoers file")
		}
		if out, code := h.certLogin("owner", "db-1", "sudo -n id -u"); code == 0 {
			t.Fatalf("sudo works with SUDO=false: %q", out)
		}

		r = h.setup(v, "--uninstall")
		if r.code != 0 {
			t.Fatalf("--uninstall: %s", r)
		}
		h.sameAs(pristine, "setup then --uninstall")
		if after := h.must("sshd -T -C user=alice,host=127.0.0.1,addr=127.0.0.1"); after != aliceBefore {
			t.Fatalf("after --uninstall, alice's effective configuration differs:\n%s", diffSnap(aliceBefore, after))
		}
		if out, code := h.certLogin("owner", "db-1", "true"); code == 0 {
			t.Fatalf("a certificate logged in after --uninstall: %q", out)
		}
	})
}

// diffWithout is diffSnap ignoring lines that start with any of keys.
func diffWithout(a, b string, keys ...string) string {
	drop := func(s string) string {
		var out []string
		for _, l := range strings.Split(s, "\n") {
			keep := true
			for _, k := range keys {
				if strings.HasPrefix(l, k+" ") {
					keep = false
				}
			}
			if keep {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n")
	}
	return diffSnap(drop(a), drop(b))
}

// TestBadValuesRefused: every malformed served file is refused before
// anything changes, and nothing in it runs (G8 "refuses each bad input",
// G13).
func TestBadValuesRefused(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		good := h.values("owner").lines()
		// good: TARGET, HUMAN, CA_KEY, SOURCE, SOURCE, SUDO, SIGNER_KEY,
		// ISSUED, URL, END=9
		ecdsa := strings.Fields(h.must("cat /etc/ssh/ssh_host_ecdsa_key.pub"))[1]
		rsa := strings.Fields(h.must("cat /etc/ssh/ssh_host_rsa_key.pub"))[1]
		hostEd := strings.Fields(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub"))[1]
		replace := func(i int, l ...string) []string {
			out := append([]string{}, good[:i]...)
			out = append(out, l...)
			out = append(out, good[i+1:]...)
			return renumber(out)
		}
		insert := func(l ...string) []string {
			out := append([]string{}, good[:len(good)-1]...)
			return renumber(append(append(out, l...), good[len(good)-1]))
		}
		b := body(t)
		cases := []struct {
			name   string
			script string
			lines  []string
			args   []string
			want   string
		}{
			{name: "command substitution in TARGET", lines: replace(0, "TARGET=$(touch /root/pwned)")},
			{name: "shell syntax in HUMAN", lines: replace(1, "HUMAN=owner;touch${IFS}/root/pwned")},
			{name: "command substitution in CA_KEY", lines: replace(2, "CA_KEY=ssh-ed25519 $(touch /root/pwned)")},
			{name: "backquotes in SOURCE", lines: replace(3, "SOURCE=`touch /root/pwned`")},
			{name: "quote breaking out in SOURCE", lines: replace(3, `SOURCE=127.0.0.1/32" ; touch /root/pwned ; "`)},
			// With plain read, "HUMAN=own\" and "er" would join into a valid
			// HUMAN=owner, and END would match.
			{name: "a line ending in a backslash isn't joined", lines: append(append(append([]string{}, good[0], `HUMAN=own\`, "er"), good[2:6]...), "END=6")},
			{name: "cut off after a data line", script: b + strings.Join(good[:3], "\n") + "\n"},
			{name: "cut off inside a data line", script: b + strings.Join(good[:2], "\n") + "\nCA_KEY=ssh-ed"},
			{name: "cut off right after the main line", script: b},
			{name: "a line missing", lines: append(append([]string{}, good[:1]...), good[2:]...), want: "END"},
			{name: "END too high", lines: append(append([]string{}, good[:6]...), "END=7"), want: "END"},
			{name: "END with a leading zero", lines: append(append([]string{}, good[:6]...), "END=06"), want: "END"},
			{name: "no END", lines: good[:6], want: "END"},
			{name: "a line after END", lines: append(append([]string{}, good...), "HUMAN=x")},
			{name: "END twice", lines: append(append([]string{}, good...), "END=6")},
			{name: "unknown name", lines: insert("FOO=bar"), want: "unknown"},
			{name: "lower-case name", lines: insert("human=x")},
			{name: "line without =", lines: insert("HUMAN")},
			{name: "empty line", lines: insert("")},
			{name: "carriage return", lines: replace(5, "SUDO=true\r")},
			{name: "TARGET twice", lines: insert("TARGET=db-2"), want: "twice"},
			{name: "SUDO twice", lines: insert("SUDO=false"), want: "twice"},
			{name: "HUMAN twice", lines: insert("HUMAN=owner"), want: "twice"},
			{name: "TARGET upper case", lines: replace(0, "TARGET=DB-1")},
			{name: "TARGET leading dash", lines: replace(0, "TARGET=-db")},
			{name: "TARGET 64 characters", lines: replace(0, "TARGET="+strings.Repeat("a", 64))},
			{name: "HUMAN 30 characters", lines: replace(1, "HUMAN="+strings.Repeat("a", 30))},
			{name: "HUMAN with underscore", lines: replace(1, "HUMAN=own_er")},
			{name: "CA_KEY rsa", lines: replace(2, "CA_KEY=ssh-rsa "+rsa)},
			{name: "CA_KEY with a comment", lines: replace(2, "CA_KEY="+h.ca+" comment")},
			{name: "CA_KEY not a key", lines: replace(2, "CA_KEY=ssh-ed25519 AAAAAAAA")},
			{name: "CA_KEY an ecdsa key labelled ed25519", lines: replace(2, "CA_KEY=ssh-ed25519 "+ecdsa)},
			{name: "SOURCE without a mask", lines: replace(3, "SOURCE=127.0.0.1")},
			{name: "SOURCE with host bits", lines: replace(3, "SOURCE=10.0.0.1/24")},
			{name: "SOURCE octet too big", lines: replace(3, "SOURCE=300.0.0.0/8")},
			{name: "SOURCE mask too long", lines: replace(4, "SOURCE=::1/129")},
			{name: "SOURCE triple colon", lines: replace(4, "SOURCE=1:::2/64")},
			{name: "SOURCE with a zone", lines: replace(4, "SOURCE=fe80::1%eth0/64")},
			{name: "SUDO yes", lines: replace(5, "SUDO=yes")},
			{name: "no SOURCE", lines: renumber(append(append([]string{}, good[:3]...), good[5:]...)), want: "SOURCE"},
			{name: "no CA_KEY", lines: renumber(append(append([]string{}, good[:2]...), good[3:]...)), want: "CA_KEY"},
			{name: "unknown argument", lines: good, args: []string{"--force"}, want: "unknown argument"},
			// docs/08 D13's data lines and options (G13).
			{name: "SIGNER_KEY not a CA_KEY", lines: replace(6, "SIGNER_KEY=ssh-ed25519 "+hostEd), want: "SIGNER_KEY"},
			{name: "SIGNER_KEY rsa", lines: replace(6, "SIGNER_KEY=ssh-rsa "+rsa), want: "SIGNER_KEY"},
			{name: "SIGNER_KEY with shell", lines: replace(6, "SIGNER_KEY=ssh-ed25519 $(touch /root/pwned)"), want: "SIGNER_KEY"},
			{name: "SIGNER_KEY twice", lines: insert(good[6]), want: "twice"},
			{name: "no SIGNER_KEY", lines: renumber(append(append([]string{}, good[:6]...), good[7:]...)), want: "SIGNER_KEY"},
			{name: "REVOKED_CA_KEY a CA_KEY", lines: insert("REVOKED_CA_KEY=" + h.ca), want: "REVOKED_CA_KEY"},
			{name: "REVOKED_CA_KEY not a key", lines: insert("REVOKED_CA_KEY=ssh-ed25519 AAAAAAAA"), want: "REVOKED_CA_KEY"},
			{name: "REVOKED_CA_KEY an ecdsa key labelled ed25519", lines: insert("REVOKED_CA_KEY=ssh-ed25519 " + ecdsa), want: "REVOKED_CA_KEY"},
			{name: "ISSUED with a leading zero", lines: replace(7, "ISSUED=0"+h.issued[1:]), want: "ISSUED"},
			{name: "ISSUED in seconds", lines: replace(7, "ISSUED="+h.issued[:10]), want: "ISSUED"},
			{name: "ISSUED negative", lines: replace(7, "ISSUED=-"+h.issued[1:]), want: "ISSUED"},
			{name: "ISSUED with shell", lines: replace(7, "ISSUED=$(touch /root/pwned)"), want: "ISSUED"},
			{name: "ISSUED twice", lines: insert(good[7]), want: "twice"},
			{name: "no ISSUED", lines: renumber(append(append([]string{}, good[:7]...), good[8:]...)), want: "ISSUED"},
			{name: "URL http", lines: replace(8, "URL=http://127.0.0.1:8443"), want: "URL"},
			{name: "URL with a path", lines: replace(8, "URL=https://127.0.0.1:8443/x"), want: "URL"},
			{name: "URL with userinfo", lines: replace(8, "URL=https://a@127.0.0.1"), want: "URL"},
			{name: "URL with shell", lines: replace(8, "URL=https://$(touch${IFS}/root/pwned)"), want: "URL"},
			{name: "URL with a quote", lines: replace(8, `URL=https://a"b`), want: "URL"},
			{name: "URL with a space", lines: replace(8, "URL=https://a b"), want: "URL"},
			{name: "URL twice", lines: insert(good[8]), want: "twice"},
			{name: "no URL", lines: renumber(good[:8]), want: "URL"},
			{name: "--cacert without a file", lines: good, args: []string{"--cacert"}, want: "--cacert"},
			{name: "--cacert of a missing file", lines: good, args: []string{"--cacert", "/nonexistent"}, want: "--cacert"},
			{name: "--cacert of no certificate", lines: good, args: []string{"--cacert", "/etc/hostname"}, want: "PEM"},
			{name: "--cacert twice", lines: good, args: []string{"--cacert", "/root/ca.pub", "--cacert", "/root/ca.pub"}, want: "twice"},
			{name: "--enroll without a token", lines: good, args: []string{"--enroll"}, want: "token"},
			{name: "--enroll with shell", lines: good, args: []string{"--enroll", "nye1.$(touch /root/pwned)"}, want: "token"},
			{name: "--enroll not a token", lines: good, args: []string{"--enroll", "Bearer abc"}, want: "token"},
			{name: "--enroll with --dry-run", lines: good, args: []string{"--dry-run", "--enroll", enrollToken}, want: "--dry-run"},
			{name: "--status with --uninstall", lines: good, args: []string{"--status", "--uninstall"}, want: "--status"},
			{name: "--uninstall with --enroll", lines: good, args: []string{"--uninstall", "--enroll", enrollToken}, want: "--uninstall"},
			{name: "--uninstall with --reset-pull-state", lines: good, args: []string{"--uninstall", "--reset-pull-state"}, want: "--uninstall"},
			{name: "--dry-run twice", lines: good, args: []string{"--dry-run", "--dry-run"}, want: "twice"},
		}
		before := h.snapshot()
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				s := c.script
				if s == "" {
					s = served(t, c.lines, afterTerminator)
				}
				for _, form := range []string{"file", "pipe"} {
					var r result
					if form == "file" {
						r = h.run(s, c.args...)
					} else if len(c.args) == 0 {
						r = h.pipe(s)
					} else {
						continue
					}
					if r.code == 0 {
						t.Fatalf("%s: accepted: %s", form, r)
					}
					if c.want != "" && !strings.Contains(r.err, c.want) {
						t.Errorf("%s: the refusal doesn't mention %q: %s", form, c.want, r)
					}
					if h.exists("/root/pwned") || h.exists("/root/after-terminator") {
						t.Fatalf("%s: a data line or the code after the terminator ran: %s", form, r)
					}
					h.sameAs(before, form+" "+c.name)
				}
			})
		}

		t.Run("data from a terminal", func(t *testing.T) {
			// What `sudo sh setup.sh` gets from a file cut right after the
			// main line, if the shell ever handed main the terminal.
			lines := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
			lines[len(lines)-1] = `main "$@"`
			h.put("/root/tty.sh", strings.Join(lines, "\n")+"\n")
			o, e, code := h.exec(`script -qec "sh /root/tty.sh" /dev/null`, "")
			if code == 0 || !strings.Contains(o+e, "terminal") {
				t.Fatalf("data from a terminal: exit %d\n%s%s", code, o, e)
			}
			h.sameAs(before, "data from a terminal")
		})
		t.Run("not root", func(t *testing.T) {
			h.put("/tmp/setup.sh", served(t, good, ""))
			o, e, code := h.exec("chmod 0644 /tmp/setup.sh && runuser -u alice -- sh /tmp/setup.sh", "")
			if code == 0 || !strings.Contains(e, "root") {
				t.Fatalf("as alice: exit %d\n%s%s", code, o, e)
			}
			h.sameAs(before, "a run as alice")
		})
	})
}

// renumber recomputes the END line of lines.
func renumber(lines []string) []string {
	var out []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "END=") {
			out = append(out, l)
		}
	}
	return append(out, fmt.Sprintf("END=%d", len(out)))
}

// TestRefusedHostStates: each failed check of §5.7 step 1 and step 4's
// account checks stops the run without changing a file (G8).
func TestRefusedHostStates(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		v := h.values("owner")
		refused := func(what, prepare, undo, want string) {
			t.Helper()
			h.must(prepare)
			before := h.snapshot()
			r := h.setup(v)
			if r.code == 0 {
				t.Fatalf("%s: accepted: %s", what, r)
			}
			if !strings.Contains(strings.ToLower(r.err), strings.ToLower(want)) {
				t.Errorf("%s: the refusal doesn't mention %q: %s", what, want, r)
			}
			h.sameAs(before, what)
			h.must(undo)
		}
		refused("a leftover home", "mkdir /home/ny-owner", "rmdir /home/ny-owner", "exists without its account")
		refused("an unlisted account", "useradd -m -s /bin/sh ny-owner", "userdel -r ny-owner 2>/dev/null; rm -rf /home/ny-owner", "didn't create it")
		refused("sshd_config not starting with the Include", "sed -i '1i Port 22' /etc/ssh/sshd_config", "sed -i '1d' /etc/ssh/sshd_config", "first line")
		refused("another TrustedUserCAKeys in a drop-in", "echo 'TrustedUserCAKeys /etc/ssh/other.pub' > /etc/ssh/sshd_config.d/10-other.conf", "rm /etc/ssh/sshd_config.d/10-other.conf", "TrustedUserCAKeys")
		refused("an AuthorizedPrincipalsFile in a Match block", "printf 'Match User bob\\n\\tAuthorizedPrincipalsFile /etc/ssh/bob\\n' >> /etc/ssh/sshd_config", "sed -i '/^Match User bob/,$d' /etc/ssh/sshd_config", "AuthorizedPrincipalsFile")
		refused("a broken sshd configuration", "echo 'NoSuchKeyword yes' > /etc/ssh/sshd_config.d/99-broken.conf", "rm /etc/ssh/sshd_config.d/99-broken.conf", "sshd -t")
		refused("a group-writable /etc/ssh/nyyrikki", "mkdir -m 0775 /etc/ssh/nyyrikki", "rmdir /etc/ssh/nyyrikki", "writable")

		h.mustSetup(v)
		// sshd -T shows Nyyrikki's value, which comes first; the other file
		// is found by reading the configuration.
		refused("another TrustedUserCAKeys after Nyyrikki's", "echo 'TrustedUserCAKeys /etc/ssh/other.pub' > /etc/ssh/sshd_config.d/60-other.conf", "rm /etc/ssh/sshd_config.d/60-other.conf", "60-other.conf")
		refused("a changed password field", "usermod -p '!' ny-owner", "usermod -p '*' ny-owner", "password field")
		refused("a changed shell", "usermod -s /bin/bash ny-owner", "usermod -s /bin/sh ny-owner", "shell")
		refused("a changed home owner", "chown root /home/ny-owner", "chown ny-owner /home/ny-owner", "owns")
		refused("a moved home", "usermod -d /home/elsewhere ny-owner", "usermod -d /home/ny-owner ny-owner", "home")
		refused("a corrupt accounts list", "echo root >> /etc/ssh/nyyrikki/accounts", "sed -i '/^root$/d' /etc/ssh/nyyrikki/accounts", "isn't a Nyyrikki account")
		// Review round 1 on #30, finding 7: root given to the account by
		// another way than Nyyrikki's sudoers file.
		refused("the account in the root group", "usermod -aG root ny-owner", "gpasswd -d ny-owner root", "group root")
		refused("another sudoers file naming the account", "echo 'ny-owner ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/10-local", "rm /etc/sudoers.d/10-local", "10-local names ny-owner")
		refused("a sudoers rule for one of its groups", "groupadd ops && usermod -aG ops ny-owner && echo '%ops ALL=(ALL) ALL' > /etc/sudoers.d/10-ops", "rm /etc/sudoers.d/10-ops; gpasswd -d ny-owner ops; groupdel ops", "names %ops")
		// Review round 2 on #30, finding 1 and 2: a file named like the
		// setup's, a rule for every user, a rule by UID, and a
		// root-equivalent group.
		refused("a stray 50-nyyrikki- file naming the account", "echo 'ny-owner ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/50-nyyrikki-x", "rm /etc/sudoers.d/50-nyyrikki-x", "50-nyyrikki-x names ny-owner")
		refused("a rule for every user", "echo 'ALL ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/10-all", "rm /etc/sudoers.d/10-all", "every user")
		refused("a rule by UID", "echo \"#$(id -u ny-owner) ALL=(ALL) ALL\" > /etc/sudoers.d/10-uid", "rm /etc/sudoers.d/10-uid", "10-uid names #")
		refused("the account in the docker group", "groupadd -f docker && usermod -aG docker ny-owner", "gpasswd -d ny-owner docker", "group docker")
		refused("PermitUserEnvironment on", "echo 'PermitUserEnvironment yes' > /etc/ssh/sshd_config.d/60-env.conf", "rm /etc/ssh/sshd_config.d/60-env.conf", "permituserenvironment no")
		// Review round 3 on #30, finding 4: a comment naming the UID is no
		// rule.
		h.must("echo \"# see ticket #$(id -u ny-owner) and ny-owner\" > /etc/sudoers.d/10-comment")
		h.mustSetup(v)
		h.must("rm /etc/sudoers.d/10-comment")
		refused("an invalid revocation list", "cp /etc/ssh/nyyrikki/revoked.krl /root/krl && : > /etc/ssh/nyyrikki/revoked.krl", "cp /root/krl /etc/ssh/nyyrikki/revoked.krl", "revocation list")
		h.mustSetup(v)
	})
}

// TestRollback: a failure, or INT, TERM or HUP, in each of steps 2 to 6
// rolls the host back, also when a signal arrives during the rollback,
// and nothing runs after it (G8).
func TestRollback(t *testing.T) {
	type injection struct {
		cmd, pattern, action string
		skip                 int
	}
	type tcase struct {
		name   string
		rerun  bool // set up with owner first, then run with other: owner is stale
		inert  bool // the run got past step 2: the stale account must be inert
		revoke bool // the re-run revokes a CA key (docs/08 D13 step 2)
		inject []injection
		real   string // a real configuration that makes the step fail
	}
	var cases []tcase
	cases = append(cases,
		tcase{name: "step 3 sshd -t fails", inject: []injection{{"sshd", "-t", "fail", 1}}},
		tcase{name: "step 3 sshd -T shows another value", real: "printf 'Match all\\n\\tAuthorizedKeysCommand /usr/local/bin/akc\\n\\tAuthorizedKeysCommandUser nobody\\n' > /etc/ssh/sshd_config.d/10-local.conf"},
		tcase{name: "re-run, step 3 sshd -T shows another value", rerun: true, real: "printf 'Match all\\n\\tClientAliveInterval 60\\n' > /etc/ssh/sshd_config.d/10-local.conf"},
		tcase{name: "step 3 KRL fails", inject: []injection{{"ssh-keygen", "-q -k -f*", "fail", 0}}},
		tcase{name: "step 4 useradd fails", inject: []injection{{"useradd", "*", "fail", 0}}},
		tcase{name: "step 6 visudo fails", inject: []injection{{"visudo", "*", "fail", 0}}},
		tcase{name: "re-run, step 2 fails", rerun: true, inject: []injection{{"rm", "*/etc/sudoers.d/50-nyyrikki-ny-owner", "fail", 0}}},
		tcase{name: "re-run, step 5 userdel fails", rerun: true, inert: true, inject: []injection{{"userdel", "*ny-owner", "fail", 0}}},
		tcase{name: "re-run, step 6 visudo fails", rerun: true, inert: true, inject: []injection{{"visudo", "*", "fail", 0}}},
		// docs/08 D13: the revocation of step 2, the pull of step 8.
		tcase{name: "re-run, step 2 revocation fails", rerun: true, revoke: true, inject: []injection{{"ssh-keygen", "-q -k -u -f*", "fail", 0}}},
		tcase{name: "step 3 signers fail", inject: []injection{{"mv", "*/etc/ssh/nyyrikki/signers.pub", "fail", 0}}},
		tcase{name: "step 8 pull.conf fails", inject: []injection{{"mv", "*/etc/ssh/nyyrikki/pull.conf", "fail", 0}}},
		tcase{name: "re-run, step 8 schedule fails", rerun: true, inert: true, revoke: true, inject: []injection{{"mv", "*/etc/[cp]*/nyyrikki*", "fail", 0}}},
	)
	for _, sig := range []string{"INT", "TERM", "HUP"} {
		cases = append(cases,
			tcase{name: sig + " in step 3", inject: []injection{{"sshd", "-T -C*", sig, 0}}},
			tcase{name: sig + " in step 4", inject: []injection{{"useradd", "*", sig, 0}}},
			tcase{name: sig + " in step 6", inject: []injection{{"visudo", "*", sig, 0}}},
			tcase{name: sig + " in step 2 of a re-run", rerun: true, inject: []injection{{"rm", "*/etc/sudoers.d/50-nyyrikki-ny-owner", sig, 0}}},
			tcase{name: sig + " in step 5 of a re-run", rerun: true, inert: true, inject: []injection{{"userdel", "*ny-owner", sig, 0}}},
			tcase{name: sig + " during the rollback", inject: []injection{{"visudo", "*", "fail", 0}, {"userdel", "*", sig, 0}}},
			tcase{name: sig + " twice during the rollback", inject: []injection{{"visudo", "*", sig, 0}, {"userdel", "*", sig, 0}, {"sshd", "-t", sig, 2}}},
			tcase{name: sig + " in step 8", inject: []injection{{"mv", "*/etc/ssh/nyyrikki/pull.sh", sig, 0}}},
		)
	}
	forEachDistro(t, func(t *testing.T, d distro) {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				h := newHost(t, d)
				v := h.values("owner")
				if c.rerun {
					h.mustSetup(v)
					v = h.values("other")
					if c.revoke {
						v.revoked = []string{"ssh-ed25519 " + strings.Fields(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub"))[1]}
					}
				}
				if c.real != "" {
					h.must(c.real)
				}
				before := h.snapshot()
				for _, in := range c.inject {
					h.installShim(in.cmd, in.pattern, in.action, in.skip, false)
				}
				r := h.run(served(t, v.lines(), afterTerminator))
				for _, in := range c.inject {
					if !h.shimHit(in.cmd) {
						t.Fatalf("the %s shim never fired: %s", in.cmd, r)
					}
					h.clearShim(in.cmd)
				}
				if r.code == 0 {
					t.Fatalf("succeeded: %s", r)
				}
				if !strings.Contains(r.err, "rolled back") {
					t.Fatalf("no rollback: %s", r)
				}
				if strings.Contains(r.out, "Done.") || h.exists("/root/after-terminator") {
					t.Fatalf("something ran after the rollback: %s", r)
				}
				after := h.snapshot()
				if c.revoke {
					// A revocation is taken away, which a rollback leaves
					// (docs/08 D13), unless it never happened.
					q := h.must("ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl /etc/ssh/ssh_host_ed25519_key.pub || true")
					if failed := c.inject[0].cmd == "ssh-keygen"; failed == strings.Contains(q, "REVOKED") {
						t.Fatalf("revoked after the rollback: %q", q)
					}
					before = dropPath(before, "/etc/ssh/nyyrikki/revoked.krl")
					after = dropPath(after, "/etc/ssh/nyyrikki/revoked.krl")
				}
				if c.rerun {
					// What step 2 took away from the stale account stays
					// away, and once step 5 deleted it, it stays deleted.
					before = dropPath(before, "ny-owner")
					after = dropPath(after, "ny-owner")
					if h.accountExists("ny-other") {
						t.Fatal("the rollback left the new account")
					}
				}
				if dd := diffSnap(before, after); dd != "" {
					t.Fatalf("the rollback left changes:\n%s\n%s", dd, r)
				}
				if h.exists("/etc/sudoers.d/.nyyrikki-new") || h.exists("/etc/ssh/sshd_config.d/.nyyrikki-new") {
					t.Fatal("a temporary file is left")
				}
				if c.inert {
					if out, code := h.certLogin("owner", "db-1", "true"); code == 0 {
						t.Fatalf("the stale account still logs in after the rollback: %q", out)
					}
				}
				// sshd runs the restored configuration: a plain key reaches no
				// ny-* account, and a re-run works.
				for _, a := range []string{"ny-owner", "ny-other"} {
					if h.accountExists(a) && h.plainKeyReaches(a) {
						t.Fatalf("a plain key reaches %s after the rollback", a)
					}
				}
				h.must("rm -f /etc/ssh/sshd_config.d/10-local.conf")
				h.mustSetup(v)
				if out, code := h.certLogin(v.humans[0], "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
					t.Fatalf("after the rollback and a re-run: exit %d %q", code, out)
				}
			})
		}
	})
}

func dropPath(snap, p string) string {
	var out []string
	for _, l := range strings.Split(snap, "\n") {
		if !strings.Contains(l, p) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// TestKilled: after a SIGKILL at each step, no plain key reaches any ny-*
// account, no account has a sudoers file without its Match block, and a
// re-run or --uninstall brings the host to a defined state (G8).
func TestKilled(t *testing.T) {
	type tcase struct {
		name          string
		rerun         bool
		revoke        bool
		cmd, pattern  string
		skip          int
		thenUninstall bool
	}
	cases := []tcase{
		{name: "step 3 before the KRL", cmd: "ssh-keygen", pattern: "-q -k -f*"},
		{name: "step 3 before sshd -T", cmd: "sshd", pattern: "-T -C*"},
		{name: "step 4 before useradd", cmd: "useradd", pattern: "*"},
		{name: "step 4 before the principals file", cmd: "mv", pattern: "*/etc/ssh/nyyrikki/principals/ny-owner"},
		{name: "step 6 before visudo", cmd: "visudo", pattern: "*", thenUninstall: true},
		{name: "step 6 before the sudoers file", cmd: "mv", pattern: "*/etc/sudoers.d/50-nyyrikki-ny-owner"},
		{name: "re-run, step 2", rerun: true, cmd: "rm", pattern: "*/etc/sudoers.d/50-nyyrikki-ny-owner"},
		{name: "re-run, step 3", rerun: true, cmd: "sshd", pattern: "-T -C*"},
		{name: "re-run, step 4", rerun: true, cmd: "useradd", pattern: "*", thenUninstall: true},
		{name: "re-run, step 5 before userdel", rerun: true, cmd: "userdel", pattern: "*ny-owner"},
		{name: "re-run, step 5 before the drop-in", rerun: true, cmd: "mv", pattern: "*/etc/ssh/sshd_config.d/50-nyyrikki.conf", skip: 1},
		{name: "re-run, step 6", rerun: true, cmd: "visudo", pattern: "*"},
		// docs/08 D13.
		{name: "step 3 before signers.pub", cmd: "mv", pattern: "*/etc/ssh/nyyrikki/signers.pub"},
		{name: "step 8 before pull.sh", cmd: "mv", pattern: "*/etc/ssh/nyyrikki/pull.sh", thenUninstall: true},
		{name: "step 8 before the schedule", cmd: "mv", pattern: "*/etc/[cp]*/nyyrikki*"},
		{name: "re-run, step 2 revocation", rerun: true, revoke: true, cmd: "ssh-keygen", pattern: "-q -k -u -f*"},
		{name: "re-run, step 2 before the KRL is replaced", rerun: true, revoke: true, cmd: "mv", pattern: "*/etc/ssh/nyyrikki/revoked.krl"},
	}
	forEachDistro(t, func(t *testing.T, d distro) {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				h := newHost(t, d)
				pristine := h.snapshot()
				v := h.values("owner")
				if c.rerun {
					h.mustSetup(v)
					v = h.values("other")
					if c.revoke {
						v.revoked = []string{"ssh-ed25519 " + strings.Fields(h.must("cat /etc/ssh/ssh_host_ed25519_key.pub"))[1]}
					}
				}
				h.installShim(c.cmd, c.pattern, "KILL", c.skip, false)
				r := h.run(served(t, v.lines(), afterTerminator))
				if !h.shimHit(c.cmd) {
					t.Fatalf("the %s shim never fired: %s", c.cmd, r)
				}
				if r.code == 0 {
					t.Fatalf("succeeded: %s", r)
				}
				h.assertFailsClosed()
				if c.thenUninstall {
					if r := h.setup(v, "--uninstall"); r.code != 0 {
						t.Fatalf("--uninstall after the kill: %s", r)
					}
					h.sameAs(pristine, "a kill, then --uninstall")
					return
				}
				h.mustSetup(v)
				if out, code := h.certLogin(v.humans[0], "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
					t.Fatalf("after the kill and a re-run: exit %d %q", code, out)
				}
				if c.rerun && h.accountExists("ny-owner") {
					t.Fatal("the re-run left the stale account")
				}
				h.assertFailsClosed()
			})
		}
	})
}

func (h *host) assertFailsClosed() {
	h.t.Helper()
	accts := strings.Fields(h.must("getent passwd | cut -d: -f1 | grep '^ny-' || true"))
	for _, a := range accts {
		if h.plainKeyReaches(a) {
			h.t.Fatalf("a plain key reaches %s", a)
		}
	}
	dropin, _, _ := h.exec("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf", "")
	for _, f := range strings.Fields(h.must("ls /etc/sudoers.d/ | grep '^50-nyyrikki-' || true")) {
		a := strings.TrimPrefix(f, "50-nyyrikki-")
		if !strings.Contains(dropin, "\nMatch User "+a+"\n") {
			h.t.Fatalf("%s has a sudoers file but no Match block", a)
		}
	}
}

// TestHumanRemoved: a re-run after a human leaves the target removes their
// sudoers file, principals file and account; with processes, it stops and
// the account stays inert (G8).
func TestHumanRemoved(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.mustSetup(h.values("owner", "second"))
		if out, code := h.certLogin("second", "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
			t.Fatalf("second: exit %d %q", code, out)
		}

		// With a process: refused, and second is inert.
		h.must("runuser -u ny-second -- sh -c 'sleep 1000 >/dev/null 2>&1 &'")
		r := h.setup(h.values("owner", "third"))
		if r.code == 0 || !strings.Contains(r.err, "has processes") {
			t.Fatalf("a stale account with processes: %s", r)
		}
		if !h.accountExists("ny-second") || h.accountExists("ny-third") {
			t.Fatal("the stopped run left the wrong accounts")
		}
		for _, p := range []string{"/etc/sudoers.d/50-nyyrikki-ny-second", "/etc/ssh/nyyrikki/principals/ny-second"} {
			if h.exists(p) {
				t.Fatalf("%s is back after the rollback", p)
			}
		}
		if out, code := h.certLogin("second", "db-1", "true"); code == 0 {
			t.Fatalf("the stale account logs in: %q", out)
		}
		if h.plainKeyReaches("ny-second") {
			t.Fatal("a plain key reaches the stale account")
		}
		h.must("pkill -KILL -u ny-second; sleep 1")

		r = h.mustSetup(h.values("owner", "third"))
		for _, p := range []string{"/etc/sudoers.d/50-nyyrikki-ny-second", "/etc/ssh/nyyrikki/principals/ny-second", "/home/ny-second"} {
			if h.exists(p) {
				t.Fatalf("%s left after the human was removed", p)
			}
		}
		if h.accountExists("ny-second") {
			t.Fatal("ny-second left after the human was removed")
		}
		if got := h.must("cat /etc/ssh/nyyrikki/accounts"); got != "ny-owner\nny-third\n" {
			t.Fatalf("accounts list: %q", got)
		}
		if dropin := h.must("cat /etc/ssh/sshd_config.d/50-nyyrikki.conf"); strings.Contains(dropin, "ny-second") {
			t.Fatal("the drop-in still has ny-second's block")
		}
		if out, code := h.certLogin("third", "db-1", "sudo -n id -u"); code != 0 || out != "0\n" {
			t.Fatalf("third: exit %d %q", code, out)
		}
	})
}

// TestUninstall: --uninstall refuses while an account has processes, after
// taking away its sudo and principals; then leaves nothing (G8).
func TestUninstall(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		pristine := h.snapshot()
		v := h.values("owner")
		h.mustSetup(v)
		h.must("runuser -u ny-owner -- sh -c 'sleep 1000 >/dev/null 2>&1 &'")
		r := h.setup(v, "--uninstall")
		if r.code == 0 || !strings.Contains(r.err, "has processes") {
			t.Fatalf("--uninstall with processes: %s", r)
		}
		if h.exists("/etc/sudoers.d/50-nyyrikki-ny-owner") || h.exists("/etc/ssh/nyyrikki/principals/ny-owner") {
			t.Fatal("--uninstall stopped before taking away sudo and the principals file")
		}
		if h.plainKeyReaches("ny-owner") {
			t.Fatal("a plain key reaches ny-owner after a stopped --uninstall")
		}
		h.must("pkill -KILL -u ny-owner; sleep 1")
		r = h.setup(v, "--uninstall")
		if r.code != 0 {
			t.Fatalf("--uninstall: %s", r)
		}
		h.sameAs(pristine, "--uninstall")
		// Again, on a clean host.
		if r := h.setup(v, "--uninstall"); r.code != 0 {
			t.Fatalf("--uninstall on a clean host: %s", r)
		}
		h.sameAs(pristine, "a second --uninstall")

		// Review round 1 on #30, finding 2. A configuration sshd -t refuses
		// stops --uninstall before it changes anything.
		h.mustSetup(v)
		h.must("echo 'NoSuchKeyword yes' > /etc/ssh/sshd_config.d/99-broken.conf")
		before := h.snapshot()
		if r := h.setup(v, "--uninstall"); r.code == 0 || !strings.Contains(r.err, "before any change") {
			t.Fatalf("--uninstall with a broken sshd configuration: %s", r)
		}
		h.sameAs(before, "--uninstall refused by sshd -t")
		h.must("rm /etc/ssh/sshd_config.d/99-broken.conf")
		// A check that fails once the drop-in is gone keeps the revocation
		// list the running sshd reads, so key logins keep working.
		// "*", not useradd's "!": sshd without PAM (Alpine) refuses a locked account.
		h.must("useradd -m -s /bin/sh admin && usermod -p '*' admin")
		h.installShim("sshd", "-t", "fail", 1, false)
		r = h.setup(v, "--uninstall")
		h.clearShim("sshd")
		if r.code == 0 {
			t.Fatalf("--uninstall with sshd -t failing at the end: %s", r)
		}
		if !h.exists("/etc/ssh/nyyrikki/revoked.krl") || !h.plainKeyReaches("admin") {
			t.Fatalf("a failed --uninstall locked key logins out: %s", r)
		}
		if r := h.setup(v, "--uninstall"); r.code != 0 {
			t.Fatalf("--uninstall again: %s", r)
		}
		h.must("userdel -r admin")
		h.sameAs(pristine, "--uninstall after a failed one")
	})
}

// TestRollbackKeepsRevocationList: a rollback that can't reload sshd keeps
// the revocation list the running sshd reads, so key logins keep working
// (review round 1 on #30, finding 2).
func TestRollbackKeepsRevocationList(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		v := h.values("owner")
		// "*", not useradd's "!": sshd without PAM (Alpine) refuses a locked account.
		h.must("useradd -m -s /bin/sh admin && usermod -p '*' admin")
		h.installShim("visudo", "*", "fail", 0, false)
		h.installShim("sshd", "-t", "fail", 2, false)
		r := h.setup(v)
		h.clearShim("visudo")
		h.clearShim("sshd")
		if r.code == 0 || !strings.Contains(r.err, "rolled back") || !strings.Contains(r.err, "kept /etc/ssh/nyyrikki/revoked.krl") {
			t.Fatalf("rollback: %s", r)
		}
		if !h.plainKeyReaches("admin") {
			t.Fatalf("a rollback that couldn't reload sshd locked key logins out: %s", r)
		}
		h.mustSetup(v)
	})
}

// TestDryRun changes nothing and lists the files.
func TestDryRun(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		v := h.values("owner")
		for i := 0; i < 2; i++ {
			before := h.snapshot()
			r := h.setup(v, "--dry-run")
			if r.code != 0 {
				t.Fatalf("--dry-run: %s", r)
			}
			for _, want := range []string{"would write /etc/ssh/sshd_config.d/50-nyyrikki.conf", "Match User ny-owner", "nothing was changed"} {
				if !strings.Contains(r.out, want) {
					t.Errorf("--dry-run output lacks %q:\n%s", want, r.out)
				}
			}
			h.sameAs(before, "--dry-run")
			r = h.setup(v, "--uninstall", "--dry-run")
			if r.code != 0 {
				t.Fatalf("--uninstall --dry-run: %s", r)
			}
			h.sameAs(before, "--uninstall --dry-run")
			h.mustSetup(v)
		}
	})
}

// TestManualPage: the files the script writes are the manual page's
// listing, for the page's own sample values (G9), the trust pull's files
// included (docs/08 G13): pull.sh as the page's command takes it from
// the script, and the schedule the host's cron runs.
func TestManualPage(t *testing.T) {
	files, fromScript, data := manualFiles(t)
	check := func(t *testing.T, h *host, withLogind bool) {
		pristine := h.snapshot()
		served := served(t, data, "")
		r := h.run(served)
		if r.code != 0 {
			t.Fatalf("setup with the page's data lines: %s", r)
		}
		for path, f := range files {
			skip := false
			switch {
			case strings.HasPrefix(path, "/etc/systemd/"):
				skip = !withLogind
			case path == "/etc/cron.d/nyyrikki":
				skip = !strings.Contains(r.out, "pull: cron.d")
			case path == "/etc/periodic/15min/nyyrikki-pull":
				skip = !strings.Contains(r.out, "pull: periodic")
			}
			if skip {
				if h.exists(path) {
					t.Errorf("%s written on a host where it doesn't apply", path)
				}
				continue
			}
			got, e, code := h.exec("stat -c '%a %u' "+shellQuote(path)+" && cat "+shellQuote(path), "")
			if code != 0 {
				t.Errorf("%s: %s", path, e)
				continue
			}
			want := strings.TrimPrefix(f[0], "0") + " 0\n" + f[1]
			if got != want {
				t.Errorf("%s differs from docs/setup/ssh-hosts.md:\ngot:\n%s\nwant:\n%s", path, got, want)
			}
		}
		if !strings.Contains(r.out, "pull: cron.d") && !strings.Contains(r.out, "pull: periodic") {
			t.Errorf("no pull schedule on a host with cron and curl:\n%s", r.out)
		}
		// The page's command takes pull.sh from the script, byte for byte.
		h.must("mkdir -p /root/manual")
		h.put("/root/manual/setup.sh", served)
		for path, f := range fromScript {
			name := path[strings.LastIndex(path, "/")+1:]
			h.must("cd /root/manual && " + f[1])
			got := h.must("stat -c '%a %u' " + shellQuote(path) + " && [ \"$(md5sum < /root/manual/" + name + ")\" = \"$(md5sum < " + shellQuote(path) + ")\" ] && echo same")
			if got != strings.TrimPrefix(f[0], "0")+" 0\nsame\n" {
				t.Errorf("%s isn't what the page's command takes from the script: %q", path, got)
			}
		}
		h.must("rm -rf /root/manual")
		// Nothing else: every file the script added is listed, or the KRL.
		for _, l := range strings.Split(diffSnap(pristine, h.snapshot()), "\n") {
			if !strings.HasPrefix(l, "+ /") {
				continue
			}
			f := strings.Fields(l[2:])
			if f[1] != "f" {
				continue
			}
			// Besides the listing: the KRL, and what useradd makes (the
			// home's skeleton files, a mail spool on RHEL-family hosts).
			_, listed := files[f[0]]
			_, taken := fromScript[f[0]]
			if !listed && !taken && f[0] != "/etc/ssh/nyyrikki/revoked.krl" && !strings.HasPrefix(f[0], "/home/ny-owner/") && !strings.HasSuffix(f[0], "/mail/ny-owner") {
				t.Errorf("the script wrote %s, which the manual page doesn't list", f[0])
			}
		}
	}
	forEachDistro(t, func(t *testing.T, d distro) {
		check(t, newHost(t, d), false)
	})
	t.Run("debian-systemd", func(t *testing.T) {
		needSystemd(t)
		t.Parallel()
		check(t, newHost(t, debianSystemd), true)
	})
}

// TestSessionKill, on Debian 13 with systemd as PID 1 (docs/07 M18): the
// setup turns session kill on and reports it, a cut session's sudo
// process that ignores TERM is gone, re-runs are idempotent and add new
// accounts, a failed logind check and a signal in step 7 roll back, a
// condition that no longer holds removes the drop-ins, another logind
// file is refused, and --uninstall leaves nothing in effect (G8).
func TestSessionKill(t *testing.T) {
	needSystemd(t)
	h := newHost(t, debianSystemd)
	pristine := h.snapshot()
	logind := func() string {
		return h.must(`for p in KillUserProcesses KillOnlyUsers; do busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager $p; done`)
	}
	v := h.values("owner")
	r := h.mustSetup(v)
	if !strings.Contains(r.out, "session_kill: true") {
		t.Fatalf("session_kill isn't true: %s", r)
	}
	if got := logind(); got != "b true\nas 1 \"ny-owner\"\n" {
		t.Fatalf("logind: %q", got)
	}

	t.Run("a cut session's processes are gone", func(t *testing.T) {
		h.sign("nyyrikki:owner@db-1")
		h.must(`ssh -n -i /root/u -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ny-owner@127.0.0.1 'sudo -n sh -c "trap \"\" TERM HUP INT; setsid sleep 1001 & exec sleep 1002"' >/dev/null 2>&1 &
echo $! > /root/ssh.pid`)
		sleeps := func() string { o, _, _ := h.exec("ps -C sleep -o user=,args= || true", ""); return o }
		waitFor(t, 15*time.Second, "the commands to start", func() bool {
			s := sleeps()
			return strings.Contains(s, "root     sleep 1002") && strings.Contains(s, "sleep 1001")
		})
		h.must("kill $(cat /root/ssh.pid)")
		start := time.Now()
		waitFor(t, 20*time.Second, "the session's processes to be gone", func() bool {
			return !strings.Contains(sleeps(), "sleep 100")
		})
		t.Logf("gone %s after the connection closed", time.Since(start).Round(time.Second))
	})

	once := h.snapshot()
	r = h.mustSetup(v)
	if !strings.Contains(r.out, "session_kill: true") {
		t.Fatalf("re-run: %s", r)
	}
	h.sameAs(once, "a re-run with session kill")

	v2 := h.values("owner", "second")
	h.mustSetup(v2)
	if got := logind(); got != "b true\nas 2 \"ny-owner\" \"ny-second\"\n" {
		t.Fatalf("a new account isn't in KillOnlyUsers: %q", got)
	}

	t.Run("a failed logind check rolls back", func(t *testing.T) {
		before := h.snapshot()
		h.installShim("busctl", "*KillOnlyUsers*", "fail", 1, true)
		r := h.setup(h.values("owner", "second", "third"))
		h.clearShim("busctl")
		if r.code == 0 || !strings.Contains(r.err, "rolled back") {
			t.Fatalf("%s", r)
		}
		h.sameAs(before, "a failed logind check")
	})
	t.Run("TERM in step 7 rolls back", func(t *testing.T) {
		before := h.snapshot()
		h.installShim("systemctl", "restart systemd-logind.service", "TERM", 0, false)
		r := h.setup(h.values("owner", "second", "third"))
		h.clearShim("systemctl")
		if r.code == 0 || !strings.Contains(r.err, "rolled back") {
			t.Fatalf("%s", r)
		}
		h.sameAs(before, "TERM in step 7")
	})
	t.Run("another logind file is refused", func(t *testing.T) {
		h.must("printf '[Login]\\nKillUserProcesses=no\\n' > /etc/systemd/logind.conf.d/10-other.conf")
		before := h.snapshot()
		r := h.setup(v2)
		if r.code == 0 || !strings.Contains(r.err, "logind") {
			t.Fatalf("%s", r)
		}
		h.sameAs(before, "another logind file")
		h.must("rm /etc/systemd/logind.conf.d/10-other.conf")
	})
	t.Run("a condition no longer holding removes the drop-ins", func(t *testing.T) {
		h.must("cp /etc/pam.d/common-session /root/common-session && sed -i 's/^\\(session.*pam_systemd\\)/#\\1/' /etc/pam.d/common-session")
		r := h.mustSetup(v2)
		if !strings.Contains(r.out, "session_kill: false") || !strings.Contains(r.out, "pam_systemd") {
			t.Fatalf("%s", r)
		}
		if h.exists("/etc/systemd/logind.conf.d/50-nyyrikki.conf") || h.exists("/etc/systemd/system/session-.scope.d/50-nyyrikki.conf") {
			t.Fatal("the drop-ins are still there")
		}
		if got := logind(); got != "b false\nas 0\n" {
			t.Fatalf("logind: %q", got)
		}
		h.must("cp /root/common-session /etc/pam.d/common-session")
		if r := h.mustSetup(v2); !strings.Contains(r.out, "session_kill: true") {
			t.Fatalf("back on: %s", r)
		}
	})

	// After a login, the account's systemd --user stays for logind's
	// UserStopDelaySec, and for good if logind restarted meanwhile (as the
	// re-runs above did). --uninstall refuses while it runs and says how
	// to end it.
	if _, _, code := h.exec("pgrep -u ny-owner", ""); code == 0 {
		r := h.setup(v2, "--uninstall")
		if r.code == 0 || !strings.Contains(r.err, "systemctl stop user@") {
			t.Fatalf("--uninstall with a user manager running: %s", r)
		}
		h.must("for a in ny-owner ny-second; do id -u $a >/dev/null 2>&1 && systemctl stop user@$(id -u $a).service; done; true")
	}
	if r := h.setup(v2, "--uninstall"); r.code != 0 {
		t.Fatalf("--uninstall: %s", r)
	}
	h.sameAs(pristine, "--uninstall on a host with session kill")
	if got := logind(); got != "b false\nas 0\n" {
		t.Fatalf("logind after --uninstall: %q", got)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestMeasureM14: sshd_config's first effective line is the Include of
// the drop-in directory (docs/07 M14).
func TestMeasureM14(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		first := strings.TrimSpace(h.must(`awk '{ sub(/#.*/, "") } NF { print; exit }' /etc/ssh/sshd_config`))
		ver := strings.TrimSpace(h.must("sshd -V 2>&1 | head -n 1"))
		dropins := strings.TrimSpace(h.must("ls /etc/ssh/sshd_config.d/"))
		t.Logf("M14 %s (%s): first effective line %q; drop-ins: %q", d.base, ver, first, dropins)
		if first != "Include /etc/ssh/sshd_config.d/*.conf" {
			t.Fatalf("M14 doesn't hold on %s: %q", d.base, first)
		}
	})
}

// TestMeasureM15: with `Defaults requiretty`, sudo refuses a command
// without a TTY unless `!requiretty` applies to the user, and D7's
// sudoers file makes it apply (docs/07 M15).
func TestMeasureM15(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		def, _, _ := h.exec("grep -rn requiretty /etc/sudoers /etc/sudoers.d", "")
		t.Logf("M15 %s: requiretty in the default sudoers: %q", d.base, strings.TrimSpace(def))
		h.must("printf 'Defaults requiretty\\n' > /etc/sudoers.d/00-requiretty && chmod 0440 /etc/sudoers.d/00-requiretty")
		h.mustSetup(h.values("owner"))
		out, code := h.certLogin("owner", "db-1", "sudo -n id -u")
		t.Logf("M15 %s: with requiretty and D7's file: exit %d %q", d.base, code, out)
		if code != 0 || out != "0\n" {
			t.Fatal("D7's !requiretty doesn't let sudo run without a TTY")
		}
		h.must("sed -i '/requiretty/d' /etc/sudoers.d/50-nyyrikki-ny-owner")
		out, code = h.certLogin("owner", "db-1", "sudo -n id -u")
		t.Logf("M15 %s: with requiretty, without !requiretty: exit %d %q", d.base, code, out)
		if code == 0 {
			t.Fatal("sudo ran without a TTY despite requiretty")
		}
		h.must("rm /etc/sudoers.d/00-requiretty")
	})
}
