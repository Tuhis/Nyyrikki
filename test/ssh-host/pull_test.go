//go:build sshhost

package sshhost_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/hostsetup"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
)

// restartSSHDLogged restarts sshd logging to /root/sshd.log, where a
// reload shows as "Received SIGHUP".
func (h *host) restartSSHDLogged() {
	h.t.Helper()
	h.must(`pid=$(cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid) && kill $pid
i=0; while kill -0 $pid 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
/usr/sbin/sshd -E /root/sshd.log`)
}

func (h *host) sshdReloads() int {
	h.t.Helper()
	o, _, _ := h.exec("cat /root/sshd.log", "")
	return strings.Count(o, "Received SIGHUP")
}

// refused asserts that the pull refuses what is served, changes nothing,
// and says why.
func (h *host) refused(what string, served []byte, want string) {
	h.t.Helper()
	before := h.snapshot()
	h.answer("trust", 0, served)
	r := h.pull()
	if r.code == 0 {
		h.t.Fatalf("%s: applied: %s", what, r)
	}
	if !strings.Contains(r.err, want) {
		h.t.Errorf("%s: the refusal doesn't say %q: %s", what, want, r)
	}
	h.sameAs(before, what)
}

// TestPull covers docs/08 G4: the pull applies revocations, removes the
// principals and sudoers files of humans no longer on the target, removes
// sudoers with SUDO=false, and replaces the CA set, without reloading
// sshd: a certificate of a newly revoked CA is refused and one of a newly
// added CA logs in, on the next login. It refuses, changing nothing, each
// bad bundle G4 lists. It never creates an account, writes a new
// principals file or grants sudo, and logs what it would need a re-run
// for.
func TestPull(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.startFake()
		h.recordLogger()
		h.restartSSHDLogged()
		a, b, c, other := h.newCAKey("a"), h.newCAKey("b"), h.newCAKey("c"), h.newCAKey("other")
		v := h.values("owner", "second")
		v.caKeys, v.signers = []string{a.line, b.line}, []string{a.line}
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		for _, k := range []caKey{a, b} {
			if out, code := h.loginWith(k, "owner", "id -un"); code != 0 {
				t.Fatalf("before the pull: exit %d %q", code, out)
			}
		}
		principals := h.must("cat /etc/ssh/nyyrikki/principals/ny-owner")
		reloads := h.sshdReloads()
		pid := h.must("cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid")

		base := bundle{target: "db-1", ca: []string{a.line, c.line}, signers: []string{a.line}, revoked: []string{b.line},
			humans: []string{"owner", "third"}, sudo: true, signer: a.signer}
		next := func() bundle {
			nb := base
			nb.issued = millis(time.Now())
			time.Sleep(2 * time.Millisecond)
			return nb
		}
		first := next()
		firstBytes := first.bytes(t)
		if r := h.serveAndPull(firstBytes); r.code != 0 {
			t.Fatalf("pull: %s", r)
		}
		// Taken away, on the next login, without a reload (M4).
		if out, code := h.loginWith(b, "owner", "true"); code == 0 {
			t.Fatalf("a certificate of the revoked CA logged in: %q", out)
		}
		if out, code := h.loginWith(c, "owner", "id -un"); code != 0 || out != "ny-owner\n" {
			t.Fatalf("a certificate of the added CA: exit %d %q", code, out)
		}
		if q := h.must("ssh-keygen -Q -f /etc/ssh/nyyrikki/revoked.krl " + b.path + ".pub 2>&1 || true"); !strings.Contains(q, "REVOKED") {
			t.Fatalf("the revoked key isn't in the KRL: %q", q)
		}
		for _, p := range []string{"/etc/ssh/nyyrikki/principals/ny-second", "/etc/sudoers.d/50-nyyrikki-ny-second"} {
			if h.exists(p) {
				t.Fatalf("%s is left for a human no longer on the target", p)
			}
		}
		if out, code := h.loginWith(a, "second", "true"); code == 0 {
			t.Fatalf("the removed human logs in: %q", out)
		}
		// Never adds access: no account, principals file or sudo for third.
		if h.accountExists("ny-third") || h.exists("/etc/ssh/nyyrikki/principals/ny-third") || h.exists("/etc/sudoers.d/50-nyyrikki-ny-third") {
			t.Fatal("the pull added access for a new human")
		}
		if !strings.Contains(h.logged(), "re-run the setup to add ny-third") {
			t.Errorf("no re-run notice for the new human: %q", h.logged())
		}
		if !h.accountExists("ny-second") {
			t.Error("the pull deleted an account; only the setup does")
		}
		if got := h.mark(); got != strconv.FormatInt(first.issued, 10) {
			t.Fatalf("pull.state ISSUED %q, want %d", got, first.issued)
		}
		if !strings.Contains(h.must("cat /etc/ssh/nyyrikki/pull.state"), "BY=pull") {
			t.Fatal("pull.state doesn't say the pull applied it")
		}

		// G4's refusals, each changing nothing.
		h.refused("a replayed bundle", firstBytes, "not after the last one applied")
		bad := next().bytes(t)
		i := strings.Index(string(bad), "SUDO=true")
		bad[i+5] = 'T'
		h.refused("a bad signature", bad, "doesn't verify")
		byC := next()
		byC.signer = c.signer
		h.refused("signed by a trusted key that isn't a signer", byC.bytes(t), "doesn't verify")
		byOther := next()
		byOther.signer = other.signer
		h.refused("signed by an untrusted key", byOther.bytes(t), "doesn't verify")
		otherTarget := next()
		otherTarget.target = "db-2"
		h.refused("another target's bundle", otherTarget.bytes(t), "for target db-2")
		ahead := next()
		ahead.issued = millis(time.Now().Add(11 * time.Minute))
		h.refused("a bundle more than 10 minutes ahead", ahead.bytes(t), "ahead of this host's clock")
		notSubset := next()
		notSubset.signers = []string{a.line, other.line}
		h.refused("signers that aren't CA keys", notSubset.bytes(t), "not among the CA_KEYs")
		malformed := next()
		malformed.extra = []string{"FOO=bar"}
		h.refused("an unknown line", malformed.bytes(t), "unknown")
		withShell := next()
		withShell.humans = []string{"owner", "x;touch${IFS}/root/pwned"}
		h.refused("shell syntax in a line", withShell.bytes(t), "HUMAN")
		whole := next().bytes(t)
		h.refused("a bundle cut off in its data lines", whole[:len(whole)/3], "cut off")
		h.refused("a bundle cut off in its signature", whole[:len(whole)-40], "doesn't verify")
		h.refused("a bundle without END", append([]byte(strings.Replace(string(next().data()), "\nEND=", "\nX_END=", 1)), []byte(hostsetup.SignatureLine+"\n")...), "")
		// A failed fetch.
		before := h.snapshot()
		h.answer("trust", http.StatusServiceUnavailable, []byte("unavailable: ca_key_unreadable\n"))
		if r := h.pull(); r.code == 0 || !strings.Contains(r.err, "fetching") {
			t.Fatalf("a failed fetch: %s", r)
		}
		h.must("rm -f /srv/ny/trust.answer /srv/ny/trust.status")
		if r := h.pull(); r.code == 0 {
			t.Fatalf("a 404: %s", r)
		}
		h.sameAs(before, "a failed fetch")
		if h.exists("/root/pwned") {
			t.Fatal("a bundle line ran")
		}

		// A signer the host revoked by hand can't sign any more.
		e := h.newCAKey("e")
		stage := next()
		stage.ca, stage.signers = []string{a.line, c.line, e.line}, []string{a.line, e.line}
		if r := h.serveAndPull(stage.bytes(t)); r.code != 0 {
			t.Fatalf("stage: %s", r)
		}
		h.must("ssh-keygen -q -k -u -f /etc/ssh/nyyrikki/revoked.krl " + e.path + ".pub")
		byE := next()
		byE.ca, byE.signers, byE.signer = stage.ca, stage.signers, e.signer
		h.refused("signed by a revoked signer", byE.bytes(t), "doesn't verify")
		unstage := next()
		if r := h.serveAndPull(unstage.bytes(t)); r.code != 0 {
			t.Fatalf("unstage: %s", r)
		}

		// SUDO=false takes sudo away; SUDO=true doesn't give it back.
		noSudo := next()
		noSudo.sudo = false
		if r := h.serveAndPull(noSudo.bytes(t)); r.code != 0 {
			t.Fatalf("SUDO=false: %s", r)
		}
		if h.exists("/etc/sudoers.d/50-nyyrikki-ny-owner") {
			t.Fatal("SUDO=false left the sudoers file")
		}
		if out, code := h.loginWith(a, "owner", "sudo -n id -u"); code == 0 {
			t.Fatalf("sudo after SUDO=false: %q", out)
		}
		if r := h.serveAndPull(next().bytes(t)); r.code != 0 {
			t.Fatalf("SUDO=true again: %s", r)
		}
		if h.exists("/etc/sudoers.d/50-nyyrikki-ny-owner") {
			t.Fatal("the pull granted sudo")
		}
		if !strings.Contains(h.logged(), "re-run the setup to add sudo for ny-owner") {
			t.Errorf("no re-run notice for sudo: %q", h.logged())
		}

		// from= is never changed, and sshd was never reloaded.
		if got := h.must("cat /etc/ssh/nyyrikki/principals/ny-owner"); got != principals {
			t.Fatalf("the principals file changed: %q", got)
		}
		if n := h.sshdReloads(); n != reloads {
			t.Fatalf("sshd was reloaded %d times by the pull", n-reloads)
		}
		if got := h.must("cat /run/sshd.pid 2>/dev/null || cat /var/run/sshd.pid"); got != pid {
			t.Fatalf("sshd restarted: %q → %q", pid, got)
		}
	})
}

// TestPullSigners covers docs/08 G13's signer relations: a planned stage,
// promote and unstage are applied; a host offered {B,C} while holding
// {A,B} refuses, and so does any other change than a stage or a promote,
// and a promote signed by a key it drops; each change is logged. A pod
// whose user-ca-next is revoked serves, from the real handler, a bundle
// without it as a signer, which the host accepts and applies.
func TestPullSigners(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.startFake()
		h.recordLogger()
		a, n, q, r := h.newCAKey("a"), h.newCAKey("n"), h.newCAKey("q"), h.newCAKey("r")
		v := h.values("owner")
		v.caKeys, v.signers = []string{a.line}, []string{a.line}
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		signers := func() string {
			return strings.Join(strings.Fields(h.must("cut -d' ' -f2 /etc/ssh/nyyrikki/signers.pub")), " ")
		}
		b64 := func(ks ...caKey) string {
			var out []string
			for _, k := range ks {
				out = append(out, strings.Fields(k.line)[1])
			}
			return strings.Join(out, " ")
		}
		lines := func(ks ...caKey) []string {
			var out []string
			for _, k := range ks {
				out = append(out, k.line)
			}
			return out
		}
		pull := func(signer caKey, ca, sig []caKey) result {
			time.Sleep(2 * time.Millisecond)
			return h.serveAndPull(bundle{target: "db-1", ca: lines(ca...), signers: lines(sig...), humans: []string{"owner"},
				sudo: true, issued: millis(time.Now()), signer: signer.signer}.bytes(t))
		}
		apply := func(what string, signer caKey, ca, sig []caKey) {
			t.Helper()
			if res := pull(signer, ca, sig); res.code != 0 {
				t.Fatalf("%s: %s", what, res)
			}
			if got := signers(); got != b64(sig...) {
				t.Fatalf("%s: signers %s, want %s", what, got, b64(sig...))
			}
		}
		refuse := func(what string, signer caKey, ca, sig []caKey, want string) {
			t.Helper()
			before := h.snapshot()
			res := pull(signer, ca, sig)
			if res.code == 0 || !strings.Contains(res.err, want) {
				t.Fatalf("%s: %s", what, res)
			}
			h.sameAs(before, what)
		}
		ks := func(k ...caKey) []caKey { return k }

		apply("stage", a, ks(a, n), ks(a, n))
		if !strings.Contains(h.logged(), "bundle signers changed (stage") {
			t.Errorf("the stage isn't logged: %q", h.logged())
		}
		if out, code := h.loginWith(n, "owner", "true"); code != 0 {
			t.Fatalf("the staged key doesn't log in: %q", out)
		}
		apply("promote", n, ks(n), ks(n))
		if !strings.Contains(h.logged(), "bundle signers changed (promote") {
			t.Errorf("the promote isn't logged: %q", h.logged())
		}
		if out, code := h.loginWith(a, "owner", "true"); code == 0 {
			t.Fatalf("the promoted-away key still logs in: %q", out)
		}
		apply("stage again", n, ks(n, q), ks(n, q))
		apply("unstage", n, ks(n), ks(n))
		apply("stage once more", n, ks(n, q), ks(n, q))
		// A host that missed a promote and then a stage: {N,Q} offered {Q,R}.
		refuse("{N,Q} offered {Q,R}", q, ks(q, r), ks(q, r), "neither a stage nor a promote")
		if !strings.Contains(h.logged(), "neither a stage nor a promote") {
			t.Errorf("the refusal isn't logged: %q", h.logged())
		}
		refuse("{N,Q} offered {R}", n, ks(n, q, r), ks(r), "neither a stage nor a promote")
		refuse("a promote signed by the key it drops", n, ks(q), ks(q), "keeps")
		refuse("a replacement in one bundle", n, ks(n, r), ks(r), "neither a stage nor a promote")

		// The real handler, for a pod whose user-ca-next (Q) is revoked:
		// SIGNER_KEY is user-ca (N) only, Q is a REVOKED_CA_KEY, and the
		// host takes it as a promote and revokes Q.
		cfgBytes, err := os.ReadFile("../../internal/config/testdata/valid.yaml")
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Parse(cfgBytes)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "user-ca"), n.pem, 0o600)
		os.WriteFile(filepath.Join(dir, "user-ca-next"), q.pem, 0o600)
		keys := sshca.New(sshca.Options{Files: sshca.Files{UserCA: filepath.Join(dir, "user-ca"), NextUserCA: filepath.Join(dir, "user-ca-next")},
			Revoked: []ssh.PublicKey{q.signer.PublicKey()}})
		hs, err := hostsetup.New(cfg, []byte("#!/bin/sh\n"+hostsetup.MainLine+"\n"), keys, nopAudit{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		hs.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/hosts/db-1/trust", nil))
		if w.Code != 200 || strings.Contains(w.Body.String(), "SIGNER_KEY="+q.line) || !strings.Contains(w.Body.String(), "REVOKED_CA_KEY="+q.line) {
			t.Fatalf("the served bundle: %d\n%s", w.Code, w.Body)
		}
		if res := h.serveAndPull(w.Body.Bytes()); res.code != 0 {
			t.Fatalf("the real bundle without the revoked staged key: %s", res)
		}
		if got := signers(); got != b64(n) {
			t.Fatalf("signers %s after the revoked stage", got)
		}
		if out, code := h.loginWith(q, "owner", "true"); code == 0 {
			t.Fatalf("the revoked staged key logs in: %q", out)
		}
		if out, code := h.loginWith(n, "owner", "id -un"); code != 0 {
			t.Fatalf("user-ca doesn't log in after the pull: %q", out)
		}
	})
}

// TestSetupIssued covers docs/08 G13's marks: a re-run sets pull.state to
// the setup's ISSUED, and a bundle issued before it is refused; a setup
// whose ISSUED is more than 10 minutes ahead of the host's clock is
// refused, naming the clock; a setup older than the last bundle applied is
// refused and leaves the host unchanged, and with --reset-pull-state it
// succeeds and sets the mark to its ISSUED; a far-ahead mark is forgotten.
func TestSetupIssued(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		h.startFake()
		ca := h.defaultCA()
		v := h.values("owner")
		h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		if got := h.mark(); got != v.issued {
			t.Fatalf("pull.state ISSUED %q, want the setup's %s", got, v.issued)
		}
		issued, _ := strconv.ParseInt(v.issued, 10, 64)
		b := bundle{target: "db-1", ca: []string{ca.line}, signers: []string{ca.line}, humans: []string{"owner"}, sudo: true, signer: ca.signer}

		// A bundle issued before the setup is refused.
		older := b
		older.issued = issued - 1000
		h.refused("a bundle issued before the setup", older.bytes(t), "not after the last one applied")

		// A setup far ahead of the host's clock.
		ahead := v
		ahead.issued = strconv.FormatInt(millis(time.Now().Add(11*time.Minute)), 10)
		before := h.snapshot()
		if r := h.setup(ahead); r.code == 0 || !strings.Contains(r.err, "ahead of this host's clock") {
			t.Fatalf("a setup from the future: %s", r)
		}
		h.sameAs(before, "a setup from the future")

		// A bundle after the setup moves the mark; the old setup is then
		// stale.
		newer := b
		newer.issued = millis(time.Now())
		if r := h.serveAndPull(newer.bytes(t)); r.code != 0 {
			t.Fatalf("pull: %s", r)
		}
		before = h.snapshot()
		r := h.setup(v)
		if r.code == 0 || !strings.Contains(r.err, "this setup script is older than the last bundle applied; fetch it again") ||
			!strings.Contains(r.err, strconv.FormatInt(newer.issued, 10)) || !strings.Contains(r.err, "--reset-pull-state") {
			t.Fatalf("a stale setup: %s", r)
		}
		h.sameAs(before, "a stale setup")
		h.mustSetup(v, "--cacert", "/root/server-ca.pem", "--reset-pull-state")
		if got := h.mark(); got != v.issued {
			t.Fatalf("--reset-pull-state: mark %q, want %s", got, v.issued)
		}
		h.refused("a bundle issued before the reset setup", older.bytes(t), "not after the last one applied")

		// A fresh setup sets the mark to its own ISSUED.
		fresh := v
		fresh.issued = nowMillis()
		h.mustSetup(fresh, "--cacert", "/root/server-ca.pem")
		if got := h.mark(); got != fresh.issued {
			t.Fatalf("a fresh setup: mark %q, want %s", got, fresh.issued)
		}
		// A mark far ahead of the clock (a bundle from a pod whose clock
		// jumped) is forgotten by the next setup.
		far := strconv.FormatInt(millis(time.Now().Add(time.Hour)), 10)
		h.must("printf 'ISSUED=" + far + "\\nAPPLIED=1\\nBY=pull\\n' > /etc/ssh/nyyrikki/pull.state")
		h.mustSetup(fresh, "--cacert", "/root/server-ca.pem")
		if got := h.mark(); got != fresh.issued {
			t.Fatalf("a far-ahead mark: %q after the setup, want %s", got, fresh.issued)
		}
		// A malformed pull.state needs --reset-pull-state.
		h.must("echo garbage > /etc/ssh/nyyrikki/pull.state")
		before = h.snapshot()
		if r := h.setup(fresh); r.code == 0 || !strings.Contains(r.err, "--reset-pull-state") {
			t.Fatalf("a malformed pull.state: %s", r)
		}
		h.sameAs(before, "a malformed pull.state")
		h.mustSetup(fresh, "--cacert", "/root/server-ca.pem", "--reset-pull-state")
		// --dry-run shows the refusal too, and changes nothing.
		before = h.snapshot()
		if r := h.setup(v, "--dry-run"); r.code == 0 || !strings.Contains(r.err, "older than the last bundle applied") {
			t.Fatalf("--dry-run of a stale setup: %s", r)
		}
		h.sameAs(before, "--dry-run of a stale setup")
	})
}

// TestPullSchedule covers docs/08 G5: the setup installs
// /etc/cron.d/nyyrikki where a cron that isn't BusyBox's exists (Debian's
// cron, Rocky's cronie), /etc/periodic/15min/nyyrikki-pull on Alpine,
// and nothing, reporting pull: none, without cron or without curl. The
// installed schedule runs the pull. --status changes nothing.
// --uninstall removes every pull file.
func TestPullSchedule(t *testing.T) {
	forEachDistro(t, func(t *testing.T, d distro) {
		h := newHost(t, d)
		pristine := h.snapshot()
		h.startFake()
		ca := h.defaultCA()
		v := h.values("owner")
		if d.name == "alpine" {
			// BusyBox crond ignores /etc/cron.d even where it exists (M3).
			h.must("mkdir -p /etc/cron.d")
			pristine = h.snapshot()
		}
		r := h.mustSetup(v, "--cacert", "/root/server-ca.pem")
		want, file, mode := "pull: cron.d", "/etc/cron.d/nyyrikki", "644"
		if d.name == "alpine" {
			want, file, mode = "pull: periodic", "/etc/periodic/15min/nyyrikki-pull", "755"
		}
		if !strings.Contains(r.out, want) {
			t.Fatalf("output lacks %q:\n%s", want, r.out)
		}
		if got := h.must("stat -c '%a %u' " + file); got != mode+" 0\n" {
			t.Fatalf("%s: %s", file, got)
		}
		for _, other := range []string{"/etc/cron.d/nyyrikki", "/etc/periodic/15min/nyyrikki-pull"} {
			if other != file && h.exists(other) {
				t.Fatalf("%s written as well", other)
			}
		}
		// The schedule runs the pull: cron's command, or run-parts.
		h.answer("trust", 0, bundle{target: "db-1", ca: []string{ca.line}, signers: []string{ca.line}, humans: []string{"owner"},
			sudo: true, issued: millis(time.Now()), signer: ca.signer}.bytes(t))
		if d.name == "alpine" {
			h.must("run-parts /etc/periodic/15min")
		} else {
			line := strings.TrimSpace(h.must("grep -v '^#' /etc/cron.d/nyyrikki"))
			f := strings.Fields(line)
			if len(f) != 7 || f[0] != "13-59/15" || f[5] != "root" {
				t.Fatalf("cron line %q", line)
			}
			h.must(strings.Join(f[6:], " "))
		}
		if !strings.Contains(h.must("cat /etc/ssh/nyyrikki/pull.state"), "BY=pull") {
			t.Fatal("the schedule's command didn't apply a bundle")
		}

		// --status changes nothing and shows the schedule and the last pull.
		before := h.snapshot()
		st := h.setup(v, "--status")
		if st.code != 0 {
			t.Fatalf("--status: %s", st)
		}
		fp := strings.Fields(h.must("ssh-keygen -l -f /root/ca.pub"))[1]
		for _, w := range []string{want, "by the pull at", "bundle signers", fp, "host certificate: none"} {
			if !strings.Contains(st.out, w) {
				t.Errorf("--status lacks %q:\n%s", w, st.out)
			}
		}
		h.sameAs(before, "--status")
		if st := h.setup(v, "--status", "--dry-run"); st.code == 0 {
			t.Fatal("--status with another option was accepted")
		}

		// Without cron, or without curl: none, and the schedule goes.
		fresh := v
		fresh.issued = nowMillis()
		if d.name == "alpine" {
			h.must("cp /etc/crontabs/root /root/crontab && sed -i '/periodic\\/15min/d' /etc/crontabs/root")
		} else {
			h.must("for c in cron crond; do p=$(command -v $c) && mv $p $p.off; done; true")
		}
		r = h.mustSetup(fresh, "--cacert", "/root/server-ca.pem")
		if !strings.Contains(r.out, "pull: none") || h.exists(file) {
			t.Fatalf("without cron: %s", r)
		}
		if d.name == "alpine" {
			h.must("cp /root/crontab /etc/crontabs/root")
		} else {
			h.must("for c in /usr/sbin/cron.off /usr/sbin/crond.off; do [ -e $c ] && mv $c ${c%.off}; done; true")
		}
		h.must("p=$(command -v curl) && mv $p /root/curl.off && echo $p > /root/curl.path")
		r = h.mustSetup(fresh, "--cacert", "/root/server-ca.pem")
		if !strings.Contains(r.out, "pull: none") || !strings.Contains(r.out, "curl") || h.exists(file) {
			t.Fatalf("without curl: %s", r)
		}
		h.must("mv /root/curl.off $(cat /root/curl.path)")
		r = h.mustSetup(fresh, "--cacert", "/root/server-ca.pem")
		if !strings.Contains(r.out, want) {
			t.Fatalf("back: %s", r)
		}

		// --uninstall removes every pull file.
		if r := h.setup(fresh, "--uninstall"); r.code != 0 {
			t.Fatalf("--uninstall: %s", r)
		}
		h.must("rm -f /root/curl.path /root/crontab")
		h.sameAs(pristine, "setup with the pull, then --uninstall")
	})
}
