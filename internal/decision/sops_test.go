package decision_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
)

const (
	sopsKeyA = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod"
	sopsKeyB = "projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/staging"
)

func withSOPS(e *env) *env {
	e.cfg.Targets = append(e.cfg.Targets, config.Target{Name: "sops-prod", Humans: []string{"owner"},
		SOPS: &config.SOPSTarget{GCPKMS: config.SOPSGCPKMS{CredentialsFile: "/etc/nyyrikki/gcp/sops-prod.json", Keys: []string{sopsKeyA, sopsKeyB}}}})
	return e
}

// sopsRequest stands in for sopstarget.Request: what the decision point
// uses of one, without linking the SOPS library into this package's
// tests. The real request is exercised with the decision point in
// internal/server.
type sopsRequest struct{ file string }

func (r sopsRequest) Type() string      { return codes.TypeSOPS }
func (r sopsRequest) Interactive() bool { return false }
func (r sopsRequest) Digest(target, _ string) [32]byte {
	return sha256.Sum256([]byte("sops\x00" + target + "\x00" + r.file))
}
func (r sopsRequest) Audit() audit.Request   { return audit.Request{Argv: []string{"encrypt"}} }
func (r sopsRequest) DisplayCommand() string { return "sops encrypt --gcp-kms=" + sopsKeyA }
func (r sopsRequest) DisplayStdin() string {
	return "‹plaintext yaml, 18 bytes, sha256:000000000000›"
}
func (r sopsRequest) Prompt() *approval.SOPSRequest {
	return &approval.SOPSRequest{Asks: "Encrypt a new file: 1 value encrypted, 0 left in cleartext",
		FileName: r.file, KMSKeys: []string{sopsKeyA}}
}

func sopsReq(t *testing.T, target string) decision.RunRequest {
	t.Helper()
	return decision.RunRequest{Principal: principal("agent-a"), RunID: decision.NewRunID(), Target: target,
		Request: sopsRequest{file: "clusters/prod/new.enc.yaml"}, Reason: "because"}
}

// TestSOPSOneOff covers docs/10 D8 and OD3 at the decision point: the
// prompt carries what the request says of itself, "Runs as" is
// Nyyrikki's own credential, never the human's Kubernetes identity, and
// the Grant binds to the request's digest.
func TestSOPSOneOff(t *testing.T) {
	e := withSOPS(newEnv(t))
	r := sopsReq(t, "sops-prod")
	ch := e.runAsync(context.Background(), r)
	id := e.prompt()
	p := e.asker.lastRun
	const runAs = "Nyyrikki's Google credential, for owner"
	if p.Type != codes.TypeSOPS || p.SSH != nil || p.RunAs.User != runAs || len(p.RunAs.Groups) != 0 || p.Interactive {
		t.Fatalf("prompt %+v", p)
	}
	if p.SOPS == nil || p.SOPS.Asks != "Encrypt a new file: 1 value encrypted, 0 left in cleartext" || p.SOPS.FileName != "clusters/prod/new.enc.yaml" ||
		p.SOPS.ShowSays || len(p.SOPS.KMSKeys) != 1 || p.SOPS.KMSKeys[0] != sopsKeyA {
		t.Fatalf("prompt's SOPS part %+v", p.SOPS)
	}
	if p.Argv != r.Request.DisplayCommand() || p.Stdin != r.Request.DisplayStdin() {
		t.Fatalf("prompt's command %q, file %q", p.Argv, p.Stdin)
	}
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionApprove, approverID); !ok {
		t.Fatal("approve")
	}
	res := get(t, ch)
	if res.err != nil {
		t.Fatal(res.err)
	}
	defer res.g.Release()
	if res.g.RunAs().User != runAs || res.g.Digest() != r.Request.Digest("sops-prod", "") || res.g.Interactive() || res.g.CoveredBy() != codes.CoveredOneOff {
		t.Fatalf("grant %+v", res.g.RunAs())
	}
}

// A request of another type never runs on a SOPS target, nor a SOPS
// request elsewhere (docs/07 D13, docs/10 D1).
func TestSOPSTypeMismatch(t *testing.T) {
	e := withSOPS(withSSH(newEnv(t)))
	for name, r := range map[string]decision.RunRequest{
		"kubectl on sops": runReq(t, "agent-a", "sops-prod", "get", "secrets"),
		"ssh on sops":     func() decision.RunRequest { r := sshReq(t, "sops-prod", false, "id"); return r }(),
		"sops on kubectl": sopsReq(t, "prod"),
		"sops on ssh":     sopsReq(t, "db-1"),
	} {
		if _, err := e.p.DecideRun(context.Background(), r); codes.Of(err) != codes.Internal || codes.DetailOf(err) != "target_type_mismatch" {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.noPrompt()
}

// mute is a request that claims to be for a SOPS target but can't say
// what the approver should be shown.
type mute struct{}

func (mute) Type() string                   { return codes.TypeSOPS }
func (mute) Interactive() bool              { return false }
func (mute) Digest(string, string) [32]byte { return [32]byte{1} }
func (mute) Audit() audit.Request           { return audit.Request{Argv: []string{"decrypt"}} }
func (mute) DisplayCommand() string         { return "sops decrypt" }
func (mute) DisplayStdin() string           { return "" }

// A request on a SOPS target that can't be shown is denied, and nobody
// is asked (docs/10 D8: the approver sees what is asked).
func TestSOPSRequestThatCantBeShown(t *testing.T) {
	e := withSOPS(newEnv(t))
	_, err := e.p.DecideRun(context.Background(), decision.RunRequest{
		Principal: principal("agent-a"), RunID: decision.NewRunID(), Target: "sops-prod", Request: mute{}, Reason: "because"})
	if codes.Of(err) != codes.Internal || codes.DetailOf(err) != "sops_prompt_missing" {
		t.Fatalf("a request that can't be shown: %v", err)
	}
	e.noPrompt()
}

// TestElevationSOPS covers docs/10 D8 for elevations: the prompt names
// each SOPS target's keys, and the elevation then covers a request on
// it without a prompt, with the same "Runs as".
func TestElevationSOPS(t *testing.T) {
	e := withSOPS(newEnv(t))
	el := e.elevate("agent-a", []string{"prod", "sops-prod"}, 5*time.Minute)
	pr := e.asker.lastElev
	if len(pr.SOPS) != 1 || pr.SOPS[0].Target != "sops-prod" || len(pr.SOPS[0].Keys) != 2 || pr.SOPS[0].Keys[0] != sopsKeyA || pr.SOPS[0].Keys[1] != sopsKeyB {
		t.Fatalf("elevation prompt's SOPS part %+v", pr.SOPS)
	}
	if len(pr.SSH) != 0 || pr.RunAs.User != "owner@example.com" {
		t.Fatalf("elevation prompt %+v", pr)
	}
	r := sopsReq(t, "sops-prod")
	r.Handle = el.Handle
	g, err := e.p.DecideRun(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Release()
	if g.CoveredBy() != codes.CoveredElevation || g.RunAs().User != "Nyyrikki's Google credential, for owner" || g.NotAfter().IsZero() || g.ElevationID() == "" {
		t.Fatalf("grant %s %s", g.CoveredBy(), g.RunAs().User)
	}
	e.noPrompt()

	// An elevation that doesn't name the SOPS target doesn't cover it.
	el2 := e.elevate("agent-a", []string{"prod"}, 5*time.Minute)
	r2 := sopsReq(t, "sops-prod")
	r2.Handle = el2.Handle
	ch := e.runAsync(context.Background(), r2)
	id := e.prompt()
	if ok, _ := e.p.Resolve(context.Background(), id, approval.ActionDeny, approverID); !ok {
		t.Fatal("deny")
	}
	if res := get(t, ch); codes.Of(res.err) != codes.Denied {
		t.Fatalf("a request outside its elevation: %v", res.err)
	}
}
