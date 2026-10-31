package decision_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/store"
)

// withGroups adds the SSH targets of withSSH and the groups given.
func withGroups(e *env, groups ...config.Group) *env {
	withSSH(e)
	e.cfg.Groups = append(e.cfg.Groups, groups...)
	return e
}

// auditRecords returns the audit records of kind, decoded.
func auditRecords(t *testing.T, e *env, kind string) []map[string]any {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(e.dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("SELECT record FROM audit WHERE kind = ? ORDER BY time_ms, id", kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func (e *env) elevateErr(targets ...string) error {
	e.t.Helper()
	_, err := e.p.Elevate(context.Background(), decision.ElevateRequest{Principal: principal("agent-a"), Targets: targets, Reason: "r"})
	return err
}

// TestElevateGroupExpands covers docs/08 D11 (G10): a group name in
// elevate is expanded on the server into its members; the elevation, the
// prompt and the audit carry exactly that list, sorted and without
// duplicates; the prompt says which group each came from, and the audit
// which groups were asked for. The handle covers each member, and no
// target outside the list.
func TestElevateGroupExpands(t *testing.T) {
	e := withGroups(newEnv(t), config.Group{Name: "hosts", Targets: []string{"web-1", "db-1"}})
	el := e.elevate("agent-a", []string{"hosts", "prod", "db-1", "hosts"}, 5*time.Minute)
	want := []string{"db-1", "prod", "web-1"}
	if !slices.Equal(el.Targets, want) {
		t.Fatalf("elevation targets %v, want %v", el.Targets, want)
	}
	pr := e.asker.lastElev
	if !slices.Equal(pr.Targets, want) || len(pr.Groups) != 1 || pr.Groups[0].Name != "hosts" || !slices.Equal(pr.Groups[0].Targets, []string{"db-1", "web-1"}) {
		t.Fatalf("prompt targets %v groups %+v", pr.Targets, pr.Groups)
	}
	if len(pr.SSH) != 2 {
		t.Fatalf("prompt SSH %+v", pr.SSH)
	}
	allow := auditRecords(t, e, codes.KindDecision)
	last := allow[len(allow)-1]
	if last["decision"] != codes.Allow || !slices.Equal(strs(last["targets"]), want) || !slices.Equal(strs(last["target_groups"]), []string{"hosts"}) {
		t.Fatalf("audit %v", last)
	}
	asked := auditRecords(t, e, codes.KindElevationRequested)
	if got := strs(asked[0]["targets"]); !slices.Equal(got, []string{"hosts", "prod", "db-1", "hosts"}) {
		t.Fatalf("elevation_requested targets %v: want what was asked", got)
	}

	for _, name := range want {
		r := runReq(t, "agent-a", name, "get", "pods")
		if name != "prod" {
			r = sshReq(t, name, false, "id")
		}
		r.Handle = el.Handle
		g, err := e.p.DecideRun(context.Background(), r)
		if err != nil || g.CoveredBy() != codes.CoveredElevation {
			t.Fatalf("%s: %v", name, err)
		}
		g.Release()
	}
	e.noPrompt()
	r := runReq(t, "agent-a", "lab", "get", "pods")
	r.Handle = el.Handle
	ctx, cancel := context.WithCancel(context.Background())
	ch := e.runAsync(ctx, r)
	e.prompt() // not covered: asks one-off
	cancel()
	get(t, ch)
}

// TestElevateGroupNotWidened covers docs/08 D11 and INV-03 (G10): the
// elevation covers the members the group had when it was approved. A
// later change to the group, live or after a restart with a new config,
// doesn't add a target to it.
func TestElevateGroupNotWidened(t *testing.T) {
	dir := t.TempDir()
	e := withGroups(newEnvAt(t, dir), config.Group{Name: "hosts", Targets: []string{"web-1"}})
	el := e.elevate("agent-a", []string{"hosts"}, 10*time.Minute)
	if !slices.Equal(el.Targets, []string{"web-1"}) {
		t.Fatalf("targets %v", el.Targets)
	}
	notCovered := func(e *env) {
		t.Helper()
		r := sshReq(t, "db-1", false, "id")
		r.Handle = el.Handle
		ctx, cancel := context.WithCancel(context.Background())
		ch := e.runAsync(ctx, r)
		e.prompt() // the one-off path: the elevation doesn't cover db-1
		cancel()
		if res := get(t, ch); res.err == nil {
			t.Fatal("db-1 ran under the elevation")
		}
	}
	// The group gains db-1 in the running process's config.
	e.cfg.Groups[0].Targets = append(e.cfg.Groups[0].Targets, "db-1")
	notCovered(e)

	// A restart with a config in which the group holds db-1.
	e2 := withGroups(newEnvAt(t, dir), config.Group{Name: "hosts", Targets: []string{"db-1", "web-1"}})
	notCovered(e2)
	r := sshReq(t, "web-1", false, "id")
	r.Handle = el.Handle
	if g, err := e2.p.DecideRun(context.Background(), r); err != nil || g.CoveredBy() != codes.CoveredElevation {
		t.Fatalf("web-1 after restart: %v", err)
	} else {
		g.Release()
	}
}

// TestElevateGroupMaxTargets covers docs/08 D11 (G10): MaxTargets counts
// the expanded list, after duplicates are removed, and too many is
// invalid_request with nothing asked.
func TestElevateGroupMaxTargets(t *testing.T) {
	e := newEnv(t)
	var many []string
	for i := range decision.MaxTargets + 1 {
		name := fmt.Sprintf("k%02d", i)
		many = append(many, name)
		e.cfg.Targets = append(e.cfg.Targets, config.Target{Name: name, Humans: []string{"owner"}, Kubernetes: config.KubeTarget{InCluster: true}})
	}
	e.cfg.Groups = []config.Group{
		{Name: "all", Targets: many},
		{Name: "first", Targets: many[:6]},
		{Name: "last", Targets: many[5:]},
		{Name: "nine", Targets: many[:9]},
	}
	for name, asked := range map[string][]string{
		"one group too big":    {"all"},
		"two groups too many":  {"first", "last"},
		"group and one target": {"nine", "prod", "lab"},
	} {
		if err := e.elevateErr(asked...); codes.Of(err) != codes.InvalidRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	e.noPrompt()
	// Members named twice, or also by name, count once: 9 + prod = 10.
	el := e.elevate("agent-a", []string{"nine", "k00", "prod", "nine"}, time.Minute)
	if len(el.Targets) != decision.MaxTargets {
		t.Fatalf("targets %v", el.Targets)
	}
}

// TestElevateGroupInvisibleMember covers docs/08 D11 (G10): every target
// an elevation covers must be visible to the agent. A group with a
// member it may not see is invalid_request, with nothing asked; a group
// none of whose members it may see answers as a name that doesn't exist
// (docs/02 D5).
func TestElevateGroupInvisibleMember(t *testing.T) {
	e := withGroups(newEnv(t),
		config.Group{Name: "mixed", Targets: []string{"prod", "claude-only"}},
		config.Group{Name: "hidden", Targets: []string{"claude-only"}})
	err := e.elevateErr("mixed")
	if codes.Of(err) != codes.InvalidRequest {
		t.Fatalf("a group with a hidden member: %v", err)
	}
	hidden, unknown := e.elevateErr("hidden"), e.elevateErr("no-such-group")
	if codes.Of(hidden) != codes.TargetNotAllowed || hidden.Error() != unknown.Error() {
		t.Fatalf("a group of hidden targets %v; an unknown name %v", hidden, unknown)
	}
	e.noPrompt()
	// Each refusal is audited as a deny.
	n := 0
	for _, r := range auditRecords(t, e, codes.KindDecision) {
		if r["decision"] == codes.Deny {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%d denies audited, want 3", n)
	}
	// The same group is fine for the client that may see all of it.
	pr := principal("agent-a")
	pr2 := *pr
	pr2.ClientID = "claude-code"
	ch := make(chan error, 1)
	go func() {
		_, err := e.p.Elevate(context.Background(), decision.ElevateRequest{Principal: &pr2, Targets: []string{"mixed"}, Reason: "r"})
		ch <- err
	}()
	id := e.prompt()
	if got := e.asker.lastElev.Targets; !slices.Equal(got, []string{"claude-only", "prod"}) {
		t.Fatalf("targets %v", got)
	}
	e.p.Resolve(context.Background(), id, approval.ActionDeny, approverID)
	<-ch
}

// TestElevateGroupInRunRefused covers docs/08 D11 (G10): run takes
// target names only. A group name is refused exactly as a name that
// doesn't exist, and nothing is asked.
func TestElevateGroupInRunRefused(t *testing.T) {
	e := withGroups(newEnv(t), config.Group{Name: "hosts", Targets: []string{"web-1", "prod"}})
	_, grp := e.p.DecideRun(context.Background(), runReq(t, "agent-a", "hosts", "get", "pods"))
	_, unk := e.p.DecideRun(context.Background(), runReq(t, "agent-a", "no-such", "get", "pods"))
	if codes.Of(grp) != codes.TargetNotAllowed || grp.Error() != unk.Error() {
		t.Fatalf("group in run %v; unknown %v", grp, unk)
	}
	e.noPrompt()
}
