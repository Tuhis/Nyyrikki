package decision

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/store"
)

type nopAsker struct{}

func (nopAsker) AskRun(context.Context, approval.RunPrompt) error             { return nil }
func (nopAsker) AskElevation(context.Context, approval.ElevationPrompt) error { return nil }
func (nopAsker) Settle(context.Context, string, approval.Outcome) error       { return nil }
func (nopAsker) Healthy() bool                                                { return true }

// TestDeliverElevationCallerGone covers the race found in review: the
// approval wins while the waiting call is being cancelled. Whatever the
// cancelled context does to later queries, the elevation must end and
// the handle must not linger (docs/01 D24, CODE-REVIEW.md: error paths
// release what they acquired).
func TestDeliverElevationCallerGone(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, _ := audit.NewWriter(ctx, db, io.Discard, time.Now)
	p, err := New(ctx, Config{Config: config.Defaults(), DB: db, Audit: w, Asker: nopAsker{}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	id := "apr_test"
	if _, err := db.Exec(`INSERT INTO approvals (id, kind, state, human, agent_key, approver_id, targets, duration_ms, created_ms, expires_ms)
		VALUES (?, 'elevation', 'pending', 'owner', 'k', 1, '["prod"]', 600000, ?, ?)`, id, time.Now().UnixMilli(), time.Now().Add(time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if ok, err := p.approveElevation(id); !ok || err != nil {
		t.Fatalf("approve: %v %v", ok, err)
	}
	gone, cancel := context.WithCancel(ctx)
	cancel()
	el, err := p.deliverElevation(gone, id, audit.Record{}, []string{"prod"})
	if el != nil || codes.Of(err) != codes.Withdrawn {
		t.Fatalf("delivered to a gone caller: %v %v", el, err)
	}
	var state string
	if err := db.QueryRow("SELECT state FROM elevations WHERE approval_id = ?", id).Scan(&state); err != nil || state != stateEnded {
		t.Fatalf("elevation state %q: %v", state, err)
	}
	p.mu.Lock()
	n, live := len(p.handles), len(p.elevations)
	p.mu.Unlock()
	if n != 0 || live != 0 {
		t.Fatalf("leaked %d handles, %d live elevations", n, live)
	}
}

// TestApproveWithoutWaiterRefused: authority made for one call goes only to
// that call (docs/01 D24). An approval whose waiter is gone (a failed
// settle left it pending) must not be approvable: for an elevation it
// would create a live elevation nobody holds. Found in review of #10 (L9).
func TestApproveWithoutWaiterRefused(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w, _ := audit.NewWriter(ctx, db, io.Discard, time.Now)
	p, err := New(ctx, Config{Config: config.Defaults(), DB: db, Audit: w, Asker: nopAsker{}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, kind := range []string{"run", "elevation"} {
		id := "apr_orphan_" + kind
		if _, err := db.Exec(`INSERT INTO approvals (id, kind, state, human, agent_key, approver_id, targets, duration_ms, created_ms, expires_ms)
			VALUES (?, ?, 'pending', 'owner', 'k', 1, '["prod"]', 600000, ?, ?)`, id, kind, time.Now().UnixMilli(), time.Now().Add(time.Minute).UnixMilli()); err != nil {
			t.Fatal(err)
		}
		if ok, _ := p.Resolve(ctx, id, approval.ActionApprove, 1); ok {
			t.Errorf("%s: an approval with no waiting call was approved", kind)
		}
	}
	var n int
	db.QueryRow("SELECT COUNT(*) FROM elevations").Scan(&n)
	if n != 0 {
		t.Fatalf("%d elevations created without a waiter", n)
	}
}
