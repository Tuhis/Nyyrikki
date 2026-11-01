package store

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// oldSchema is the approvals table and its dependants as they were
// before enrollment (docs/08 SE5).
const oldSchema = `
CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('run', 'elevation')),
  state TEXT NOT NULL,
  human TEXT NOT NULL,
  agent_key TEXT NOT NULL,
  approver_id INTEGER NOT NULL,
  targets TEXT NOT NULL,
  digest BLOB,
  duration_ms INTEGER,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  settled_ms INTEGER
);
CREATE TABLE elevations (
  id TEXT PRIMARY KEY,
  approval_id TEXT NOT NULL UNIQUE REFERENCES approvals(id),
  handle_hash BLOB NOT NULL UNIQUE,
  state TEXT NOT NULL,
  human TEXT NOT NULL,
  agent_key TEXT NOT NULL,
  client_id TEXT NOT NULL,
  approver_id INTEGER NOT NULL,
  targets TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  ended_ms INTEGER
);
CREATE TABLE approval_host_facts (
  approval_id TEXT PRIMARY KEY REFERENCES approvals(id),
  facts TEXT NOT NULL
);
INSERT INTO approvals VALUES ('apr_1', 'elevation', 'approved', 'owner', 'k', 7, '["db-1"]', NULL, 60000, 1, 2, 3);
INSERT INTO approvals VALUES ('apr_2', 'run', 'denied', 'owner', 'k', 7, '["prod"]', x'0102', NULL, 1, 2, 3);
INSERT INTO elevations VALUES ('elv_1', 'apr_1', x'aa', 'live', 'owner', 'k', 'c', 7, '["db-1"]', 1, 2, NULL);
INSERT INTO approval_host_facts VALUES ('apr_1', '{"db-1":true}');
`

// TestStoreMigratesApprovals: a database made before enrollment gets the
// enroll kind and group_id, keeps every row, and still enforces its
// foreign keys.
func TestStoreMigratesApprovals(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "n.db")
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	old, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.ExecContext(ctx, oldSchema); err != nil {
		t.Fatal(err)
	}
	old.Close()

	for range 2 { // the second open finds nothing to migrate
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM approvals WHERE id IN ('apr_1', 'apr_2')").Scan(&n); err != nil || n != 2 {
			t.Fatalf("approvals kept: %d %v", n, err)
		}
		var digest []byte
		var targets string
		if err := db.QueryRowContext(ctx, "SELECT digest, targets FROM approvals WHERE id = 'apr_2'").Scan(&digest, &targets); err != nil || string(digest) != "\x01\x02" || targets != `["prod"]` {
			t.Fatalf("row changed: %q %q %v", digest, targets, err)
		}
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO approvals (id, kind, state, human, agent_key, approver_id, targets, created_ms, expires_ms, group_id)
			VALUES ('apr_3', 'enroll', 'pending', 'owner', '', 7, '["db-1"]', 1, 2, 'apr_3')`); err != nil {
			t.Fatalf("an enroll approval: %v", err)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO approvals (id, kind, state, human, agent_key, approver_id, targets, created_ms, expires_ms)
			VALUES ('apr_4', 'other', 'pending', 'owner', '', 7, '[]', 1, 2)`); err == nil || !strings.Contains(err.Error(), "CHECK") {
			t.Fatalf("an unknown kind was accepted: %v", err)
		}
		// The foreign keys still point at approvals, and are enforced.
		if _, err := db.ExecContext(ctx, `INSERT INTO approval_host_facts VALUES ('apr_missing', '{}')`); err == nil {
			t.Fatal("a foreign key is no longer enforced")
		}
		var facts string
		if err := db.QueryRowContext(ctx, "SELECT f.facts FROM approval_host_facts f JOIN elevations e ON e.approval_id = f.approval_id JOIN approvals a ON a.id = e.approval_id").Scan(&facts); err != nil || facts != `{"db-1":true}` {
			t.Fatalf("dependants: %q %v", facts, err)
		}
		db.Close()
	}
}

// A transaction that reads, then writes, must not fail because another
// connection wrote in between: in WAL mode a deferred transaction can't
// upgrade its read snapshot to a write once someone else has committed
// (SQLITE_BUSY_SNAPSHOT, "database is locked (517)"), and busy_timeout
// doesn't help. Seen as a lost settle under load on #50, so transactions
// begin immediate: the second writer waits instead.
func TestStoreReadThenWriteUnderContention(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "INSERT INTO meta (key, value) VALUES ('a', x'00'), ('b', x'00')"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var v []byte
	if err := tx.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = 'a'").Scan(&v); err != nil {
		t.Fatal(err)
	}
	other := make(chan error, 1)
	go func() {
		_, err := db.ExecContext(ctx, "UPDATE meta SET value = x'01' WHERE key = 'b'")
		other <- err
	}()
	time.Sleep(200 * time.Millisecond) // let the other writer commit, if it can
	if _, err := tx.ExecContext(ctx, "UPDATE meta SET value = x'02' WHERE key = 'a'"); err != nil {
		t.Fatalf("write after read, with another writer: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-other; err != nil {
		t.Fatalf("the other writer: %v", err)
	}
}
