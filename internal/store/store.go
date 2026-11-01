// Package store opens Nyyrikki's SQLite database and holds its schema
// (docs/01 D11, docs/02 D15). Every state change elsewhere is a
// compare-and-set that acts only when exactly one row changed.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // the pure-Go driver (docs/01 D11)
)

// Open opens (creating if needed) the database at path, in WAL mode, and
// applies the schema.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(FULL)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		db.Close()
		return nil, fmt.Errorf("store: WAL mode not active (%q): %v", mode, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}
	if err := migrateApprovals(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrating approvals: %w", err)
	}
	if _, err := db.ExecContext(ctx, indexes); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: indexes: %w", err)
	}
	return db, nil
}

// approvalsColumns is the approvals table. An approval is a one-off
// run, an elevation, or a host enrollment (docs/08 D7). An enrollment
// asks every human of its target, one row each, sharing group_id: the
// first valid tap settles every row of the group at once (docs/08 §5.2).
// group_id is NULL for runs and elevations.
const approvalsColumns = `
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('run', 'elevation', 'enroll')),
  state TEXT NOT NULL,
  human TEXT NOT NULL,
  agent_key TEXT NOT NULL,
  approver_id INTEGER NOT NULL,
  targets TEXT NOT NULL,
  digest BLOB,
  duration_ms INTEGER,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL,
  settled_ms INTEGER,
  group_id TEXT
`

// oldApprovalsColumns are the columns of the table before enrollment
// (docs/08 SE5), copied by migrateApprovals.
const oldApprovalsColumns = `id, kind, state, human, agent_key, approver_id, targets, digest, duration_ms, created_ms, expires_ms, settled_ms`

const indexes = `
CREATE INDEX IF NOT EXISTS approvals_group ON approvals(group_id) WHERE group_id IS NOT NULL;
`

// migrateApprovals rebuilds an approvals table made before enrollment
// existed, whose CHECK allows only run and elevation, as SQLite's
// documented twelve steps do: SQLite can't change a CHECK in place.
// Foreign keys are off on that one connection while the table is
// replaced (elevations and approval_host_facts refer to it), and checked
// before the commit; any failure rolls back and leaves the old table.
func migrateApprovals(ctx context.Context, db *sql.DB) error {
	var def string
	if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'approvals'").Scan(&def); err != nil {
		return err
	}
	if strings.Contains(def, "'enroll'") {
		return nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return err
	}
	// The connection goes back to the pool afterwards: foreign keys on
	// again whatever happened.
	defer conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA foreign_keys = ON")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, stmt := range []string{
		"CREATE TABLE approvals_new (" + approvalsColumns + ")",
		"INSERT INTO approvals_new (" + oldApprovalsColumns + ") SELECT " + oldApprovalsColumns + " FROM approvals",
		"DROP TABLE approvals",
		"ALTER TABLE approvals_new RENAME TO approvals",
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	broken := rows.Next()
	rows.Close()
	if broken {
		return errors.New("foreign keys broken by the rebuild")
	}
	return tx.Commit()
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (` + approvalsColumns + `);

CREATE TABLE IF NOT EXISTS elevations (
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

-- What an elevation's approver was shown about its SSH hosts (docs/08
-- D10): a JSON object, target name to session_kill shown.
CREATE TABLE IF NOT EXISTS approval_host_facts (
  approval_id TEXT PRIMARY KEY REFERENCES approvals(id),
  facts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  time_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  record TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
`

// Secret returns the 32-byte secret stored under key in meta, generating
// and storing it on first use.
func Secret(ctx context.Context, db *sql.DB, key string) ([]byte, error) {
	var v []byte
	err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	if err == nil {
		if len(v) != 32 {
			return nil, fmt.Errorf("store: meta %s has length %d", key, len(v))
		}
		return v, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	v = make([]byte, 32)
	if _, err := rand.Read(v); err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", key, v); err != nil {
		return nil, err
	}
	// Read back: a concurrent first start may have won the insert.
	if err := db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", key).Scan(&v); err != nil {
		return nil, err
	}
	return v, nil
}
