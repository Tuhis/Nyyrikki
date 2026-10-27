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
	return db, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
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
