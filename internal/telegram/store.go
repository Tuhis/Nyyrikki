package telegram

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/approval"
)

// Prompt states. A prompt is "open" while its Approve and Deny buttons are
// live, "live" while an elevation shows End now, and "closed" once settled.
const (
	stateOpen   = "open"
	stateLive   = "live"
	stateClosed = "closed"

	kindRun       = "run"
	kindElevation = "elevation"
)

// The body is kept so that Settle can edit the prompt without re-rendering
// it, and cleared when the prompt closes. It is the text the approver was
// already shown: redacted argv and stdin (docs/04 D14), never a credential.
var schema = []string{
	`CREATE TABLE IF NOT EXISTS telegram_prompts (
		id          TEXT PRIMARY KEY,
		kind        TEXT NOT NULL CHECK (kind IN ('run', 'elevation')),
		approver_id INTEGER NOT NULL,
		chat_id     INTEGER NOT NULL,
		message_id  INTEGER NOT NULL,
		body        TEXT NOT NULL,
		state       TEXT NOT NULL CHECK (state IN ('open', 'live', 'closed')),
		created_at  INTEGER NOT NULL
	) STRICT`,
	`CREATE TABLE IF NOT EXISTS telegram_callback_keys (
		key       TEXT PRIMARY KEY,
		prompt_id TEXT NOT NULL REFERENCES telegram_prompts(id) ON DELETE CASCADE,
		action    INTEGER NOT NULL
	) STRICT`,
	`CREATE INDEX IF NOT EXISTS telegram_callback_keys_prompt ON telegram_callback_keys(prompt_id)`,
	`CREATE TABLE IF NOT EXISTS telegram_offset (
		id          INTEGER PRIMARY KEY CHECK (id = 1),
		next_offset INTEGER NOT NULL
	) STRICT`,
}

// Migrate creates the package's tables. It is idempotent.
func Migrate(ctx context.Context, db *sql.DB) error {
	for _, stmt := range schema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("telegram: migrate: %w", err)
		}
	}
	return nil
}

// callbackKeyLen is "v1:" plus 22 base64url characters for 16 random bytes
// (docs/05 D4).
const (
	callbackPrefix = "v1:"
	callbackKeyLen = len(callbackPrefix) + 22
)

func newCallbackKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go ≥ 1.24)
	return callbackPrefix + base64.RawURLEncoding.EncodeToString(b[:])
}

// wellFormedKey checks the shape before the key is used in a lookup.
func wellFormedKey(s string) bool {
	if len(s) != callbackKeyLen || s[:len(callbackPrefix)] != callbackPrefix {
		return false
	}
	for i := len(callbackPrefix); i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

type promptRow struct {
	id         string
	kind       string
	approverID int64
	chatID     int64
	messageID  int64
	body       string
	state      string
}

var errNoPrompt = errors.New("telegram: no such prompt")

func (b *Bot) promptExists(ctx context.Context, id string) (bool, error) {
	var one int
	err := b.db.QueryRowContext(ctx, `SELECT 1 FROM telegram_prompts WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (b *Bot) loadPrompt(ctx context.Context, id string) (promptRow, error) {
	p := promptRow{id: id}
	err := b.db.QueryRowContext(ctx,
		`SELECT kind, approver_id, chat_id, message_id, body, state FROM telegram_prompts WHERE id = ?`, id).
		Scan(&p.kind, &p.approverID, &p.chatID, &p.messageID, &p.body, &p.state)
	if errors.Is(err, sql.ErrNoRows) {
		return p, errNoPrompt
	}
	return p, err
}

type keyedAction struct {
	key    string
	action approval.Action
}

// insertPrompt stores a sent prompt and its button keys in one transaction.
func (b *Bot) insertPrompt(ctx context.Context, p promptRow, keys []keyedAction) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // a no-op after Commit
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_prompts (id, kind, approver_id, chat_id, message_id, body, state, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.id, p.kind, p.approverID, p.chatID, p.messageID, p.body, p.state, time.Now().Unix()); err != nil {
		return err
	}
	for _, k := range keys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO telegram_callback_keys (key, prompt_id, action) VALUES (?, ?, ?)`,
			k.key, p.id, int(k.action)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// transition moves a prompt from one state to another with a
// compare-and-set, drops its keys and stores the new ones. It reports
// false when the prompt was not in state from (already settled, or a
// concurrent Settle won), and then changes nothing.
func (b *Bot) transition(ctx context.Context, id, from, to string, newKeys []keyedAction) (bool, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() // a no-op after Commit
	q := `UPDATE telegram_prompts SET state = ? WHERE id = ? AND state = ?`
	if to == stateClosed {
		q = `UPDATE telegram_prompts SET state = ?, body = '' WHERE id = ? AND state = ?`
	}
	res, err := tx.ExecContext(ctx, q, to, id, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM telegram_callback_keys WHERE prompt_id = ?`, id); err != nil {
		return false, err
	}
	for _, k := range newKeys {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO telegram_callback_keys (key, prompt_id, action) VALUES (?, ?, ?)`,
			k.key, id, int(k.action)); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// lookupKey returns the prompt and action a callback key belongs to.
func (b *Bot) lookupKey(ctx context.Context, key string) (promptRow, approval.Action, error) {
	var p promptRow
	var action int
	err := b.db.QueryRowContext(ctx,
		`SELECT p.id, p.kind, p.approver_id, p.chat_id, p.message_id, p.state, k.action
		   FROM telegram_callback_keys k JOIN telegram_prompts p ON p.id = k.prompt_id
		  WHERE k.key = ?`, key).
		Scan(&p.id, &p.kind, &p.approverID, &p.chatID, &p.messageID, &p.state, &action)
	if errors.Is(err, sql.ErrNoRows) {
		return p, 0, errNoPrompt
	}
	return p, approval.Action(action), err
}

func (b *Bot) loadOffset(ctx context.Context) (int64, error) {
	var off int64
	err := b.db.QueryRowContext(ctx, `SELECT next_offset FROM telegram_offset WHERE id = 1`).Scan(&off)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return off, err
}

func (b *Bot) saveOffset(ctx context.Context, off int64) error {
	_, err := b.db.ExecContext(ctx,
		`INSERT INTO telegram_offset (id, next_offset) VALUES (1, ?)
		 ON CONFLICT (id) DO UPDATE SET next_offset = excluded.next_offset`, off)
	return err
}
