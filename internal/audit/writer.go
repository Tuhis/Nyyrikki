package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/Tuhis/Nyyrikki/internal/store"
)

// Writer appends records to SQLite and then to a JSON-lines stream
// (stdout in production) (docs/03 D2, D5).
type Writer struct {
	db  *sql.DB
	key []byte
	now func() time.Time

	mu  sync.Mutex
	out io.Writer
}

// NewWriter returns a Writer. The HMAC key for agent keys is kept in the
// database (docs/03 D3).
func NewWriter(ctx context.Context, db *sql.DB, out io.Writer, now func() time.Time) (*Writer, error) {
	key, err := store.Secret(ctx, db, "audit_key")
	if err != nil {
		return nil, fmt.Errorf("audit: key: %w", err)
	}
	if now == nil {
		now = time.Now
	}
	return &Writer{db: db, key: key, now: now, out: out}, nil
}

// AgentHash returns the keyed hash under which agent key k appears in the
// audit log and to the approver (docs/03 D3).
func (w *Writer) AgentHash(k string) string {
	if k == "" {
		return ""
	}
	m := hmac.New(sha256.New, w.key)
	m.Write([]byte(k))
	return hex.EncodeToString(m.Sum(nil))[:16]
}

// Append stores r. An error means it was not stored (docs/03 D4).
func (w *Writer) Append(ctx context.Context, r Record) error {
	t := w.now().UTC()
	r.ID = "aud_" + ulid.MustNew(ulid.Timestamp(t), ulid.DefaultEntropy()).String()
	r.Time = t.Format("2006-01-02T15:04:05.000Z")
	r.Agent = w.AgentHash(r.Agent)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("audit: encode: %w", err)
	}
	line := buf.Bytes()
	// Detached from the caller's context: a cancelled call must still be
	// able to record that it was cancelled.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := w.db.ExecContext(wctx, "INSERT INTO audit (id, time_ms, kind, record) VALUES (?, ?, ?, ?)",
		r.ID, t.UnixMilli(), r.Kind, string(bytes.TrimSpace(line))); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	if w.out != nil {
		w.mu.Lock()
		_, _ = w.out.Write(line)
		w.mu.Unlock()
	}
	return nil
}
