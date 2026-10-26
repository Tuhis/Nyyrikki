package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/store"
)

func TestAuditAppendOnlyAndHashed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out bytes.Buffer
	w, err := audit.NewWriter(ctx, db, &out, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	const key = "dpop\x00https://issuer\x00nyyrikki-cli\x00secret-jkt"
	if err := w.Append(ctx, audit.Record{Kind: "decision", Human: "owner", Agent: key, Decision: "deny"}); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := db.QueryRow("SELECT record FROM audit").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{stored, out.String()} {
		if strings.Contains(s, "secret-jkt") {
			t.Fatal("agent key in clear")
		}
		var r audit.Record
		if err := json.Unmarshal([]byte(s), &r); err != nil || r.Agent != w.AgentHash(key) || len(r.Agent) != 16 || !strings.HasPrefix(r.ID, "aud_") {
			t.Fatalf("record %q: %v", s, err)
		}
	}
	// docs/03 G2
	if _, err := db.Exec("UPDATE audit SET kind = 'x'"); err == nil {
		t.Fatal("UPDATE allowed")
	}
	if _, err := db.Exec("DELETE FROM audit"); err == nil {
		t.Fatal("DELETE allowed")
	}
	// The key survives a restart, so hashes stay comparable.
	w2, _ := audit.NewWriter(ctx, db, nil, time.Now)
	if w2.AgentHash(key) != w.AgentHash(key) {
		t.Fatal("audit key changed")
	}
}

func TestAuditWriteFailure(t *testing.T) {
	ctx := context.Background()
	db, _ := store.Open(ctx, filepath.Join(t.TempDir(), "db"))
	w, err := audit.NewWriter(ctx, db, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := w.Append(ctx, audit.Record{Kind: "decision"}); err == nil {
		t.Fatal("write to a closed database reported success")
	}
}
