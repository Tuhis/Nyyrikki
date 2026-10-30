// Package audit writes Nyyrikki's append-only audit log (docs/03).
package audit

import "context"

// Request is the audited form of a request: the canonical argv after the
// redaction of docs/04 D14, and the size and hash of stdin, never its
// contents (docs/03 D6).
type Request struct {
	Argv []string `json:"argv,omitempty"`
	// Command is an SSH request's command string, as sent (docs/07 D2).
	Command     string `json:"command,omitempty"`
	StdinBytes  int    `json:"stdin_bytes,omitempty"`
	StdinSHA256 string `json:"stdin_sha256,omitempty"`
	Interactive bool   `json:"interactive,omitempty"`
}

// RunAs is the identity a request runs as on the target.
type RunAs struct {
	User   string   `json:"user"`
	Groups []string `json:"groups,omitempty"`
}

// Record is one audit event (docs/03 D1). ID and Time are filled in by the
// writer. Agent is the raw agent key: the writer replaces it with its keyed
// hash before anything is stored (docs/03 D3), so callers pass the key as
// they have it.
type Record struct {
	ID          string   `json:"id"`
	Time        string   `json:"time"`
	Kind        string   `json:"kind"`
	Human       string   `json:"human,omitempty"`
	Agent       string   `json:"agent,omitempty"`
	ClientID    string   `json:"client_id,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	RunID       string   `json:"run_id,omitempty"`
	ElevationID string   `json:"elevation_id,omitempty"`
	ApprovalID  string   `json:"approval_id,omitempty"`
	Request     *Request `json:"request,omitempty"`
	Reason      string   `json:"reason,omitempty"`
	RunAs       *RunAs   `json:"run_as,omitempty"`
	CoveredBy   string   `json:"covered_by,omitempty"`
	Decision    string   `json:"decision,omitempty"`
	Code        string   `json:"code,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	ExitCode    *int     `json:"exit_code,omitempty"`
	StdoutBytes int64    `json:"stdout_bytes,omitempty"`
	StderrBytes int64    `json:"stderr_bytes,omitempty"`
	// CertSerial is the serial of the SSH certificate a run was issued
	// (docs/07 D5), in decimal; its key ID is "nyyrikki:" and the run ID.
	CertSerial string `json:"cert_serial,omitempty"`
}

// Appender appends records. An error means the record was not stored, and
// the caller must not act on the step it records (docs/03 D4).
type Appender interface {
	Append(ctx context.Context, r Record) error
}
