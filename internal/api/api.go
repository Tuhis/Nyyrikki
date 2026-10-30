// Package api holds the tools' names and their input and result types,
// shared by the MCP server and the CLI (docs/02 §5.2), so the two can't
// drift apart.
package api

import "github.com/Tuhis/Nyyrikki/internal/codes"

// Tool names, one definition (docs/02 D1).
const (
	ToolListTargets = "list_targets"
	ToolRun         = "run"
	ToolElevate     = "elevate"
)

// ListTargetsIn is list_targets' input: nothing.
type ListTargetsIn struct{}

// TargetInfo describes one target.
type TargetInfo struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
}

// ListTargetsOut is list_targets' result.
type ListTargetsOut struct {
	// Error is set when the call failed (docs/02 D14).
	Error   *ErrorBody   `json:"error,omitempty"`
	Targets []TargetInfo `json:"targets"`
}

// RunIn is run's input (docs/02 §5.2).
type RunIn struct {
	Target      string   `json:"target" jsonschema:"the target name, from list_targets"`
	Args        []string `json:"args" jsonschema:"kubernetes targets: kubectl arguments, without the leading kubectl; ssh targets: the command, joined with spaces into one string the host's shell runs"`
	Stdin       string   `json:"stdin,omitempty" jsonschema:"input for commands that read stdin (kubectl -f -, exec/attach -i; any ssh command). On ssh targets the approver sees only its size and hash"`
	Reason      string   `json:"reason" jsonschema:"why you need this; shown to the approver as your claim"`
	Elevation   string   `json:"elevation,omitempty" jsonschema:"the handle of a live elevation covering this target"`
	Timeout     string   `json:"timeout,omitempty" jsonschema:"how long the command may run, Go duration syntax, e.g. 2m"`
	Interactive bool     `json:"interactive,omitempty" jsonschema:"a terminal session (kubectl exec/attach -i -t, or an ssh command or login shell): return a stream ticket instead of output (the nyyrikki CLI uses this)"`
}

// RunOut is run's result.
type RunOut struct {
	// Error is set when the call failed (docs/02 D14).
	Error           *ErrorBody `json:"error,omitempty"`
	RunID           string     `json:"run_id"`
	CoveredBy       string     `json:"covered_by"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	Stdout          string     `json:"stdout,omitempty"`
	StdoutBase64    string     `json:"stdout_base64,omitempty"`
	Stderr          string     `json:"stderr,omitempty"`
	StdoutTruncated bool       `json:"stdout_truncated,omitempty"`
	StderrTruncated bool       `json:"stderr_truncated,omitempty"`
	// Detail notes how the command ended, such as "signal: TERM".
	Detail          string `json:"detail,omitempty"`
	StreamTicket    string `json:"stream_ticket,omitempty"`
	StreamURL       string `json:"stream_url,omitempty"`
	TicketExpiresAt string `json:"ticket_expires_at,omitempty"`
}

// ElevateIn is elevate's input (docs/02 D8).
type ElevateIn struct {
	Targets  []string `json:"targets" jsonschema:"target names, 1 to 10"`
	Duration string   `json:"duration,omitempty" jsonschema:"Go duration, default 15m, at most 30m"`
	Reason   string   `json:"reason" jsonschema:"why you need it; shown to the approver as your claim"`
}

// ElevateOut is elevate's result.
type ElevateOut struct {
	// Error is set when the call failed (docs/02 D14).
	Error       *ErrorBody `json:"error,omitempty"`
	ElevationID string     `json:"elevation_id"`
	Handle      string     `json:"handle"`
	Targets     []string   `json:"targets"`
	ExpiresAt   string     `json:"expires_at"`
}

// ErrorResult is the structured content of a failed call (docs/02 D14).
type ErrorResult struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is a code and a message for the agent.
type ErrorBody struct {
	Code    codes.Code `json:"code"`
	Message string     `json:"message"`
}
