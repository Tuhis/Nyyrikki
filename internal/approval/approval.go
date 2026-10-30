// Package approval is the interface between the decision point and the
// channel that asks a human (docs/05 §5.1). The decision point owns all
// approval and elevation state; the channel only shows prompts and reports
// taps back through Resolver.
package approval

import (
	"context"
	"time"
)

// Identity is who a request runs as on the target.
type Identity struct {
	User   string
	Groups []string
}

// Agent is what the approver is shown about an agent (docs/01 §5.4).
// ClientName is the client's own claim and must be shown as such.
type Agent struct {
	ClientName string
	KeyShort   string
	SignedInAt time.Time
}

// SSHHost is what the approver is shown about an SSH target (docs/07
// D12): the account a run uses there, the host's address, and what its
// config states about root and about cuts.
type SSHHost struct {
	Target      string
	Account     string
	Address     string
	Sudo        bool
	SessionKill bool
}

// RunPrompt asks for a one-off approval of one request (docs/05 D5).
// Argv and Stdin are the display forms from docs/04 §5.2 and docs/07 D2,
// already redacted where the type redacts (docs/04 D14) but not
// HTML-escaped. Stdin is empty when there is none. For an SSH target
// (Type codes.TypeSSH), Argv is the command string, possibly multi-line,
// Stdin is only its size and hash, and SSH is set.
type RunPrompt struct {
	ID          string
	ApproverID  int64
	Target      string
	Type        string
	SSH         *SSHHost
	RunAs       Identity
	Agent       Agent
	Argv        string
	Stdin       string
	Interactive bool
	Reason      string
	ExpiresAt   time.Time
}

// ElevationPrompt asks for an elevation (docs/05 D7).
// RunAs is the Kubernetes identity, for the targets SSH doesn't list;
// SSH lists the SSH targets among Targets (docs/07 D12).
type ElevationPrompt struct {
	ID         string
	ApproverID int64
	Targets    []string
	Duration   time.Duration
	RunAs      Identity
	SSH        []SSHHost
	Agent      Agent
	Reason     string
	ExpiresAt  time.Time
}

// OutcomeKind is what a prompt is edited to show (docs/05 D6, D7).
type OutcomeKind int

const (
	Approved OutcomeKind = iota + 1
	Denied
	Expired   // nobody answered: denied
	Withdrawn // the waiting call went away
	Failed    // Nyyrikki could not complete it
	ElevationLive
	ElevationEnded
	ElevationExpired
	// SessionApproved is Approved for an interactive run: no buttons,
	// but the message stays editable for SessionLive (docs/07 D17).
	SessionApproved
	// SessionLive shows "Session live since At" with End now.
	SessionLive
	// SessionEnded shows "Session ended at At", without buttons.
	SessionEnded
	// SessionUnused closes an approved session that never attached.
	SessionUnused
)

// Outcome is the final or current state of a prompt. Until is set for
// ElevationLive.
type Outcome struct {
	Kind  OutcomeKind
	At    time.Time
	Until time.Time
}

// Action is what a tap asks for.
type Action int

const (
	ActionApprove Action = iota + 1
	ActionDeny
	ActionEnd // "End now" on a live elevation or interactive run
)

// Asker sends prompts to the approver.
type Asker interface {
	// AskRun sends a one-off prompt. It returns once the prompt was
	// sent; an error means it was not, and the request must be denied.
	// A prompt that can't be shown in full returns an error with
	// codes.InvalidRequest (docs/05 D9).
	AskRun(ctx context.Context, p RunPrompt) error
	// AskElevation sends an elevation prompt, with the same contract.
	AskElevation(ctx context.Context, p ElevationPrompt) error
	// Settle edits the prompt with the given ID to show the outcome.
	Settle(ctx context.Context, id string, o Outcome) error
	// Healthy reports whether prompts can be sent and answers received.
	Healthy() bool
}

// Resolver is implemented by the decision point. The channel calls it for
// a tap that passed its own checks (docs/05 D4); Resolve does the
// compare-and-set and checks approverID against the prompt's approver. It
// returns false when the tap changed nothing (already settled, expired,
// wrong approver).
type Resolver interface {
	Resolve(ctx context.Context, id string, action Action, approverID int64) (bool, error)
}
