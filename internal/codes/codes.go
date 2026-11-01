// Package codes holds the error codes, decision values and audit kinds
// shared across Nyyrikki. Each is defined here once (CODE-REVIEW.md:
// shared constants have exactly one definition; docs/02 D14).
package codes

import (
	"errors"
	"fmt"
)

// Code is an error code returned to the agent (docs/02 D14).
type Code string

const (
	InvalidRequest      Code = "invalid_request"
	Unauthenticated     Code = "unauthenticated"
	TargetNotAllowed    Code = "target_not_allowed"
	HandleUnknown       Code = "handle_unknown"
	Denied              Code = "denied"
	Expired             Code = "expired"
	Withdrawn           Code = "withdrawn"
	IntrospectionFailed Code = "introspection_failed"
	SessionInactive     Code = "session_inactive"
	Unavailable         Code = "unavailable"
	Internal            Code = "internal"
)

// Error is an error that carries a Code. Message is shown to the agent and
// must never contain a credential, handle or ticket.
type Error struct {
	Code    Code
	Message string
	// Detail is a machine-readable sub-reason (for example
	// "canonical_mismatch"); it goes to the audit log, not only the agent.
	Detail string
	Err    error
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an *Error with the given code and message.
func New(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// WithDetail returns an *Error with a detail sub-reason.
func WithDetail(code Code, detail, format string, args ...any) *Error {
	return &Error{Code: code, Detail: detail, Message: fmt.Sprintf(format, args...)}
}

// Wrap returns an *Error that wraps err. The wrapped error's text is not
// shown to the agent.
func Wrap(code Code, err error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Err: err}
}

// Of returns the Code of err, or Internal when err carries none. A nil
// error has no code; callers must not ask.
func Of(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Internal
}

// DetailOf returns the detail of err, if any.
func DetailOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// Decision values recorded in the audit log.
const (
	Allow = "allow"
	Deny  = "deny"
)

// Target types (docs/02 D5, docs/07 D13), as list_targets returns them.
const (
	TypeKubernetes = "kubernetes"
	TypeSSH        = "ssh"
)

// What covered an allowed request.
const (
	CoveredOneOff    = "one-off"
	CoveredElevation = "elevation"
)

// DetailHostUnreachable is the detail of a host check whose host could
// not be reached (docs/08 D10). It is defined here because the check
// (internal/sshtarget) and the elevation message (internal/telegram)
// both name it.
const DetailHostUnreachable = "host_unreachable"

// Audit kinds (docs/03 §5.1).
const (
	KindAuthFailed         = "auth_failed"
	KindInvalidRequest     = "invalid_request"
	KindRunRequested       = "run_requested"
	KindElevationRequested = "elevation_requested"
	KindApprovalSent       = "approval_sent"
	KindApprovalSettled    = "approval_settled"
	KindCallbackRejected   = "callback_rejected"
	KindDecision           = "decision"
	KindRunStarted         = "run_started"
	KindRunFinished        = "run_finished"
	KindRunCut             = "run_cut"
	KindElevationLive      = "elevation_live"
	KindElevationEnded     = "elevation_ended"
	KindElevationExpired   = "elevation_expired"
	KindStreamAttached     = "stream_attached"
	KindDependencyFailed   = "dependency_failed"
	KindHostSetupServed    = "host_setup_served"
	// KindSSHCAWarning: an extra trusted key equals a derived one
	// (docs/08 D14).
	KindSSHCAWarning = "ssh_ca_warning"
)
