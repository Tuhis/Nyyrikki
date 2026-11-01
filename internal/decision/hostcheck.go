package decision

import "context"

// HostFacts are what a host check read about an SSH host (docs/08 D9,
// D10): from a certificate Nyyrikki's own host CA signed, or else from
// the target's config.
type HostFacts struct {
	SessionKill bool
}

// HostChecker is the host check of docs/08 D10: dial an SSH target's
// host, verify it, read its facts and disconnect without
// authenticating. It decides nothing: its answer is input to the
// decision point, which alone allows or denies. An error is a
// *codes.Error with codes.Unavailable and the check's detail.
type HostChecker interface {
	CheckHost(ctx context.Context, target string) (HostFacts, error)
}
