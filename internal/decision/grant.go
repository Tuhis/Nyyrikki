package decision

import "github.com/Tuhis/Nyyrikki/internal/decision/internal/grant"

// Grant is the decision point's permission to run exactly one canonical
// request. Only this package makes one (docs/02 D6); the runner takes
// nothing else.
type Grant = grant.Grant
