package sopstarget

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// kmsScope is the only scope Nyyrikki's Google tokens carry (docs/10
// D6).
const kmsScope = "https://www.googleapis.com/auth/cloudkms"

// tokenTimeout bounds one token exchange.
const tokenTimeout = 15 * time.Second

// maxCredentialsFile is the largest credential file read.
const maxCredentialsFile = 64 << 10

// The two kinds of credential file accepted (docs/10 D6).
const (
	credServiceAccount  = "service_account"
	credExternalAccount = "external_account"
)

// externalAccountFields are the fields a Workload Identity Federation
// configuration may hold (docs/10 D6). Anything else is refused: the
// format can name a URL to fetch, a program to run or another cloud's
// metadata service, and Nyyrikki needs none of them.
var externalAccountFields = map[string]bool{
	"type": true, "audience": true, "subject_token_type": true, "token_url": true, "token_info_url": true,
	"service_account_impersonation_url": true, "service_account_impersonation": true,
	"credential_source": true, "universe_domain": true,
}

// ValidateCredentials checks that b is one of the two kinds of Google
// credential file a SOPS target takes (docs/10 D6): a service account
// key, or a Workload Identity Federation configuration whose subject
// token comes from a file. The error never holds anything from the
// file.
func ValidateCredentials(b []byte) (kind string, err error) {
	if len(b) > maxCredentialsFile {
		return "", errors.New("the credential file is too large")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return "", errors.New("the credential file is not a JSON object")
	}
	if err := json.Unmarshal(top["type"], &kind); err != nil {
		return "", errors.New("the credential file has no type")
	}
	switch kind {
	case credServiceAccount:
		return kind, nil
	case credExternalAccount:
	default:
		return "", errors.New("the credential file must be of type service_account or external_account")
	}
	for name := range top {
		if !externalAccountFields[name] {
			// Not the name: the error is logged, and a file that isn't
			// what it should be holds nobody knows what.
			return "", errors.New("an external_account credential file holds a field Nyyrikki doesn't accept (docs/setup/sops.md lists them)")
		}
	}
	var src map[string]json.RawMessage
	if err := json.Unmarshal(top["credential_source"], &src); err != nil {
		return "", errors.New("an external_account credential file needs a credential_source")
	}
	for name := range src {
		// A URL, an executable, a certificate or an environment_id
		// would make Nyyrikki fetch or run something to get its token.
		if name != "file" && name != "format" {
			return "", errors.New("credential_source may hold only file and format")
		}
	}
	var file string
	if err := json.Unmarshal(src["file"], &file); err != nil || file == "" {
		return "", errors.New("credential_source.file is required: the subject token must come from a file")
	}
	return kind, nil
}

// credentials turns a target's credential file into access tokens
// (docs/10 D6). The file is read on each use; the token source, which
// keeps a token in memory until it expires, is reused while the file's
// bytes stay the same.
type credentials struct {
	file string
	// client replaces the HTTP client of token exchanges (tests).
	client *http.Client

	mu  sync.Mutex
	sum [32]byte
	ts  oauth2.TokenSource
}

// tokenSource reads and checks the file and returns a token source for
// it. Its errors never hold anything from the file.
func (c *credentials) tokenSource() (oauth2.TokenSource, error) {
	b, err := os.ReadFile(c.file)
	if err != nil {
		return nil, errors.New("the credential file could not be read")
	}
	kind, err := ValidateCredentials(b)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ts != nil && bytes.Equal(sum[:], c.sum[:]) {
		return c.ts, nil
	}
	hc := c.client
	if hc == nil {
		hc = &http.Client{Timeout: tokenTimeout}
	}
	// The context only carries the HTTP client: a token source outlives
	// the run that made it.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, hc)
	creds, err := google.CredentialsFromJSONWithType(ctx, b, google.CredentialsType(kind), kmsScope)
	if err != nil {
		return nil, errors.New("the credential file could not be used")
	}
	c.sum, c.ts = sum, creds.TokenSource
	return c.ts, nil
}
