package sopstarget

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"

	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keyservice"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
)

// The fixed details a failed run ends with (docs/10 D9). The agent, the
// audit log and the server's log get these, never the text of an error
// of SOPS's or Google's.
const (
	DetailMACMismatch         = "mac_mismatch"
	DetailValueNotDecryptable = "value_not_decryptable"
	DetailKMSCallLimit        = "kms_call_limit"
	DetailKMSDenied           = "kms_denied"
	DetailKMSUnavailable      = "kms_unavailable"
)

// kmsCall is one call the key service was asked for, and how it ended:
// Outcome is "" for a call that succeeded, else one of the details
// above or DetailKeyNotAllowed.
type kmsCall struct {
	Key     string
	Outcome string
	// Made is false for a call the key service refused: nothing was
	// sent to Cloud KMS.
	Made bool
}

// keyService is the one key service a run hands to the SOPS library
// (docs/10 D5). It wraps SOPS's own Google key source, and adds what
// SOPS's built-in key service can't carry (M13): the target's token
// source, the request reason and the run's context. It answers only for
// the target's Cloud KMS keys, at most once per key, and keeps a record
// of the run, because SOPS goes on to the next key after an error (M15)
// and reports failures only as text.
type keyService struct {
	ctx     context.Context
	allowed []string
	tokens  oauth2.TokenSource
	reason  string
	// extra are client options added after Nyyrikki's own (tests: the
	// fake KMS's endpoint).
	extra []option.ClientOption

	mu      sync.Mutex
	calls   []kmsCall
	refused string // the latch: the detail of the first refusal
}

var _ keyservice.KeyServiceClient = (*keyService)(nil)

// begin decides whether a call for key may be made, and records a
// refusal. A key that isn't a Google Cloud KMS key of the target, and a
// second call for a key, are refused, and the latch is set.
func (k *keyService) begin(key *keyservice.Key) (id string, call int, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	refuse := func(id, detail string) (string, int, error) {
		k.calls = append(k.calls, kmsCall{Key: id, Outcome: detail})
		if k.refused == "" {
			k.refused = detail
		}
		return "", 0, errors.New("sopstarget: refused: " + detail)
	}
	g := key.GetGcpKmsKey()
	if g == nil {
		return refuse("", DetailKeyNotAllowed)
	}
	id = g.GetResourceId()
	if !slices.Contains(k.allowed, id) {
		// The name isn't recorded: it is the file's, not the target's.
		return refuse("", DetailKeyNotAllowed)
	}
	for _, c := range k.calls {
		if c.Key == id {
			return refuse(id, DetailKMSCallLimit)
		}
	}
	// Recorded before it is made, so that a second call for the key
	// finds it whenever it comes. Until it ends it counts as failed.
	k.calls = append(k.calls, kmsCall{Key: id, Outcome: DetailKMSUnavailable, Made: true})
	return id, len(k.calls) - 1, nil
}

func (k *keyService) end(call int, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.calls[call].Outcome = classify(err)
}

// masterKey is SOPS's Google key source for id, set up with the
// target's tokens and the reason (docs/10 D5, D7). With a token source
// set, SOPS reads no credential from the environment (M7).
func (k *keyService) masterKey(id string) *gcpkms.MasterKey {
	mk := gcpkms.NewMasterKeyFromResourceID(id)
	gcpkms.NewTokenSource(k.tokens).ApplyToMasterKey(mk)
	gcpkms.UseRESTClient{}.ApplyToMasterKey(mk)
	gcpkms.ClientOptions(append([]option.ClientOption{option.WithRequestReason(k.reason)}, k.extra...)).ApplyToMasterKey(mk)
	return mk
}

// Decrypt unwraps a data key with one of the target's keys. The context
// SOPS passes is its own background one; the call runs under the run's.
func (k *keyService) Decrypt(_ context.Context, req *keyservice.DecryptRequest, _ ...grpc.CallOption) (*keyservice.DecryptResponse, error) {
	id, call, err := k.begin(req.GetKey())
	if err != nil {
		return nil, err
	}
	mk := k.masterKey(id)
	mk.SetEncryptedDataKey(req.GetCiphertext())
	plaintext, err := mk.DecryptContext(k.ctx)
	k.end(call, err)
	if err != nil {
		return nil, errors.New("sopstarget: the key could not be used")
	}
	return &keyservice.DecryptResponse{Plaintext: plaintext}, nil
}

// Encrypt wraps a new file's data key with one of the target's keys.
func (k *keyService) Encrypt(_ context.Context, req *keyservice.EncryptRequest, _ ...grpc.CallOption) (*keyservice.EncryptResponse, error) {
	id, call, err := k.begin(req.GetKey())
	if err != nil {
		return nil, err
	}
	mk := k.masterKey(id)
	err = mk.EncryptContext(k.ctx, req.GetPlaintext())
	k.end(call, err)
	if err != nil {
		return nil, errors.New("sopstarget: the key could not be used")
	}
	return &keyservice.EncryptResponse{Ciphertext: mk.EncryptedDataKey()}, nil
}

// classify maps the error of a Cloud KMS call to a fixed detail (docs/10
// D9). The error itself goes nowhere.
func classify(err error) string {
	if err == nil {
		return ""
	}
	var ge *googleapi.Error
	if errors.As(err, &ge) {
		switch ge.Code {
		case http.StatusBadRequest:
			// Cloud KMS couldn't decrypt what the file gave as its
			// wrapped data key.
			return DetailValueNotDecryptable
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return DetailKMSDenied
		}
	}
	return DetailKMSUnavailable
}

// record is what the runner reads when the library returns.
func (k *keyService) record() (calls []kmsCall, refused string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(k.calls), k.refused
}
