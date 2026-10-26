package authn_test

import (
	"encoding/base64"
	"encoding/json"
)

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}
