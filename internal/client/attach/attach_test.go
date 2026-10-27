package attach

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/stream/protocol"
)

func wsURL(s *httptest.Server) string { return "ws" + strings.TrimPrefix(s.URL, "http") }

func TestAttachErrors(t *testing.T) {
	// A refusal without a JSON body still maps to a code.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer plain.Close()
	if _, err := Attach(t.Context(), wsURL(plain), "nyst_x", nil, strings.NewReader(""), io.Discard, nil); codes.Of(err) != codes.Unauthenticated {
		t.Errorf("401 = %v", err)
	}
	if _, err := Attach(t.Context(), wsURL(plain), "", nil, strings.NewReader(""), io.Discard, nil); codes.Of(err) != codes.InvalidRequest {
		t.Errorf("no ticket = %v", err)
	}

	// The ticket and the caller's headers reach the server; a stream that
	// closes without an exit status is an error, not exit 0.
	gotHeaders := make(chan http.Header, 1)
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders <- r.Header.Clone()
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.Write(r.Context(), websocket.MessageBinary, []byte("partial"))
		c.Close(websocket.StatusNormalClosure, "")
	}))
	defer drop.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var out strings.Builder
	_, err := Attach(ctx, wsURL(drop), "nyst_x", http.Header{"Authorization": {"DPoP tok"}, "Dpop": {"proof"}}, strings.NewReader(""), &out, nil)
	if codes.Of(err) != codes.Unavailable {
		t.Errorf("dropped stream = %v", err)
	}
	h := <-gotHeaders
	if h.Get(protocol.TicketHeader) != "nyst_x" || h.Get("Authorization") != "DPoP tok" || h.Get("DPoP") != "proof" {
		t.Errorf("headers = %v", h)
	}
	if out.String() != "partial" {
		t.Errorf("output = %q", out.String())
	}
}
