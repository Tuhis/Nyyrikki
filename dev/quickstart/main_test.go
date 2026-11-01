//go:build quickstart

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Tuhis/Nyyrikki/test/stack"
)

const testToken = "123456789:AAtestTESTtestTESTtestTESTtestTESTte"

func fakeBotAPI(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := botAPI
	botAPI = srv.URL
	t.Cleanup(func() { botAPI = old })
}

// senders reads who wrote to the bot without confirming any update (no
// offset) and without setting allowed_updates, which would stay set for
// nyyrikkid; it skips bots and repeats.
func TestSenders(t *testing.T) {
	fakeBotAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+testToken+"/getUpdates" {
			t.Errorf("path %s", r.URL.Path)
		}
		if q := r.URL.Query(); q.Has("offset") || q.Has("allowed_updates") {
			t.Errorf("getUpdates with %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"ok":true,"result":[
			{"update_id":1,"message":{"from":{"id":42,"is_bot":false,"first_name":"Ann","username":"ann"}}},
			{"update_id":2,"message":{"from":{"id":7,"is_bot":true,"first_name":"Other bot"}}},
			{"update_id":3,"callback_query":{"from":{"id":99}}},
			{"update_id":4,"message":{"from":{"id":42,"first_name":"Ann"}}},
			{"update_id":5,"message":{"from":{"id":43,"first_name":"Bob\u001b]52;c;cHduZWQ=\u0007"}}},
			{"update_id":6,"message":{"from":{"id":666,"first_name":"Ann (@ann), user ID 42\"","username":"mallory"}}}
		]}`))
	})
	got, err := senders(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != 42 || got[1].ID != 43 || got[2].ID != 666 {
		t.Fatalf("senders: %+v", got)
	}
	if s := got[1].String(); strings.ContainsAny(s, "\x1b\x07") {
		t.Fatalf("a terminal escape reaches the terminal: %q", s)
	}
	// What Telegram checked comes first; the name the sender chose comes
	// last, quoted, so it can't pass for another account's ID or username.
	for _, c := range []struct {
		s    sender
		want string
	}{
		{got[0], `user ID 42, @ann, calls themself "Ann"`},
		{got[1], `user ID 43, (no username), calls themself "Bob]52;c;cHduZWQ="`},
		{got[2], `user ID 666, @mallory, calls themself "Ann (@ann), user ID 42\""`},
	} {
		if s := c.s.String(); s != c.want {
			t.Errorf("shown as %s, want %s", s, c.want)
		}
	}
}

func TestSendersConflict(t *testing.T) {
	fakeBotAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"ok":false,"error_code":409}`))
	})
	if _, err := senders(testToken); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a 409: %v", err)
	}
}

// No error from the Bot API calls carries the token, which is in the URL.
func TestBotErrorsHideTheToken(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close() // refused connections from here on
	old := botAPI
	botAPI = srv.URL
	t.Cleanup(func() { botAPI = old })
	if _, err := getMe(testToken); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("getMe: %v", err)
	}
	if _, err := senders(testToken); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("senders: %v", err)
	}
	fakeBotAPI(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	if _, err := getMe(testToken); err == nil || strings.Contains(err.Error(), testToken) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("getMe on 401: %v", err)
	}
}

// waitReady works on a stack without a context, as the stack's own waits
// do: it runs out its time and says so, rather than panicking.
func TestWaitReadyWithoutContext(t *testing.T) {
	s := &stack.Stack{Kubeconfig: filepath.Join(t.TempDir(), "none")}
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New(fmt.Sprint("panic: ", r))
			}
		}()
		err = waitReady(s, time.Second)
	}()
	if err == nil || !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("waitReady without a context: %v", err)
	}
}
