//go:build quickstart

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
			{"update_id":5,"message":{"from":{"id":43,"first_name":"Bob\u001b]52;c;cHduZWQ=\u0007"}}}
		]}`))
	})
	got, err := senders(testToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != 42 || got[1].ID != 43 {
		t.Fatalf("senders: %+v", got)
	}
	if s := got[1].String(); strings.ContainsAny(s, "\x1b\x07") {
		t.Fatalf("a terminal escape reaches the terminal: %q", s)
	}
	if s := got[0].String(); s != "Ann (@ann), user ID 42" {
		t.Fatalf("shown as %q", s)
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
