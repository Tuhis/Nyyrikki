//go:build e2e

// Command fakebot is the fake Telegram Bot API for the end-to-end tests. It
// runs in a container on the kind network, where nyyrikkid can reach it,
// and serves a small control API that the test uses to read prompts and tap
// buttons as the approver.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strconv"

	"github.com/Tuhis/Nyyrikki/internal/telegram/telegramtest"
)

func main() {
	api := flag.String("api", ":8443", "Bot API listen address (TLS)")
	control := flag.String("control", ":9000", "control API listen address")
	cert := flag.String("cert", "/certs/tls.crt", "TLS certificate")
	key := flag.String("key", "/certs/tls.key", "TLS key")
	flag.Parse()

	f := telegramtest.NewStandalone()
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /sent", func(w http.ResponseWriter, r *http.Request) { reply(w, f.Sent()) })
	mux.HandleFunc("GET /message", func(w http.ResponseWriter, r *http.Request) {
		chat, _ := strconv.ParseInt(r.URL.Query().Get("chat"), 10, 64)
		id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		m, ok := f.Message(chat, id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		reply(w, m)
	})
	mux.HandleFunc("POST /callback", func(w http.ResponseWriter, r *http.Request) {
		var c telegramtest.Callback
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reply(w, map[string]string{"id": f.PushCallback(c)})
	})
	mux.HandleFunc("GET /answer", func(w http.ResponseWriter, r *http.Request) {
		a, ok := f.Answer(r.URL.Query().Get("id"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		reply(w, a)
	})
	go func() { log.Fatal(http.ListenAndServe(*control, mux)) }()
	log.Fatal(http.ListenAndServeTLS(*api, *cert, *key, f.Handler()))
}
