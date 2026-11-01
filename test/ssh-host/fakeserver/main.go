//go:build sshhost

// Command fakeserver stands in for Nyyrikki's /hosts/ endpoints inside a
// test/ssh-host container, so that the setup script's trust pull and
// enrollment (docs/08 D5, D7) talk HTTPS to something the test controls.
// It serves what the test writes into -dir:
//
//	trust.answer, trust.status     GET  /hosts/<t>/trust
//	enroll.answer, enroll.status   POST /hosts/<t>/enroll (held while enroll.hold exists)
//	check.answer, check.status     POST /hosts/<t>/enroll/check
//
// and records each request's Authorization header and body as
// <name>.auth and <name>.body. A missing answer is 404.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "listen address")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	dir := flag.String("dir", "", "directory of answers")
	flag.Parse()
	serve := func(name string, hold bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			_ = os.WriteFile(filepath.Join(*dir, name+".auth"), []byte(r.Header.Get("Authorization")), 0o600)
			_ = os.WriteFile(filepath.Join(*dir, name+".body"), b, 0o600)
			f, _ := os.OpenFile(filepath.Join(*dir, "requests"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if f != nil {
				_, _ = f.WriteString(r.Method + " " + r.URL.Path + "\n")
				_ = f.Close()
			}
			for deadline := time.Now().Add(10 * time.Minute); hold && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				if _, err := os.Stat(filepath.Join(*dir, name+".hold")); err != nil {
					break
				}
			}
			status := http.StatusOK
			if s, err := os.ReadFile(filepath.Join(*dir, name+".status")); err == nil {
				if n, err := strconv.Atoi(strings.TrimSpace(string(s))); err == nil {
					status = n
				}
			}
			answer, err := os.ReadFile(filepath.Join(*dir, name+".answer"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(status)
			_, _ = w.Write(answer)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hosts/{t}/trust", serve("trust", false))
	mux.HandleFunc("POST /hosts/{t}/enroll", serve("enroll", true))
	mux.HandleFunc("POST /hosts/{t}/enroll/check", serve("check", false))
	log.Fatal(http.ListenAndServeTLS(*addr, *cert, *key, mux))
}
