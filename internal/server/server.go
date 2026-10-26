// Package server wires nyyrikkid together: listeners, TLS, the
// authentication middleware, the MCP endpoint, /stream and health
// (docs/01 D10, docs/02 §5.1).
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/mcpserver"
	"github.com/Tuhis/Nyyrikki/internal/store"
	"github.com/Tuhis/Nyyrikki/internal/stream"
	"github.com/Tuhis/Nyyrikki/internal/telegram"
)

// Options holds what isn't in the config file: process-level wiring and
// test seams.
type Options struct {
	Version    string
	AuditOut   io.Writer // stdout in production
	Logger     *slog.Logger
	Executable string // for kubectl-child; os.Executable() when empty
	// AuthHTTPClient and TelegramHTTPClient replace the default clients
	// (tests use them to trust test servers).
	AuthHTTPClient     *http.Client
	TelegramHTTPClient *http.Client
	// Ready, if set, receives the bound addresses once listening.
	Ready func(main, health net.Addr)
	Now   func() time.Time
	// KubeServiceAccountDir overrides the in-cluster credential directory
	// (tests).
	KubeServiceAccountDir string
}

// Run starts nyyrikkid and blocks until ctx ends or a listener fails.
func Run(ctx context.Context, cfg *config.Config, o Options) error {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.AuditOut == nil {
		o.AuditOut = os.Stdout
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Executable == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		o.Executable = exe
	}
	log := o.Logger

	db, err := store.Open(ctx, filepath.Join(cfg.Server.StateDir, "nyyrikki.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	aw, err := audit.NewWriter(ctx, db, o.AuditOut, o.Now)
	if err != nil {
		return err
	}

	verifier := authn.NewVerifier(authn.Config{
		Issuer:      cfg.Auth.Issuer,
		CLIClientID: cfg.Auth.CLIClientID,
		Audience:    cfg.MCPURL(),
		HumanBySubject: func(sub string) (authn.Human, bool) {
			h, ok := cfg.HumanBySubject(sub)
			if !ok {
				return authn.Human{}, false
			}
			return authn.Human{ID: h.ID}, true
		},
		ResourceMetadataURL:     cfg.Server.CanonicalURL + "/.well-known/oauth-protected-resource/mcp",
		IntrospectionClientID:   cfg.Auth.IntrospectionClientID,
		IntrospectionSecretFile: cfg.Auth.IntrospectionSecretFile,
		HTTPClient:              o.AuthHTTPClient,
		Now:                     o.Now,
		Audit:                   aw,
		Logger:                  log,
	})

	if err := telegram.Migrate(ctx, db); err != nil {
		return err
	}
	bot, err := telegram.New(telegram.Config{
		APIURL:     cfg.Telegram.APIURL,
		TokenFile:  cfg.Telegram.BotTokenFile,
		Now:        o.Now,
		Logger:     log,
		HTTPClient: o.TelegramHTTPClient,
	}, db, aw)
	if err != nil {
		return err
	}

	point, err := decision.New(ctx, decision.Config{
		Config: cfg, DB: db, Audit: aw, Asker: bot, Introspector: verifier, Now: o.Now, Logger: log,
	})
	if err != nil {
		return err
	}
	defer point.Close()
	bot.SetResolver(point)

	targets := map[string]kubectl.Target{}
	for _, t := range cfg.Targets {
		targets[t.Name] = kubectl.Target{
			Name: t.Name, InCluster: t.Kubernetes.InCluster,
			Server: t.Kubernetes.Server, CAFile: t.Kubernetes.CAFile, TokenFile: t.Kubernetes.TokenFile,
		}
	}
	runner, err := kubectl.NewRunner(kubectl.RunnerConfig{
		RuntimeDir: cfg.Server.RuntimeDir,
		Executable: o.Executable,
		Targets:    targets,
		Limits: kubectl.Limits{
			DefaultTimeout: cfg.Run.DefaultTimeout.D(),
			MaxTimeout:     cfg.Run.MaxTimeout.D(),
			MaxInteractive: cfg.Run.MaxInteractive.D(),
			MaxOutput:      int64(cfg.Run.MaxOutput),
		},
		Audit:             aw,
		Now:               o.Now,
		Logger:            log,
		ServiceAccountDir: o.KubeServiceAccountDir,
	})
	if err != nil {
		return err
	}

	mcpSrv := mcpserver.New(mcpserver.Deps{Config: cfg, Point: point, Runner: runner, Audit: aw, Logger: log, Version: o.Version})

	mux := http.NewServeMux()
	mux.Handle("POST /mcp", verifier.Middleware(cfg.MCPURL(), mcpSrv.Handler()))
	mux.Handle("GET /stream", verifier.Middleware(cfg.StreamURL(), stream.NewHandler(point, runner, verifier, aw, log)))
	prm := protectedResourceMetadata(cfg)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", prm)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", prm)

	health := http.NewServeMux()
	health.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	health.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// No data: only the status code (docs/01 D10).
		if !bot.Healthy() || db.PingContext(r.Context()) != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	certs, err := newCertReloader(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
	if err != nil {
		return err
	}
	mainLn, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return err
	}
	healthLn, err := net.Listen("tcp", cfg.Server.HealthListen)
	if err != nil {
		mainLn.Close()
		return err
	}
	if o.Ready != nil {
		o.Ready(mainLn.Addr(), healthLn.Addr())
	}

	mainSrv := &http.Server{
		Handler:           mux,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.get},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	healthSrv := &http.Server{Handler: health, ReadHeaderTimeout: 5 * time.Second}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 3)
	go func() {
		err := bot.Run(ctx)
		if errors.Is(err, telegram.ErrStopped) {
			// Another poller or a revoked token: the poller stops for good
			// and escalations are denied, but the server keeps serving so
			// /readyz reports it. Exiting would make the kubelet restart
			// us into exactly the retry loop docs/05 D2 forbids.
			log.Error("telegram poller stopped; escalations are denied until restart", "err", err)
			return
		}
		errc <- err
	}()
	go func() { errc <- mainSrv.ServeTLS(mainLn, "", "") }()
	go func() { errc <- healthSrv.Serve(healthLn) }()
	log.Info("nyyrikkid listening", "listen", mainLn.Addr().String(), "health", healthLn.Addr().String(), "version", o.Version)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		if errors.Is(runErr, http.ErrServerClosed) || errors.Is(runErr, context.Canceled) {
			runErr = nil
		}
		if runErr == nil {
			// The Telegram poller stops for good on a 409/401
			// (docs/05 D2); keep serving so /readyz reports it, and
			// escalations are denied meanwhile.
			select {
			case <-ctx.Done():
			case runErr = <-errc:
			}
		}
	}
	cancel()
	shutdownCtx, sc := context.WithTimeout(context.Background(), 10*time.Second)
	defer sc()
	_ = mainSrv.Shutdown(shutdownCtx)
	_ = healthSrv.Shutdown(shutdownCtx)
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	return runErr
}

func protectedResourceMetadata(cfg *config.Config) http.HandlerFunc {
	body, _ := json.Marshal(map[string]any{
		"resource":                          cfg.MCPURL(),
		"authorization_servers":             []string{cfg.Auth.Issuer},
		"bearer_methods_supported":          []string{"header"},
		"scopes_supported":                  []string{cfg.Auth.Scope},
		"dpop_signing_alg_values_supported": []string{"ES256", "ES384", "ES512", "RS256", "PS256", "EdDSA"},
		"resource_name":                     "Nyyrikki",
		// Lets `nyyrikki login` find the pre-registered CLI client.
		"nyyrikki_cli_client_id": cfg.Auth.CLIClientID,
	})
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// certReloader re-reads the TLS key pair when its files change, so a
// rotated certificate needs no restart.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if _, err := r.load(); err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return r, nil
}

func (r *certReloader) load() (*tls.Certificate, error) {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return nil, err
	}
	if r.cert != nil && st.ModTime().Equal(r.modTime) {
		return r.cert, nil
	}
	c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return nil, err
	}
	r.cert, r.modTime = &c, st.ModTime()
	return r.cert, nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) > time.Minute {
		r.checked = time.Now()
		if _, err := r.load(); err != nil && r.cert == nil {
			return nil, err
		}
	}
	return r.cert, nil
}
