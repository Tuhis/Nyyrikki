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

	"golang.org/x/crypto/ssh"

	sshhost "github.com/Tuhis/Nyyrikki/deploy/ssh-host"
	"github.com/Tuhis/Nyyrikki/internal/audit"
	"github.com/Tuhis/Nyyrikki/internal/authn"
	"github.com/Tuhis/Nyyrikki/internal/codes"
	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/decision"
	"github.com/Tuhis/Nyyrikki/internal/hostsetup"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/mcpserver"
	"github.com/Tuhis/Nyyrikki/internal/runner"
	"github.com/Tuhis/Nyyrikki/internal/sshca"
	"github.com/Tuhis/Nyyrikki/internal/sshtarget"
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
	// SSHDial replaces the SSH runner's TCP dialler (tests).
	SSHDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// newSSHKeys builds the CA key loader of docs/08 D1 from the ssh block:
// the three key files, the extra trusted keys and the revoked ones.
func newSSHKeys(cfg *config.Config, aw audit.Appender, log *slog.Logger) (*sshca.Keys, error) {
	o := sshca.Options{
		Files: sshca.Files{
			UserCA:     cfg.SSH.UserCAKeyFile,
			NextUserCA: cfg.SSH.NextUserCAKeyFile,
			HostCA:     cfg.SSH.HostCAKeyFile,
		},
		Audit:  aw,
		Logger: log,
	}
	for _, k := range cfg.SSH.UserCAPublicKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			return nil, err
		}
		o.Extra = append(o.Extra, pk)
	}
	for _, k := range cfg.SSH.RevokedUserCAKeys {
		pk, err := config.ParseUserCAKey(k)
		if err != nil {
			return nil, err
		}
		o.Revoked = append(o.Revoked, pk)
	}
	return sshca.New(o), nil
}

// newSSHRunner builds the SSH runner from the ssh block and the SSH
// targets (docs/07 §5.5); nil when there are none. keys are the CA keys
// of docs/08 D1.
func newSSHRunner(cfg *config.Config, keys *sshca.Keys, aw audit.Appender, log *slog.Logger, o Options) (*sshtarget.Runner, error) {
	parseKeys := func(keys []string) ([]ssh.PublicKey, error) {
		var out []ssh.PublicKey
		for _, k := range keys {
			pk, err := config.ParsePublicKey(k)
			if err != nil {
				return nil, err
			}
			out = append(out, pk)
		}
		return out, nil
	}
	// docs/08 D9: the global host CAs are accepted for every target, and
	// a revoked key for none.
	globalCAs, err := parseKeys(cfg.SSH.HostCAs)
	if err != nil {
		return nil, fmt.Errorf("ssh.host_cas: %w", err)
	}
	revoked, err := parseKeys(cfg.SSH.RevokedHostKeys)
	if err != nil {
		return nil, fmt.Errorf("ssh.revoked_host_keys: %w", err)
	}
	targets := map[string]sshtarget.Target{}
	for _, t := range cfg.Targets {
		if t.SSH == nil {
			continue
		}
		host, _, err := config.SplitAddress(t.SSH.Address)
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		st := sshtarget.Target{Name: t.Name, Address: t.SSH.Address, Host: host, SessionKill: t.SSH.SessionKill}
		if st.HostKeys, err = parseKeys(t.SSH.HostKeys); err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		if st.HostCAs, err = parseKeys(t.SSH.HostCAs); err != nil {
			return nil, fmt.Errorf("target %s: %w", t.Name, err)
		}
		st.HostCAs = append(st.HostCAs, globalCAs...)
		targets[t.Name] = st
	}
	if len(targets) == 0 {
		return nil, nil
	}
	return sshtarget.NewRunner(sshtarget.RunnerConfig{
		Targets:         targets,
		RevokedHostKeys: revoked,
		CA:              sshtarget.NewCA(keys, cfg.SSH.SourceAddresses, o.Now),
		ConnectTimeout:  cfg.SSH.ConnectTimeout.D(),
		Limits: sshtarget.Limits{
			DefaultTimeout: cfg.Run.DefaultTimeout.D(),
			MaxTimeout:     cfg.Run.MaxTimeout.D(),
			MaxInteractive: cfg.Run.MaxInteractive.D(),
			MaxOutput:      int64(cfg.Run.MaxOutput),
		},
		Audit:  aw,
		Logger: log,
		Now:    o.Now,
		Dial:   o.SSHDial,
	})
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

	sshKeys, err := newSSHKeys(cfg, aw, log)
	if err != nil {
		return err
	}
	sshRunner, err := newSSHRunner(cfg, sshKeys, aw, log, o)
	if err != nil {
		return err
	}
	dc := decision.Config{
		Config: cfg, DB: db, Audit: aw, Asker: bot, Introspector: verifier, Now: o.Now, Logger: log,
	}
	if sshRunner != nil {
		// docs/08 D10: the host check before every SSH prompt. Set only
		// when non-nil, so that the interface is nil, not a nil runner.
		dc.Hosts = sshRunner
	}
	point, err := decision.New(ctx, dc)
	if err != nil {
		return err
	}
	defer point.Close()
	bot.SetResolver(point)

	targets := map[string]kubectl.Target{}
	for _, t := range cfg.Targets {
		if t.SSH != nil {
			continue
		}
		targets[t.Name] = kubectl.Target{
			Name: t.Name, InCluster: t.Kubernetes.InCluster,
			Server: t.Kubernetes.Server, CAFile: t.Kubernetes.CAFile, TokenFile: t.Kubernetes.TokenFile,
		}
	}
	kubeRunner, err := kubectl.NewRunner(kubectl.RunnerConfig{
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

	if sshRunner != nil {
		// Read once at start, only to say early what is wrong: runs and
		// the /hosts/ endpoints read the keys again on each use, and fail
		// closed then (docs/08 D1).
		if _, err := sshKeys.Load(); err != nil {
			log.Error("the SSH CA keys are unavailable; SSH runs and /hosts/ are refused until fixed", "detail", codes.DetailOf(err), "err", err)
		}
	}
	runners := runner.Runners{Kubernetes: kubeRunner, SSH: sshRunner}

	mcpSrv := mcpserver.New(mcpserver.Deps{Config: cfg, Point: point, Runner: runners, Audit: aw, Logger: log, Version: o.Version})

	mux := http.NewServeMux()
	mux.Handle("POST /mcp", verifier.Middleware(cfg.MCPURL(), mcpSrv.Handler()))
	mux.Handle("GET /stream", verifier.Middleware(cfg.StreamURL(), stream.NewHandler(point, runners, verifier, aw, log)))
	if sshRunner != nil {
		// docs/07 D16, docs/08 D4: setup.sh and trust, no authentication;
		// a host has no token.
		setup, err := hostsetup.New(cfg, sshhost.Script, sshKeys, aw, log)
		if err != nil {
			return err
		}
		mux.Handle(hostsetup.Prefix, setup)
	}
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
