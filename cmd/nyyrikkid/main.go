// Command nyyrikkid is the Nyyrikki server (docs/01 D2).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Tuhis/Nyyrikki/internal/config"
	"github.com/Tuhis/Nyyrikki/internal/kubectl"
	"github.com/Tuhis/Nyyrikki/internal/server"
	"github.com/Tuhis/Nyyrikki/internal/sshcacmd"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

func main() {
	// The runner re-executes this binary to run one kubectl request in its
	// own process (docs/04 D6).
	if len(os.Args) > 1 && os.Args[1] == "kubectl-child" {
		os.Exit(kubectl.ChildMain(os.Args[2:]))
	}
	// The SSH CA helper (docs/08 D2), an administrator's tool, and the
	// chart's CA hook and CronJobs (D16). Without a subcommand, the
	// server runs.
	if len(os.Args) > 1 && os.Args[1] == "ssh-ca" {
		os.Exit(sshcacmd.Main(os.Args[2:], sshcacmd.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Client: sshcacmd.InCluster}))
	}
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "/etc/nyyrikki/config.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	checkConfig := flag.Bool("check-config", false, "validate the configuration file and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return 0
	}
	// Server logs go to stderr; stdout carries only the audit stream
	// (docs/03 D5).
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("invalid configuration", "err", err)
		return 1
	}
	if *checkConfig {
		fmt.Fprintln(os.Stderr, "configuration is valid")
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, cfg, server.Options{Version: version, Logger: log, AuditOut: os.Stdout}); err != nil {
		log.Error("nyyrikkid stopped", "err", err)
		return 1
	}
	return 0
}
