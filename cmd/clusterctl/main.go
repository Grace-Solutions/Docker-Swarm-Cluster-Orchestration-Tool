package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"clusterctl/internal/config"
	"clusterctl/internal/deployer"
	"clusterctl/internal/logging"
)

func main() {
	if err := logging.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logging: %v\n", err)
		os.Exit(1)
	}
	defer logging.Sync()

	ctx := withSignals(context.Background())

	// Parse flags
	fs := flag.NewFlagSet("clusterctl", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to JSON configuration file (default: clusterctl.json in binary directory)")
	dryRun := fs.Bool("dry-run", false, "Validate configuration without deploying")
	showHelp := fs.Bool("help", false, "Show help message")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	if *showHelp {
		usage()
		return
	}

	runDeploy(ctx, *configPath, *dryRun)
}

func withSignals(parent context.Context) context.Context {
	ctx, _ := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	return ctx
}

func usage() {
	fmt.Fprint(os.Stderr, `clusterctl - Docker Swarm Cluster Orchestrator

Deploy and manage Docker Swarm clusters with GlusterFS storage via SSH.

Usage:
  clusterctl [flags]

Flags:
  -config string
        Path to JSON configuration file (default: clusterctl.json in binary directory)
  -dry-run
        Validate configuration without deploying
  -help
        Show this help message

Example:
  clusterctl -config cluster.json
  clusterctl -config cluster.json -dry-run

For configuration examples, see clusterctl.json.example

`)
}

func runDeploy(ctx context.Context, configPath string, dryRun bool) {
	log := logging.L().With("command", "deploy")

	// Load configuration
	log.Infow("loading configuration", "configPath", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Errorw("failed to load configuration", "err", err)
		os.Exit(1)
	}

	log.Infow("configuration loaded successfully",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"overlayProvider", cfg.GlobalSettings.OverlayProvider,
	)

	if dryRun {
		log.Infow("dry-run mode: configuration is valid")
		return
	}

	// Run deployment
	if err := deployer.Deploy(ctx, cfg); err != nil {
		log.Errorw("deployment failed", "err", err)
		os.Exit(1)
	}

	log.Infow("✅ Deployment completed successfully!")
}
