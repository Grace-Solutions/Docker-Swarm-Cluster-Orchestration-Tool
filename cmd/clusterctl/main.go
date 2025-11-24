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
	teardown := fs.Bool("teardown", false, "Teardown/reset the cluster")
	removeOverlays := fs.Bool("remove-overlays", false, "Remove overlay networks during teardown (may break connectivity)")
	removeGlusterData := fs.Bool("remove-gluster-data", false, "Remove GlusterFS data during teardown")
	showHelp := fs.Bool("help", false, "Show help message")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	if *showHelp {
		usage()
		return
	}

	if *teardown {
		runTeardown(ctx, *configPath, *removeOverlays, *removeGlusterData)
	} else {
		runDeploy(ctx, *configPath, *dryRun)
	}
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
  -teardown
        Teardown/reset the cluster (removes services, swarm, optionally networks and data)
  -remove-overlays
        Remove overlay networks during teardown (may break connectivity, use with caution)
  -remove-gluster-data
        Remove GlusterFS data during teardown (WARNING: deletes all data)
  -help
        Show this help message

Examples:
  # Deploy cluster
  clusterctl -config cluster.json

  # Validate configuration
  clusterctl -config cluster.json -dry-run

  # Teardown cluster (keeps networks and data)
  clusterctl -config cluster.json -teardown

  # Full teardown (removes everything including data)
  clusterctl -config cluster.json -teardown -remove-overlays -remove-gluster-data

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

func runTeardown(ctx context.Context, configPath string, removeOverlays, removeGlusterData bool) {
	log := logging.L().With("command", "teardown")

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
		"removeOverlays", removeOverlays,
		"removeGlusterData", removeGlusterData,
	)

	// Run teardown
	if err := deployer.Teardown(ctx, cfg, removeOverlays, removeGlusterData); err != nil {
		log.Errorw("teardown failed", "err", err)
		os.Exit(1)
	}

	log.Infow("teardown completed successfully")
}
