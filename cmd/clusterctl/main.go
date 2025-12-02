package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
		runTeardown(ctx, *configPath, *removeOverlays)
	} else {
		runDeploy(ctx, *configPath, *dryRun)
	}
}

func withSignals(parent context.Context) context.Context {
	ctx, _ := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	return ctx
}

// formatError formats a nested error with each level on a separate line
func formatError(err error) string {
	if err == nil {
		return ""
	}

	var lines []string
	current := err

	for current != nil {
		// Get the error message
		msg := current.Error()

		// Try to unwrap
		unwrapped := errors.Unwrap(current)

		if unwrapped != nil {
			// Remove the wrapped part from the message
			unwrappedMsg := unwrapped.Error()
			if strings.HasSuffix(msg, ": "+unwrappedMsg) {
				msg = strings.TrimSuffix(msg, ": "+unwrappedMsg)
			}
		}

		lines = append(lines, msg)
		current = unwrapped
	}

	// Format with indentation
	var formatted strings.Builder
	for i, line := range lines {
		if i > 0 {
			formatted.WriteString("\n  ")
			formatted.WriteString(strings.Repeat("→ ", i))
		}
		formatted.WriteString(line)
	}

	return formatted.String()
}

func usage() {
	fmt.Fprint(os.Stderr, `clusterctl - Docker Swarm Cluster Orchestrator

Deploy and manage Docker Swarm clusters with distributed storage (MicroCeph) via SSH.

Usage:
  clusterctl [flags]

Flags:
  -config string
        Path to JSON configuration file (default: clusterctl.json in binary directory)
  -dry-run
        Validate configuration without deploying
  -teardown
        Teardown/reset the cluster (removes services, swarm, optionally networks and storage)
  -remove-overlays
        Remove overlay networks during teardown (may break connectivity, use with caution)
  -help
        Show this help message

Notes:
  Distributed storage teardown is controlled by the "globalSettings.distributedStorage.forceRecreation"
  setting in the configuration file. Set it to true to allow storage removal during teardown.

Examples:
  # Deploy cluster
  clusterctl -config cluster.json

  # Validate configuration
  clusterctl -config cluster.json -dry-run

  # Teardown cluster (honors distributedStorage.forceRecreation setting)
  clusterctl -config cluster.json -teardown

  # Full teardown (removes overlay networks as well)
  clusterctl -config cluster.json -teardown -remove-overlays

For configuration examples, see clusterctl.json.example

`)
}

func runDeploy(ctx context.Context, configPath string, dryRun bool) {
	log := logging.L().With("command", "deploy")

	// Load configuration
	log.Infow("loading configuration", "configPath", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Errorw("failed to load configuration")
		fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
		os.Exit(1)
	}

	log.Infow("configuration loaded successfully",
		"configFile", cfg.ConfigPath,
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"overlayProvider", cfg.GlobalSettings.OverlayProvider,
		"preScripts", len(cfg.GlobalSettings.PreScripts),
		"postScripts", len(cfg.GlobalSettings.PostScripts),
	)

	if dryRun {
		log.Infow("dry-run mode: configuration is valid")
		return
	}

	// Run deployment
	if err := deployer.Deploy(ctx, cfg); err != nil {
		log.Errorw("deployment failed")
		fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
		os.Exit(1)
	}

	log.Infow("✅ Deployment completed successfully!")
}

func runTeardown(ctx context.Context, configPath string, removeOverlays bool) {
	log := logging.L().With("command", "teardown")

	// Load configuration
	log.Infow("loading configuration", "configPath", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Errorw("failed to load configuration")
		fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
		os.Exit(1)
	}

	ds := cfg.GetDistributedStorage()
	log.Infow("configuration loaded successfully",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"removeOverlays", removeOverlays,
		"storageEnabled", ds.Enabled,
		"storageForceRecreation", ds.ForceRecreation,
	)

	// Run teardown
	if err := deployer.Teardown(ctx, cfg, removeOverlays); err != nil {
		log.Errorw("teardown failed")
		fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
		os.Exit(1)
	}

	log.Infow("teardown completed successfully")
}
