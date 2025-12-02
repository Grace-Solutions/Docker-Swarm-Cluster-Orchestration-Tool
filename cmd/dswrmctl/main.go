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

// Version information - set via ldflags during build
var (
	// Version is the build version in yyyy-MM-dd-HHmm format
	Version = "dev"
	// BuildTime is the build timestamp
	BuildTime = "unknown"
	// BinaryName is the name of the binary
	BinaryName = "dswrmctl"
)

func main() {
	if err := logging.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logging: %v\n", err)
		os.Exit(1)
	}
	defer logging.Sync()

	ctx := withSignals(context.Background())

	// Parse flags
	fs := flag.NewFlagSet(BinaryName, flag.ExitOnError)
	configPath := fs.String("configpath", "", "Path to JSON configuration file (default: dswrmctl.json in binary directory)")
	dryRun := fs.Bool("dry-run", false, "Validate configuration without deploying")
	showHelp := fs.Bool("help", false, "Show help message")
	showVersion := fs.Bool("version", false, "Show version information")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("%s version %s (built %s)\n", BinaryName, Version, BuildTime)
		return
	}

	if *showHelp {
		usage()
		return
	}

	run(ctx, *configPath, *dryRun)
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
	fmt.Fprintf(os.Stderr, `%s - Docker Swarm Cluster Orchestrator
Version: %s (built %s)

Deploy and manage Docker Swarm clusters with distributed storage (MicroCeph) via SSH.

Usage:
  %s [flags]

Flags:
  -configpath string
        Path to JSON configuration file (default: dswrmctl.json in binary directory)
  -dry-run
        Validate configuration without deploying
  -version
        Show version information
  -help
        Show this help message

Execution Mode:
  The execution mode is controlled by the configuration file:

  Deploy (default):
    "globalSettings.decommissioning.enabled": false

  Decommission/Teardown:
    "globalSettings.decommissioning.enabled": true
    "globalSettings.decommissioning.disconnectOverlays": true/false
    "globalSettings.decommissioning.removeStorage": true/false (defaults to forceRecreation)
    "globalSettings.decommissioning.removeDockerSwarm": true/false (default: true)

Examples:
  # Deploy cluster
  %s -configpath cluster.json

  # Validate configuration
  %s -configpath cluster.json -dry-run

For configuration examples, see dswrmctl.json.example

`, BinaryName, Version, BuildTime, BinaryName, BinaryName, BinaryName)
}

func run(ctx context.Context, configPath string, dryRun bool) {
	log := logging.L()

	// Load configuration
	log.Infow("loading configuration", "configPath", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Errorw("failed to load configuration")
		fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
		os.Exit(1)
	}

	ds := cfg.GetDistributedStorage()
	decom := cfg.GetDecommissioning()

	log.Infow("configuration loaded successfully",
		"configFile", cfg.ConfigPath,
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"overlayProvider", cfg.GlobalSettings.OverlayProvider,
		"decommissioning", decom.Enabled,
	)

	if dryRun {
		log.Infow("dry-run mode: configuration is valid")
		return
	}

	// Check execution mode from config
	if decom.Enabled {
		// Decommissioning mode
		log = log.With("command", "decommission")
		log.Infow("decommissioning mode enabled",
			"disconnectOverlays", decom.DisconnectOverlays,
			"removeStorage", decom.ShouldRemoveStorage(ds),
			"removeDockerSwarm", decom.ShouldRemoveDockerSwarm(),
		)

		if err := deployer.Teardown(ctx, cfg, decom.DisconnectOverlays); err != nil {
			log.Errorw("decommissioning failed")
			fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
			os.Exit(1)
		}

		log.Infow("✅ Decommissioning completed successfully!")
	} else {
		// Deployment mode
		log = log.With("command", "deploy")
		log.Infow("deployment mode",
			"preScripts", len(cfg.GlobalSettings.PreScripts),
			"postScripts", len(cfg.GlobalSettings.PostScripts),
			"storageEnabled", ds.Enabled,
		)

		if err := deployer.Deploy(ctx, cfg); err != nil {
			log.Errorw("deployment failed")
			fmt.Fprintf(os.Stderr, "\nError:\n  %s\n\n", formatError(err))
			os.Exit(1)
		}

		log.Infow("✅ Deployment completed successfully!")
	}
}
