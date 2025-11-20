package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"clusterctl/internal/controller"
	"clusterctl/internal/deps"
	"clusterctl/internal/logging"
	"clusterctl/internal/nodeagent"
	"clusterctl/internal/swarm"
)

const (
	defaultListenAddr = "0.0.0.0:7000"
	defaultStateDir   = "/data/GlusterFS/0001/orchestration"
)

func main() {
	if err := logging.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialise logging: %v\n", err)
		os.Exit(1)
	}
	defer logging.Sync()

	ctx := withSignals(context.Background())

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "master":
		runMaster(ctx, args)
	case "node":
		runNode(ctx, args)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
}

func withSignals(parent context.Context) context.Context {
	ctx, _ := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	return ctx
}

func usage() {
	fmt.Fprint(os.Stderr, `clusterctl - Swarm cluster orchestrator

Usage:
  clusterctl master init [flags]
  clusterctl master serve [flags]
  clusterctl master reset [flags]
  clusterctl node join [flags]
  clusterctl node reset [flags]

`)
}

func runMaster(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "missing master subcommand (init|serve|reset)")
		os.Exit(2)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "init":
		masterInit(ctx, subArgs)
	case "serve":
		masterServe(ctx, subArgs)
	case "reset":
		masterReset(ctx, subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown master subcommand %q\n", sub)
		os.Exit(2)
	}
}

func masterInit(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("master init", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "controller state directory")
	enableGluster := fs.Bool("enable-glusterfs", false, "prepare GlusterFS brick and paths")
	primary := fs.Bool("primary-master", false, "bootstrap this node as the initial Swarm manager and start the controller")
	listen := fs.String("listen", defaultListenAddr, "controller listen address when --primary-master is set")
	advertise := fs.String("advertise-addr", "", "swarm advertise address for this master (and controller advertise-addr)")
	minManagers := fs.Int("min-managers", 0, "minimum managers before ready when --primary-master is set")
	minWorkers := fs.Int("min-workers", 0, "minimum workers before ready when --primary-master is set")
	waitForMinimum := fs.Bool("wait-for-minimum", false, "gate responses until minimum nodes reached when --primary-master is set")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	opts := controller.MasterInitOptions{
		StateDir:      *stateDir,
		EnableGluster: *enableGluster,
	}

	if err := controller.MasterInit(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "master init failed: %v\n", err)
		os.Exit(1)
	}

	if !*primary {
		return
	}

	if err := deps.EnsureDockerWithCompose(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "master init (primary-master) docker installation failed: %v\n", err)
		os.Exit(1)
	}

	if err := swarm.Init(ctx, *advertise); err != nil {
		fmt.Fprintf(os.Stderr, "master init (primary-master) swarm init failed: %v\n", err)
		os.Exit(1)
	}

	serveOpts := controller.ServeOptions{
		ListenAddr:     *listen,
		StateDir:       *stateDir,
		AdvertiseAddr:  *advertise,
		MinManagers:    *minManagers,
		MinWorkers:     *minWorkers,
		WaitForMinimum: *waitForMinimum,
	}

	if err := controller.Serve(ctx, serveOpts); err != nil {
		fmt.Fprintf(os.Stderr, "master serve failed: %v\n", err)
		os.Exit(1)
	}
}

func masterServe(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("master serve", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "controller state directory")
	listen := fs.String("listen", defaultListenAddr, "listen address")
	advertise := fs.String("advertise-addr", "", "swarm advertise address")
	minManagers := fs.Int("min-managers", 0, "minimum managers before ready")
	minWorkers := fs.Int("min-workers", 0, "minimum workers before ready")
	waitForMinimum := fs.Bool("wait-for-minimum", false, "gate responses until minimum nodes reached")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	opts := controller.ServeOptions{
		ListenAddr:     *listen,
		StateDir:       *stateDir,
		AdvertiseAddr:  *advertise,
		MinManagers:    *minManagers,
		MinWorkers:     *minWorkers,
		WaitForMinimum: *waitForMinimum,
	}

	if err := controller.Serve(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "master serve failed: %v\n", err)
		os.Exit(1)
	}
}

func masterReset(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("master reset", flag.ExitOnError)
	stateDir := fs.String("state-dir", defaultStateDir, "controller state directory")
	cleanup := fs.Bool("cleanup-state-dir", false, "also remove the controller state directory and its contents")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	opts := controller.MasterResetOptions{
		StateDir:        *stateDir,
		CleanupStateDir: *cleanup,
	}

	if err := controller.MasterReset(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "master reset failed: %v\n", err)
		os.Exit(1)
	}
}


func runNode(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "missing node subcommand (join|reset)")
		os.Exit(2)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "join":
		nodeJoin(ctx, subArgs)
	case "reset":
		nodeReset(ctx, subArgs)
	default:
		fmt.Fprintf(os.Stderr, "unknown node subcommand %q\n", sub)
		os.Exit(2)
	}
}

func nodeJoin(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("node join", flag.ExitOnError)
	master := fs.String("master", "", "controller address (host:port)")
	role := fs.String("role", "worker", "node role (manager|worker)")
	ipOverride := fs.String("ip", "", "override detected IP")
	hostnameOverride := fs.String("hostname", "", "override detected hostname")
	overlayProvider := fs.String("overlay-provider", "none", "overlay provider (netbird|tailscale|wireguard|none)")
	overlayConfig := fs.String("overlay-config", "", "overlay provider config string (e.g. setup/auth key for netbird/tailscale)")
	enableGluster := fs.Bool("enable-glusterfs", false, "enable GlusterFS on this node")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	opts := nodeagent.JoinOptions{
		MasterAddr:       *master,
		Role:             *role,
		IPOverride:       *ipOverride,
		HostnameOverride: *hostnameOverride,
		OverlayProvider:  *overlayProvider,
		OverlayConfig:    *overlayConfig,
		EnableGluster:    *enableGluster,
	}

	if err := nodeagent.Join(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "node join failed: %v\n", err)
		os.Exit(1)
	}
}

func nodeReset(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("node reset", flag.ExitOnError)
	master := fs.String("master", "", "controller address (host:port), required when --deregister is set")
	role := fs.String("role", "worker", "node role (manager|worker) for deregistration")
	hostnameOverride := fs.String("hostname", "", "override detected hostname for deregistration")
	overlayProvider := fs.String("overlay-provider", "none", "overlay provider (netbird|tailscale|wireguard|none)")
	overlayConfig := fs.String("overlay-config", "", "overlay provider config string (e.g. setup/auth key for netbird/tailscale)")
	cleanupOverlay := fs.Bool("cleanup-overlay", false, "tear down overlay provider on this node")
	glusterMount := fs.String("gluster-mount", defaultStateDir, "GlusterFS mount point to unmount when --cleanup-glusterfs is set")
	cleanupGluster := fs.Bool("cleanup-glusterfs", false, "unmount GlusterFS on this node")
	deregister := fs.Bool("deregister", false, "deregister this node from the controller")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if *deregister && *master == "" {
		fmt.Fprintln(os.Stderr, "--master is required when --deregister is set")
		os.Exit(2)
	}

	opts := nodeagent.ResetOptions{
		MasterAddr:       *master,
		Role:             *role,
		HostnameOverride: *hostnameOverride,
		OverlayProvider:  *overlayProvider,
		OverlayConfig:    *overlayConfig,
		GlusterMount:     *glusterMount,
		Deregister:       *deregister,
		CleanupOverlay:   *cleanupOverlay,
		CleanupGlusterfs: *cleanupGluster,
	}

	if err := nodeagent.Reset(ctx, opts); err != nil {
		fmt.Fprintf(os.Stderr, "node reset failed: %v\n", err)
		os.Exit(1)
	}
}


