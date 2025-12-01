package deployer

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"clusterctl/internal/config"
	"clusterctl/internal/geolocation"
	"clusterctl/internal/logging"
	"clusterctl/internal/orchestrator"
	"clusterctl/internal/retry"
	"clusterctl/internal/services"
	"clusterctl/internal/ssh"
	"clusterctl/internal/sshkeys"
	"clusterctl/internal/swarm"
)

// formatNodeMessage formats a log message with node identifier.
// If newHostname is blank, returns: "prefix [hostname] message"
// If newHostname is set, returns: "prefix [hostname - [newHostname]] message"
// Example: formatNodeMessage("→", "192.168.1.1", "node1", "installing Docker")
//   -> "→ [192.168.1.1 - [node1]] installing Docker"
func formatNodeMessage(prefix, hostname, newHostname, message string) string {
	if newHostname == "" {
		return fmt.Sprintf("%s [%s] %s", prefix, hostname, message)
	}
	return fmt.Sprintf("%s [%s - [%s]] %s", prefix, hostname, newHostname, message)
}

// Deploy orchestrates the complete cluster deployment from the configuration.
func Deploy(ctx context.Context, cfg *config.Config) error {
	log := logging.L().With("component", "deployer")

	// Track overall deployment metrics
	startTime := time.Now()
	var phasesCompleted int
	var phasesFailed int

	// Count enabled/disabled nodes
	enabledNodes := getEnabledNodes(cfg)
	disabledCount := len(cfg.Nodes) - len(enabledNodes)

	log.Infow("🚀 Starting cluster deployment",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"totalNodes", len(cfg.Nodes),
		"enabledNodes", len(enabledNodes),
		"disabledNodes", disabledCount,
		"startTime", startTime.Format(time.RFC3339),
	)

	if len(enabledNodes) == 0 {
		return fmt.Errorf("no enabled nodes found in configuration")
	}

	// Phase 1: Prepare SSH keys and connection pool
	log.Infow("Phase 1: Preparing SSH keys and connections")
	keyPair, err := prepareSSHKeys(cfg)
	if err != nil {
		return fmt.Errorf("failed to prepare SSH keys: %w", err)
	}

	sshPool, err := createSSHPool(cfg, keyPair)
	if err != nil {
		return fmt.Errorf("failed to create SSH pool: %w", err)
	}
	log.Infow("✅ SSH keys and connection pool ready")

	// Phase 2: Set hostnames if configured
	log.Infow("Phase 2: Setting hostnames")
	if err := setHostnames(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to set hostnames: %w", err)
	}
	log.Infow("✅ Hostnames configured")

	// Phase 2.5: Set root password if configured
	if cfg.GlobalSettings.SetRootPassword != "" {
		log.Infow("Phase 2.5: Setting root password on all nodes")
		if err := setRootPassword(ctx, cfg, sshPool); err != nil {
			return fmt.Errorf("failed to set root password: %w", err)
		}
		log.Infow("✅ Root password set on all nodes")
	} else {
		log.Infow("Phase 2.5: Skipping root password (not configured)")
	}

	// Phase 3: Execute pre-deployment scripts
	log.Infow("Phase 3: Executing pre-deployment scripts")
	if err := executeScripts(ctx, cfg, sshPool, cfg.GlobalSettings.PreScripts, "pre"); err != nil {
		return fmt.Errorf("failed to execute pre-deployment scripts: %w", err)
	}
	log.Infow("✅ Pre-deployment scripts complete")

	// Phase 4: Install dependencies on all nodes
	log.Infow("Phase 4: Installing dependencies on all nodes")
	if err := installDependencies(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}
	log.Infow("✅ Dependencies installed")

	// Phase 5: Configure overlay network on all nodes
	log.Infow("Phase 5: Configuring overlay network")
	if err := configureOverlay(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to configure overlay network: %w", err)
	}
	log.Infow("✅ Overlay network configured")

	// Phase 6: Setup GlusterFS if enabled
	sshGlusterWorkers := getGlusterWorkers(cfg)
	if len(sshGlusterWorkers) > 0 {
		log.Infow("Phase 6: Setting up GlusterFS", "workers", len(sshGlusterWorkers), "diskManagement", cfg.GlobalSettings.GlusterDiskManagement, "forceRecreate", cfg.GlobalSettings.GlusterForceRecreate)

		// If force recreate is enabled, teardown existing GlusterFS cluster first
		if cfg.GlobalSettings.GlusterForceRecreate {
			log.Infow("→ Force recreate enabled, tearing down existing GlusterFS cluster")
			if err := teardownGlusterFS(ctx, sshPool, sshGlusterWorkers, cfg.GlobalSettings.GlusterVolume, cfg.GlobalSettings.GlusterMount, cfg.GlobalSettings.GlusterBrick); err != nil {
				log.Warnw("⚠️ GlusterFS teardown had errors (continuing anyway)", "error", err)
			} else {
				log.Infow("✓ GlusterFS teardown complete")
			}
		}

		// Get overlay FQDNs for GlusterFS if overlay provider is configured
		glusterFQDNs, err := getGlusterHostnames(ctx, sshPool, cfg, sshGlusterWorkers)
		if err != nil {
			return fmt.Errorf("failed to get GlusterFS hostnames: %w", err)
		}
		log.Infow("→ Using FQDNs for GlusterFS", "fqdns", glusterFQDNs, "overlayProvider", cfg.GlobalSettings.OverlayProvider)

		validWorkers, err := orchestrator.GlusterSetup(ctx, sshPool, sshGlusterWorkers, glusterFQDNs,
			cfg.GlobalSettings.GlusterVolume,
			cfg.GlobalSettings.GlusterMount,
			cfg.GlobalSettings.GlusterBrick,
			cfg.GlobalSettings.GlusterDiskManagement)
		if err != nil {
			return fmt.Errorf("failed to setup GlusterFS: %w", err)
		}

		if validWorkers == nil || len(validWorkers) == 0 {
			log.Warnw("⚠️ GlusterFS setup skipped - no workers with available disks")
		} else {
			log.Infow("✅ GlusterFS setup complete", "activeWorkers", len(validWorkers), "totalWorkers", len(sshGlusterWorkers))
		}
	} else {
		log.Infow("Phase 6: Skipping GlusterFS (no workers with glusterEnabled)")
	}

	// Phase 7: Setup Docker Swarm
	log.Infow("Phase 7: Setting up Docker Swarm")
	sshManagers, sshWorkers := categorizeNodes(cfg)
	if len(sshManagers) == 0 {
		return fmt.Errorf("no manager nodes found")
	}

	// Get overlay info for all nodes if overlay provider is configured
	allSSHNodes := append(sshManagers, sshWorkers...)
	overlayInfoMap := make(map[string]OverlayInfo)

	provider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.OverlayProvider))
	if provider != "" && provider != "none" {
		log.Infow("→ Retrieving overlay info for Docker Swarm", "overlayProvider", provider, "nodes", len(allSSHNodes))
		for _, sshHost := range allSSHNodes {
			overlayInfo, err := getOverlayInfoForNode(ctx, sshPool, sshHost, provider)
			if err != nil {
				log.Warnw("failed to get overlay info, using SSH hostname", "sshHost", sshHost, "error", err)
				overlayInfoMap[sshHost] = OverlayInfo{FQDN: sshHost, IP: sshHost}
			} else {
				overlayInfoMap[sshHost] = overlayInfo
				log.Infow("→ overlay info", "sshHost", sshHost, "fqdn", overlayInfo.FQDN, "ip", overlayInfo.IP, "interface", overlayInfo.Interface)
			}
		}
	} else {
		// No overlay provider, use SSH hostnames directly
		for _, sshHost := range allSSHNodes {
			overlayInfoMap[sshHost] = OverlayInfo{FQDN: sshHost, IP: sshHost}
		}
	}

	// Build advertise addresses: prefer interface:port, fallback to IP:port
	// This makes the cluster resilient to IP changes
	managerAdvertiseAddrs := make([]string, len(sshManagers))
	for i, sshHost := range sshManagers {
		info := overlayInfoMap[sshHost]
		if info.Interface != "" {
			managerAdvertiseAddrs[i] = info.Interface + ":2377"
		} else {
			managerAdvertiseAddrs[i] = info.IP + ":2377"
		}
	}
	workerAdvertiseAddrs := make([]string, len(sshWorkers))
	for i, sshHost := range sshWorkers {
		info := overlayInfoMap[sshHost]
		if info.Interface != "" {
			workerAdvertiseAddrs[i] = info.Interface + ":2377"
		} else {
			workerAdvertiseAddrs[i] = info.IP + ":2377"
		}
	}

	primaryMaster := sshManagers[0]                              // SSH hostname for SSH operations
	primaryMasterAdvertiseAddr := managerAdvertiseAddrs[0]       // Interface:port or IP:port for Swarm advertise address

	log.Infow("→ Using advertise addresses for Docker Swarm", "primaryMasterAddr", primaryMasterAdvertiseAddr, "managerAddrs", managerAdvertiseAddrs, "workerAddrs", workerAdvertiseAddrs, "overlayProvider", provider)

	if err := orchestrator.SwarmSetup(ctx, sshPool, sshManagers, sshWorkers, managerAdvertiseAddrs, workerAdvertiseAddrs, primaryMasterAdvertiseAddr); err != nil {
		return fmt.Errorf("failed to setup Docker Swarm: %w", err)
	}
	log.Infow("✅ Docker Swarm setup complete", "primaryMasterAddr", primaryMasterAdvertiseAddr)

	// Phase 8: Detect geolocation and apply node labels
	log.Infow("Phase 8: Detecting geolocation and applying node labels")
	if err := applyNodeLabels(ctx, cfg, sshPool, primaryMaster); err != nil {
		return fmt.Errorf("failed to apply node labels: %w", err)
	}
	log.Infow("✅ Node labels applied")

	// Phase 9: Deploy services from YAML files
	log.Infow("Phase 9: Deploying services")
	metrics, err := services.DeployServices(ctx, sshPool, primaryMaster, cfg.GlobalSettings.ServicesDir, cfg.GlobalSettings.GlusterMount)
	if err != nil {
		log.Warnw("service deployment encountered errors", "error", err)
	}
	if metrics != nil {
		log.Infow("✅ Service deployment complete",
			"found", metrics.TotalFound,
			"enabled", metrics.TotalEnabled,
			"disabled", metrics.TotalDisabled,
			"success", metrics.TotalSuccess,
			"failed", metrics.TotalFailed,
			"duration", metrics.Duration.String(),
		)
	}

	// Phase 10: Execute post-deployment scripts
	log.Infow("Phase 10: Executing post-deployment scripts")
	if err := executeScripts(ctx, cfg, sshPool, cfg.GlobalSettings.PostScripts, "post"); err != nil {
		return fmt.Errorf("failed to execute post-deployment scripts: %w", err)
	}
	log.Infow("✅ Post-deployment scripts complete")

	// Phase 11: Reboot nodes if configured
	log.Infow("Phase 11: Rebooting nodes if configured")
	if err := rebootNodes(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to reboot nodes: %w", err)
	}
	log.Infow("✅ Reboot initiated for configured nodes")

	// Phase 12: Remove SSH public key from nodes if configured
	if cfg.GlobalSettings.RemoveSSHPublicKeyOnCompletion {
		log.Infow("Phase 12: Removing SSH public key from nodes on completion")
		if err := removeSSHPublicKeyFromNodes(ctx, cfg, sshPool, keyPair); err != nil {
			log.Warnw("failed to remove SSH public key from nodes", "error", err)
		} else {
			log.Infow("✅ SSH public key removed from nodes")
		}
		log.Infow("ℹ️  Local SSH key pair kept in sshkeys/ directory for future use")
	} else {
		log.Infow("Phase 12: Skipping SSH public key removal (removeSSHPublicKeyOnCompletion=false)")
	}

	// Calculate final metrics
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	log.Infow("🎉 Cluster deployment complete!",
		"totalDuration", duration.String(),
		"phasesCompleted", phasesCompleted,
		"phasesFailed", phasesFailed,
		"startTime", startTime.Format(time.RFC3339),
		"endTime", endTime.Format(time.RFC3339),
	)
	return nil
}

// Teardown orchestrates the complete cluster teardown from the configuration.
func Teardown(ctx context.Context, cfg *config.Config, removeOverlays, removeGlusterData bool) error {
	log := logging.L().With("component", "teardown")

	startTime := time.Now()

	log.Infow("🔥 Starting cluster teardown",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"removeOverlays", removeOverlays,
		"removeGlusterData", removeGlusterData,
		"startTime", startTime.Format(time.RFC3339),
	)

	// Phase 1: Prepare SSH keys and connection pool
	log.Infow("Phase 1: Preparing SSH connections")
	keyPair, err := prepareSSHKeys(cfg)
	if err != nil {
		return fmt.Errorf("failed to prepare SSH keys: %w", err)
	}

	sshPool, err := createSSHPool(cfg, keyPair)
	if err != nil {
		return fmt.Errorf("failed to create SSH pool: %w", err)
	}
	log.Infow("✅ SSH connection pool ready")

	// Get node lists
	managers, workers := categorizeNodes(cfg)
	allNodes := append(managers, workers...)
	primaryManager := managers[0]

	// Phase 2: Remove all deployed stacks
	log.Infow("Phase 2: Removing deployed stacks")
	if err := removeStacks(ctx, sshPool, primaryManager); err != nil {
		log.Warnw("failed to remove stacks", "error", err)
	} else {
		log.Infow("✅ Stacks removed")
	}

	// Phase 3: Leave swarm on all nodes
	log.Infow("Phase 3: Leaving Docker Swarm")
	if err := leaveSwarm(ctx, sshPool, allNodes); err != nil {
		log.Warnw("failed to leave swarm", "error", err)
	} else {
		log.Infow("✅ Swarm left on all nodes")
	}

	// Phase 4: Unmount GlusterFS volumes on managers
	if len(managers) > 0 {
		log.Infow("Phase 4: Unmounting GlusterFS volumes on managers")
		if err := unmountGlusterFS(ctx, sshPool, managers, cfg); err != nil {
			log.Warnw("failed to unmount GlusterFS", "error", err)
		} else {
			log.Infow("✅ GlusterFS unmounted on managers")
		}
	}

	// Phase 5: Stop and delete GlusterFS volume on workers
	if len(workers) > 0 {
		log.Infow("Phase 5: Stopping and deleting GlusterFS volume")
		if err := deleteGlusterVolume(ctx, sshPool, workers, cfg); err != nil {
			log.Warnw("failed to delete GlusterFS volume", "error", err)
		} else {
			log.Infow("✅ GlusterFS volume deleted")
		}
	}

	// Phase 6: Remove GlusterFS data if requested
	if removeGlusterData && len(workers) > 0 {
		log.Infow("Phase 6: Removing GlusterFS data directories")
		if err := removeGlusterData_func(ctx, sshPool, workers, cfg); err != nil {
			log.Warnw("failed to remove GlusterFS data", "error", err)
		} else {
			log.Infow("✅ GlusterFS data removed")
		}
	} else {
		log.Infow("Phase 6: Skipping GlusterFS data removal (use -remove-gluster-data to remove)")
	}

	// Phase 7: Remove overlay networks if requested
	if removeOverlays {
		log.Infow("Phase 7: Removing overlay networks")
		if err := removeOverlayNetworks(ctx, sshPool, primaryManager); err != nil {
			log.Warnw("failed to remove overlay networks", "error", err)
		} else {
			log.Infow("✅ Overlay networks removed")
		}
	} else {
		log.Infow("Phase 7: Skipping overlay network removal (use -remove-overlays to remove)")
	}

	// Calculate final metrics
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	log.Infow("🎉 Cluster teardown complete!",
		"totalDuration", duration.String(),
		"startTime", startTime.Format(time.RFC3339),
		"endTime", endTime.Format(time.RFC3339),
	)
	return nil
}

// prepareSSHKeys ensures SSH key pair exists and installs public keys on nodes that need it.
func prepareSSHKeys(cfg *config.Config) (*sshkeys.KeyPair, error) {
	log := logging.L().With("component", "ssh-keys")

	enabledNodes := getEnabledNodes(cfg)

	// Always generate SSH key pair for future passwordless access
	// Even if nodes currently use password auth, we'll install the key for subsequent operations
	keyPair, err := sshkeys.EnsureKeyPair("")
	if err != nil {
		return nil, fmt.Errorf("failed to ensure SSH key pair: %w", err)
	}

	log.Infow("SSH key pair ready", "privateKey", keyPair.PrivateKeyPath)

	// Install public key on enabled nodes that don't already use automatic key pair
	// (these nodes will use password/privateKeyPath for initial connection, then key for future)
	ctx := context.Background()

	// Count nodes that need public key installation
	var nodesToInstall []config.NodeConfig
	for _, node := range enabledNodes {
		if !node.UseSSHAutomaticKeyPair {
			nodesToInstall = append(nodesToInstall, node)
		}
	}

	if len(nodesToInstall) > 0 {
		log.Infow("installing public key on nodes using password/key auth", "totalNodes", len(nodesToInstall))
	}

	for i, node := range nodesToInstall {
		nodeNum := i + 1
		authMethod := "password"
		if node.PrivateKeyPath != "" {
			authMethod = "private-key"
		}

		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(nodesToInstall)),
			"hostname", node.Hostname,
			"user", node.Username,
			"port", node.SSHPort,
			"authMethod", authMethod,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "installing public key for future automatic authentication"))

		authConfig := ssh.AuthConfig{
			Username:       node.Username,
			Password:       node.Password,
			PrivateKeyPath: node.PrivateKeyPath,
			Port:           node.SSHPort,
		}

		tempPool := ssh.NewPool(map[string]ssh.AuthConfig{
			node.Hostname: authConfig,
		})

		// Install public key
		installCmd := fmt.Sprintf(
			"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "+
				"echo '%s' >> ~/.ssh/authorized_keys && "+
				"chmod 600 ~/.ssh/authorized_keys && "+
				"sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys",
			strings.TrimSpace(keyPair.PublicKey),
		)

		if _, stderr, err := tempPool.Run(ctx, node.Hostname, installCmd); err != nil {
			nodeLog.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "failed to install public key"), "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "public key installed successfully"))
		}
	}

	return keyPair, nil
}

// createSSHPool creates an SSH connection pool from the configuration.
func createSSHPool(cfg *config.Config, keyPair *sshkeys.KeyPair) (*ssh.Pool, error) {
	log := logging.L().With("phase", "ssh-pool")
	authConfigs := make(map[string]ssh.AuthConfig)

	enabledNodes := getEnabledNodes(cfg)
	log.Infow("creating SSH connection pool", "totalNodes", len(enabledNodes))

	// Count auth methods
	var autoKeyCount, privateKeyCount, passwordCount int

	for i, node := range enabledNodes {
		nodeNum := i + 1
		authMethod := "password"
		if node.UseSSHAutomaticKeyPair && keyPair != nil {
			authMethod = "automatic-keypair"
			autoKeyCount++
		} else if node.PrivateKeyPath != "" {
			authMethod = "private-key"
			privateKeyCount++
		} else {
			passwordCount++
		}

		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(enabledNodes)),
			"hostname", node.Hostname,
			"user", node.Username,
			"port", node.SSHPort,
			"authMethod", authMethod,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "configuring SSH connection"))

		authConfig := ssh.AuthConfig{
			Username: node.Username,
			Port:     node.SSHPort,
		}

		if node.UseSSHAutomaticKeyPair && keyPair != nil {
			// Use automatic key pair with password if available
			authConfig.PrivateKeyPath = keyPair.PrivateKeyPath
			authConfig.PrivateKeyPassword = keyPair.Password
		} else {
			// Use configured credentials
			authConfig.Password = node.Password
			authConfig.PrivateKeyPath = node.PrivateKeyPath
			// Note: User-provided private keys don't use the auto-generated password
		}

		authConfigs[node.Hostname] = authConfig
	}

	// Log summary once instead of per-node
	if autoKeyCount > 0 {
		log.Infow("✓ using automatic SSH key pair", "nodes", autoKeyCount, "keyPath", keyPair.PrivateKeyPath)
	}
	if privateKeyCount > 0 {
		log.Infow("✓ using configured private keys", "nodes", privateKeyCount)
	}
	if passwordCount > 0 {
		log.Infow("✓ using password authentication", "nodes", passwordCount)
	}

	log.Infow("SSH connection pool configured", "totalNodes", len(enabledNodes))
	return ssh.NewPool(authConfigs), nil
}

// installDependencies installs required dependencies on all enabled nodes.
func installDependencies(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "dependencies")

	enabledNodes := getEnabledNodes(cfg)
	log.Infow("installing dependencies on all nodes", "totalNodes", len(enabledNodes))

	for i, node := range enabledNodes {
		nodeNum := i + 1

		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(enabledNodes)),
			"hostname", node.Hostname,
			"role", node.Role,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "starting dependency installation"))

		// Install Docker
		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "installing Docker"))
		if err := installDocker(ctx, sshPool, node.Hostname); err != nil {
			return fmt.Errorf("failed to install Docker on %s: %w", node.Hostname, err)
		}
		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "Docker installed"))

		// Install GlusterFS if needed
		if node.GlusterEnabled {
			nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "installing GlusterFS server"))
			if err := installGlusterFS(ctx, sshPool, node.Hostname, true); err != nil {
				return fmt.Errorf("failed to install GlusterFS on %s: %w", node.Hostname, err)
			}
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "GlusterFS server installed"))
		} else if node.Role == "manager" && len(getGlusterWorkers(cfg)) > 0 {
			// Managers need GlusterFS client if any workers have GlusterFS
			nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "installing GlusterFS client"))
			if err := installGlusterFS(ctx, sshPool, node.Hostname, false); err != nil {
				return fmt.Errorf("failed to install GlusterFS client on %s: %w", node.Hostname, err)
			}
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "GlusterFS client installed"))
		}

		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "all dependencies installed"))
	}

	return nil
}

// installDocker installs Docker on a node via SSH.
func installDocker(ctx context.Context, sshPool *ssh.Pool, host string) error {
	// Check if Docker is already installed
	_, _, err := sshPool.Run(ctx, host, "docker --version")
	if err == nil {
		logging.L().Infow("Docker already installed", "node", host)
		return nil
	}

	// Install Docker with retry logic (network downloads can be flaky)
	retryCfg := retry.PackageManagerConfig(fmt.Sprintf("install-docker-%s", host))
	return retry.Do(ctx, retryCfg, func() error {
		cmd := "curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker"
		_, stderr, err := sshPool.Run(ctx, host, cmd)
		if err != nil {
			return fmt.Errorf("docker install failed: %w (stderr: %s)", err, stderr)
		}
		return nil
	})
}

// installGlusterFS installs GlusterFS on a node via SSH.
func installGlusterFS(ctx context.Context, sshPool *ssh.Pool, host string, server bool) error {
	// Check if GlusterFS is already installed
	_, _, err := sshPool.Run(ctx, host, "gluster --version")
	if err == nil {
		logging.L().Infow("GlusterFS already installed", "node", host)
		return nil
	}

	// Add GlusterFS PPA for latest stable version (Ubuntu/Debian)
	// For other distros, this will fail gracefully and fall back to default repos
	addPPACmd := `
if command -v add-apt-repository &> /dev/null; then
    add-apt-repository -y ppa:gluster/glusterfs-11 2>/dev/null || true
fi
`
	logging.L().Infow("adding GlusterFS PPA", "node", host)
	sshPool.Run(ctx, host, addPPACmd) // Ignore errors, PPA might not be available

	var cmd string
	if server {
		cmd = "apt-get update && apt-get install -y glusterfs-server && systemctl enable glusterd && systemctl start glusterd"
	} else {
		cmd = "apt-get update && apt-get install -y glusterfs-client"
	}

	// Install with retry logic (apt locks, network issues)
	retryCfg := retry.PackageManagerConfig(fmt.Sprintf("install-glusterfs-%s", host))
	return retry.Do(ctx, retryCfg, func() error {
		_, stderr, err := sshPool.Run(ctx, host, cmd)
		if err != nil {
			return fmt.Errorf("glusterfs install failed: %w (stderr: %s)", err, stderr)
		}
		return nil
	})
}

// configureOverlay configures the overlay network on all enabled nodes idempotently.
func configureOverlay(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "overlay")

	provider := cfg.GlobalSettings.OverlayProvider
	if provider == "" || provider == "none" {
		log.Infow("no overlay provider configured, skipping overlay setup")
		return nil
	}

	overlayConfig := cfg.GlobalSettings.OverlayConfig
	enabledNodes := getEnabledNodes(cfg)
	log.Infow("configuring overlay network", "provider", provider, "totalNodes", len(enabledNodes))

	// Configure overlay on all enabled nodes
	for i, node := range enabledNodes {
		nodeNum := i + 1

		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(enabledNodes)),
			"hostname", node.Hostname,
			"provider", provider,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "configuring overlay network"))
		if err := configureOverlayOnNode(ctx, sshPool, node, provider, overlayConfig); err != nil {
			return fmt.Errorf("failed to configure %s overlay on %s: %w", provider, node.Hostname, err)
		}
		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "overlay network configured"))
	}

	log.Infow("✅ overlay network configured", "provider", provider)
	return nil
}

// configureOverlayOnNode configures the overlay network on a single node idempotently.
func configureOverlayOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, provider string, overlayConfig string) error {
	switch provider {
	case "netbird":
		return configureNetbirdOnNode(ctx, sshPool, node, overlayConfig)
	case "tailscale":
		return configureTailscaleOnNode(ctx, sshPool, node, overlayConfig)
	case "wireguard":
		return configureWireGuardOnNode(ctx, sshPool, node, overlayConfig)
	case "none", "":
		return nil
	default:
		return fmt.Errorf("unknown overlay provider: %s", provider)
	}
}

// maskSetupKey masks setup keys for logging (replaces key with asterisks)
// Handles formats like:
//   --setup-key "C70334FC-522E-40E4-923A-2ECAE9400EAA" --allow-server-ssh
//   --authkey='tskey-abc123def456'
func maskSetupKey(fullConfig string) string {
	if fullConfig == "" {
		return ""
	}

	// Handle quoted keys: --setup-key "KEY" or --authkey='KEY'
	// Replace the key value (inside quotes or after flag) with asterisks
	result := fullConfig

	// Pattern 1: --setup-key "UUID" or --setup-key 'UUID'
	setupKeyPattern := `(--setup-key\s+["']?)([A-Za-z0-9-]+)(["']?)`
	re := regexp.MustCompile(setupKeyPattern)
	result = re.ReplaceAllStringFunc(result, func(match string) string {
		// Extract the key and replace with asterisks of same length
		submatches := re.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			prefix := submatches[1]  // --setup-key " or --setup-key '
			key := submatches[2]     // The actual key
			suffix := submatches[3]  // " or '
			masked := strings.Repeat("*", len(key))
			return prefix + masked + suffix
		}
		return match
	})

	// Pattern 2: --authkey="KEY" or --authkey='KEY'
	authKeyPattern := `(--authkey\s*=\s*["']?)([A-Za-z0-9-]+)(["']?)`
	re2 := regexp.MustCompile(authKeyPattern)
	result = re2.ReplaceAllStringFunc(result, func(match string) string {
		submatches := re2.FindStringSubmatch(match)
		if len(submatches) >= 4 {
			prefix := submatches[1]
			key := submatches[2]
			suffix := submatches[3]
			masked := strings.Repeat("*", len(key))
			return prefix + masked + suffix
		}
		return match
	})

	return result
}

// configureNetbirdOnNode configures Netbird on a single node idempotently.
func configureNetbirdOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.Hostname, "provider", "netbird")

	// Check if netbird is already running
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "checking netbird status"))
	checkCmd := "netbird status 2>/dev/null | grep -q 'Status: Connected' && echo 'CONNECTED' || echo 'NOT_CONNECTED'"
	stdout, _, err := sshPool.Run(ctx, node.Hostname, checkCmd)
	if err == nil && stdout == "CONNECTED\n" {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird already connected, skipping installation"))
		return nil
	}

	// Check if netbird is installed
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "checking if netbird is installed"))
	checkInstallCmd := "command -v netbird &> /dev/null && echo 'INSTALLED' || echo 'NOT_INSTALLED'"
	stdout, _, _ = sshPool.Run(ctx, node.Hostname, checkInstallCmd)

	if stdout != "INSTALLED\n" {
		// Install netbird if not present (with retry)
		installURL := "https://pkgs.netbird.io/install.sh"
		installCmd := fmt.Sprintf("curl -fsSL %s | sh", installURL)

		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "netbird not found, downloading and installing"))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("download URL: %s", installURL)))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("install command: %s", installCmd)))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "executing installation (this may take 30-60 seconds)..."))

		retryCfg := retry.NetworkConfig(fmt.Sprintf("install-netbird-%s", node.Hostname))
		err = retry.Do(ctx, retryCfg, func() error {
			_, stderr, err := sshPool.Run(ctx, node.Hostname, installCmd)
			if err != nil {
				log.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "netbird installation failed"), "error", err, "stderr", stderr)
				return fmt.Errorf("failed to install netbird: %w (stderr: %s)", err, stderr)
			}
			if stderr != "" {
				log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird installation completed"), "stderr", stderr)
			} else {
				log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird installation completed"))
			}
			return nil
		})
		if err != nil {
			return err
		}
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird installed successfully"))
	} else {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird already installed"))
	}

	// Start netbird with setup key and flags if provided (with retry)
	// overlayConfig can contain full flags like: --setup-key "KEY" --allow-server-ssh --enable-ssh-remote-port-forwarding
	upCmd := "netbird up"
	maskedCmd := "netbird up"
	if overlayConfig != "" {
		upCmd = fmt.Sprintf("netbird up %s", overlayConfig)
		// Mask the setup key for logging (preserves all flags, just masks the key value)
		maskedCmd = fmt.Sprintf("netbird up %s", maskSetupKey(overlayConfig))
	}

	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "starting netbird and connecting to network"))
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("command: %s", maskedCmd)))
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "executing netbird up..."))

	retryCfg := retry.NetworkConfig(fmt.Sprintf("start-netbird-%s", node.Hostname))
	err = retry.Do(ctx, retryCfg, func() error {
		_, stderr, err := sshPool.Run(ctx, node.Hostname, upCmd)
		if err != nil {
			log.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "netbird up failed"), "error", err, "stderr", stderr)
			return fmt.Errorf("failed to start netbird: %w (stderr: %s)", err, stderr)
		}
		if stderr != "" {
			log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird up completed"), "stderr", stderr)
		} else {
			log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird up completed"))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Verify connection
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "verifying netbird connection"))
	verifyCmd := "netbird status"
	verifyStdout, verifyStderr, verifyErr := sshPool.Run(ctx, node.Hostname, verifyCmd)
	if verifyErr != nil {
		log.Warnw(formatNodeMessage("⚠", node.Hostname, node.NewHostname, "failed to verify netbird status"), "error", verifyErr, "stderr", verifyStderr)
	} else {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird status"), "status", verifyStdout)
	}

	log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "netbird connected successfully"))
	return nil
}

// configureTailscaleOnNode configures Tailscale on a single node idempotently.
func configureTailscaleOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.Hostname, "provider", "tailscale")

	// Check if tailscale is already running
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "checking tailscale status"))
	checkCmd := "tailscale status --json 2>/dev/null | grep -q '\"BackendState\":\"Running\"' && echo 'RUNNING' || echo 'NOT_RUNNING'"
	stdout, _, err := sshPool.Run(ctx, node.Hostname, checkCmd)
	if err == nil && stdout == "RUNNING\n" {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale already running, skipping installation"))
		return nil
	}

	// Check if tailscale is installed
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "checking if tailscale is installed"))
	checkInstallCmd := "command -v tailscale &> /dev/null && echo 'INSTALLED' || echo 'NOT_INSTALLED'"
	stdout, _, _ = sshPool.Run(ctx, node.Hostname, checkInstallCmd)

	if stdout != "INSTALLED\n" {
		// Install tailscale if not present (with retry)
		installURL := "https://tailscale.com/install.sh"
		installCmd := fmt.Sprintf("curl -fsSL %s | sh", installURL)

		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "tailscale not found, downloading and installing"))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("download URL: %s", installURL)))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("install command: %s", installCmd)))
		log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "executing installation (this may take 30-60 seconds)..."))

		retryCfg := retry.NetworkConfig(fmt.Sprintf("install-tailscale-%s", node.Hostname))
		err = retry.Do(ctx, retryCfg, func() error {
			_, stderr, err := sshPool.Run(ctx, node.Hostname, installCmd)
			if err != nil {
				log.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "tailscale installation failed"), "error", err, "stderr", stderr)
				return fmt.Errorf("failed to install tailscale: %w (stderr: %s)", err, stderr)
			}
			if stderr != "" {
				log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale installation completed"), "stderr", stderr)
			} else {
				log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale installation completed"))
			}
			return nil
		})
		if err != nil {
			return err
		}
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale installed successfully"))
	} else {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale already installed"))
	}

	// Start tailscale with auth key if provided (with retry)
	upCmd := "tailscale up"
	maskedCmd := "tailscale up"
	if overlayConfig != "" {
		upCmd = fmt.Sprintf("tailscale up --authkey='%s'", overlayConfig)
		// Mask the auth key for logging
		maskedCmd = fmt.Sprintf("tailscale up --authkey='%s'", maskSetupKey(overlayConfig))
	}

	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "starting tailscale and connecting to network"))
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("command: %s", maskedCmd)))
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "executing tailscale up..."))

	retryCfg := retry.NetworkConfig(fmt.Sprintf("start-tailscale-%s", node.Hostname))
	err = retry.Do(ctx, retryCfg, func() error {
		_, stderr, err := sshPool.Run(ctx, node.Hostname, upCmd)
		if err != nil {
			log.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "tailscale up failed"), "error", err, "stderr", stderr)
			return fmt.Errorf("failed to start tailscale: %w (stderr: %s)", err, stderr)
		}
		if stderr != "" {
			log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale up completed"), "stderr", stderr)
		} else {
			log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale up completed"))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Verify connection
	log.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "verifying tailscale connection"))
	verifyCmd := "tailscale status"
	verifyStdout, verifyStderr, verifyErr := sshPool.Run(ctx, node.Hostname, verifyCmd)
	if verifyErr != nil {
		log.Warnw(formatNodeMessage("⚠", node.Hostname, node.NewHostname, "failed to verify tailscale status"), "error", verifyErr, "stderr", verifyStderr)
	} else {
		log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale status"), "status", verifyStdout)
	}

	log.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "tailscale connected successfully"))
	return nil
}

// configureWireGuardOnNode configures WireGuard on a single node idempotently.
func configureWireGuardOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.Hostname, "provider", "wireguard")

	// WireGuard requires a config file path in overlayConfig
	if overlayConfig == "" {
		return fmt.Errorf("wireguard requires overlayConfig to specify interface name or config path")
	}

	// Parse interface name from config (format: "wg0" or "/etc/wireguard/wg0.conf")
	iface := overlayConfig
	if len(iface) > 5 && iface[len(iface)-5:] == ".conf" {
		// Extract interface name from path
		parts := iface[len(iface)-10:]
		if idx := len(parts) - 5; idx > 0 {
			iface = parts[:idx]
		}
	}

	// Check if interface is already up
	checkCmd := fmt.Sprintf("wg show %s 2>/dev/null && echo 'UP' || echo 'DOWN'", iface)
	stdout, _, err := sshPool.Run(ctx, node.Hostname, checkCmd)
	if err == nil && stdout == "UP\n" {
		log.Infow("wireguard interface already up", "interface", iface)
		return nil
	}

	// Install wireguard if not present
	installCmd := `
if ! command -v wg &> /dev/null; then
    echo "Installing WireGuard..."
    apt-get update && apt-get install -y wireguard wireguard-tools
fi
`
	if _, stderr, err := sshPool.Run(ctx, node.Hostname, installCmd); err != nil {
		return fmt.Errorf("failed to install wireguard: %w (stderr: %s)", err, stderr)
	}

	// Start wireguard interface
	upCmd := fmt.Sprintf("wg-quick up %s", overlayConfig)
	if _, stderr, err := sshPool.Run(ctx, node.Hostname, upCmd); err != nil {
		return fmt.Errorf("failed to start wireguard: %w (stderr: %s)", err, stderr)
	}

	log.Infow("wireguard configured successfully", "interface", iface)
	return nil
}

// getEnabledNodes returns only enabled nodes from the configuration.
func getEnabledNodes(cfg *config.Config) []config.NodeConfig {
	var enabled []config.NodeConfig
	for _, node := range cfg.Nodes {
		if node.IsEnabled() {
			enabled = append(enabled, node)
		}
	}
	return enabled
}

// getGlusterWorkers returns the hostnames of all enabled workers with GlusterFS enabled.
func getGlusterWorkers(cfg *config.Config) []string {
	var workers []string
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		if node.Role == "worker" && node.GlusterEnabled {
			workers = append(workers, node.Hostname)
		}
	}
	return workers
}

// categorizeNodes returns enabled managers and workers.
func categorizeNodes(cfg *config.Config) (managers []string, workers []string) {
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		if node.Role == "manager" {
			managers = append(managers, node.Hostname)
		} else if node.Role == "worker" {
			workers = append(workers, node.Hostname)
		}
	}
	return
}

// setHostnames sets hostnames on enabled nodes if configured.
func setHostnames(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "hostnames")

	// Count enabled nodes that need hostname changes
	var nodesToUpdate []config.NodeConfig
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		if node.NewHostname != "" {
			nodesToUpdate = append(nodesToUpdate, node)
		}
	}

	if len(nodesToUpdate) == 0 {
		log.Infow("no hostname changes required")
		return nil
	}

	log.Infow("setting hostnames", "totalNodes", len(nodesToUpdate))

	for i, node := range nodesToUpdate {
		nodeNum := i + 1

		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(nodesToUpdate)),
			"hostname", node.Hostname,
			"newHostname", node.NewHostname,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "checking current hostname"))

		// Check current hostname
		stdout, _, err := sshPool.Run(ctx, node.Hostname, "hostname")
		if err == nil && stdout == node.NewHostname+"\n" {
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "hostname already set, skipping"))
			continue
		}

		// Set hostname idempotently
		setCmd := fmt.Sprintf("hostnamectl set-hostname %s", node.NewHostname)
		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, fmt.Sprintf("executing hostname change (command: %s)", setCmd)))

		if _, stderr, err := sshPool.Run(ctx, node.Hostname, setCmd); err != nil {
			return fmt.Errorf("failed to set hostname on %s: %w (stderr: %s)", node.Hostname, err, stderr)
		}

		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "hostname set successfully"))
	}

	return nil
}

// setRootPassword sets the root password on all enabled nodes.
func setRootPassword(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "root-password")

	enabledNodes := getEnabledNodes(cfg)
	if len(enabledNodes) == 0 {
		log.Infow("no nodes to update")
		return nil
	}

	password := cfg.GlobalSettings.SetRootPassword
	log.Infow("setting root password on all nodes", "totalNodes", len(enabledNodes))

	for i, node := range enabledNodes {
		nodeNum := i + 1
		nodeLog := log.With(
			"server", fmt.Sprintf("%d/%d", nodeNum, len(enabledNodes)),
			"hostname", node.Hostname,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "setting root password"))

		// Use chpasswd to set password
		// Format: username:password
		setCmd := fmt.Sprintf("echo 'root:%s' | chpasswd", password)

		if _, stderr, err := sshPool.Run(ctx, node.Hostname, setCmd); err != nil {
			return fmt.Errorf("failed to set root password on %s: %w (stderr: %s)", node.Hostname, err, stderr)
		}

		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "root password set successfully"))
	}

	return nil
}

// executeScripts executes scripts on nodes.
func executeScripts(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool, scripts []config.ScriptConfig, phase string) error {
	log := logging.L().With("phase", fmt.Sprintf("%s-scripts", phase))

	if len(scripts) == 0 {
		log.Infow("no scripts to execute")
		return nil
	}

	// Count enabled scripts
	var enabledScripts []config.ScriptConfig
	var disabledCount int
	for _, script := range scripts {
		// Debug: Log the enabled state of each script
		log.Debugw("checking script", "name", script.Name, "enabled", script.Enabled)

		if script.Enabled {
			enabledScripts = append(enabledScripts, script)
		} else {
			disabledCount++
			log.Infow("skipping disabled script", "name", script.Name, "enabled", false)
		}
	}

	if disabledCount > 0 {
		log.Infow(fmt.Sprintf("%s script summary", phase), "total", len(scripts), "enabled", len(enabledScripts), "disabled", disabledCount)
	} else {
		log.Infow(fmt.Sprintf("executing %s scripts", phase), "enabled", len(enabledScripts))
	}

	if len(enabledScripts) == 0 {
		log.Infow(fmt.Sprintf("no enabled %s scripts to execute", phase))
		return nil
	}

	for i, script := range enabledScripts {
		scriptNum := i + 1
		scriptLog := log.With(
			"script", fmt.Sprintf("%d/%d", scriptNum, len(enabledScripts)),
			"name", script.Name,
			"source", script.Source,
		)
		scriptLog.Infow("→ executing script")

		// Count enabled nodes that will execute this script
		var targetNodes []config.NodeConfig
		var skippedNodes int
		enabledNodes := getEnabledNodes(cfg)
		for _, node := range enabledNodes {
			// Skip if scripts are disabled on this node
			if !node.ScriptsEnabled {
				skippedNodes++
				continue
			}

			// Evaluate script conditions
			matches, err := config.EvaluateScriptConditions(node, script.Conditions)
			if err != nil {
				return fmt.Errorf("failed to evaluate conditions for script %s on node %s: %w", script.Name, node.Hostname, err)
			}

			if matches {
				targetNodes = append(targetNodes, node)
			} else {
				skippedNodes++
			}
		}

		if len(script.Conditions) > 0 {
			scriptLog.Infow("script will run on nodes", "targetNodes", len(targetNodes), "skippedNodes", skippedNodes, "conditions", len(script.Conditions))
		} else {
			scriptLog.Infow("script will run on nodes", "targetNodes", len(targetNodes))
		}

		// Execute script on all enabled nodes
		for j, node := range targetNodes {
			nodeNum := j + 1
			nodeLog := scriptLog.With(
				"server", fmt.Sprintf("%d/%d", nodeNum, len(targetNodes)),
				"hostname", node.Hostname,
				"user", node.Username,
				"port", node.SSHPort,
			)

			nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "executing script on node"))
			if err := executeScriptOnNode(ctx, sshPool, node, script); err != nil {
				if script.ContinueOnError {
					nodeLog.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "script failed but continuing (continueOnError=true)"), "error", err)
				} else {
					return fmt.Errorf("failed to execute script %s on %s: %w", script.Name, node.Hostname, err)
				}
			} else {
				nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "script executed successfully on node"))
			}
		}

		scriptLog.Infow("✓ script executed successfully on all nodes")
	}

	return nil
}

// executeScriptOnNode executes a single script on a single node.
func executeScriptOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, script config.ScriptConfig) error {
	log := logging.L().With("node", node.Hostname, "script", script.Name)

	// Determine if script is local or remote
	isRemote := len(script.Source) > 7 && (script.Source[:7] == "http://" || script.Source[:8] == "https://")

	var scriptPath string
	if isRemote {
		// Download remote script
		scriptPath = fmt.Sprintf("/tmp/clusterctl-script-%s.sh", script.Name)
		downloadCmd := fmt.Sprintf("curl -fsSL -o %s %s", scriptPath, script.Source)
		if _, stderr, err := sshPool.Run(ctx, node.Hostname, downloadCmd); err != nil {
			return fmt.Errorf("failed to download script: %w (stderr: %s)", err, stderr)
		}
		log.Infow("downloaded remote script", "url", script.Source)
	} else {
		// Transfer local script
		// TODO: Implement file transfer via SSH (SCP or SFTP)
		// For now, we'll assume the script is already on the remote host or use a workaround
		return fmt.Errorf("local script transfer not yet implemented (script: %s)", script.Source)
	}

	// Make script executable
	chmodCmd := fmt.Sprintf("chmod +x %s", scriptPath)
	if _, stderr, err := sshPool.Run(ctx, node.Hostname, chmodCmd); err != nil {
		return fmt.Errorf("failed to make script executable: %w (stderr: %s)", err, stderr)
	}

	// Execute script with parameters
	execCmd := scriptPath
	if script.Parameters != "" {
		execCmd = fmt.Sprintf("%s %s", scriptPath, script.Parameters)
	}

	stdout, stderr, err := sshPool.Run(ctx, node.Hostname, execCmd)
	if err != nil {
		return fmt.Errorf("script execution failed: %w (stderr: %s)", err, stderr)
	}

	log.Infow("script executed", "stdout", stdout, "stderr", stderr)
	return nil
}

// rebootNodes reboots nodes if configured.
func rebootNodes(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "reboot")

	for _, node := range cfg.Nodes {
		if !node.RebootOnCompletion {
			continue
		}

		nodeLog := log.With("node", node.Hostname)
		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "initiating reboot with 15 second delay"))

		// Initiate reboot with 15 second delay and terminate SSH connection cleanly
		rebootCmd := "nohup sh -c 'sleep 15 && reboot' > /dev/null 2>&1 &"
		if _, stderr, err := sshPool.Run(ctx, node.Hostname, rebootCmd); err != nil {
			// Ignore errors as the connection may be terminated
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "reboot initiated (connection may have terminated)"), "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "reboot scheduled successfully"))
		}
	}

	return nil
}

// applyNodeLabels detects geolocation and applies automatic and custom labels to Docker nodes.
func applyNodeLabels(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool, primaryMaster string) error {
	log := logging.L().With("phase", "labels")

	// Detect geolocation for all nodes in parallel
	log.Infow("detecting geolocation for all nodes")
	hostnames := make([]string, 0, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		hostnames = append(hostnames, node.Hostname)
	}
	geoInfoMap := geolocation.DetectGeoLocationBatch(ctx, sshPool, hostnames)

	// Apply labels to each node
	for _, node := range cfg.Nodes {
		nodeLog := log.With("node", node.Hostname)
		geoInfo := geoInfoMap[node.Hostname]

		// Build automatic labels
		labels := make(map[string]string)

		// Geolocation labels
		if geoInfo != nil {
			if geoInfo.PublicIP != "" && geoInfo.PublicIP != "unknown" {
				labels["geo.public-ip"] = geoInfo.PublicIP
			}
			if geoInfo.Country != "" {
				labels["geo.country"] = geoInfo.Country
			}
			if geoInfo.CountryCode != "" {
				labels["geo.country-code"] = strings.ToLower(geoInfo.CountryCode)
			}
			if geoInfo.Region != "" {
				labels["geo.region"] = geoInfo.Region
			}
			if geoInfo.RegionName != "" {
				labels["geo.region-name"] = geoInfo.RegionName
			}
			if geoInfo.City != "" {
				labels["geo.city"] = geoInfo.City
			}
			if geoInfo.Timezone != "" {
				labels["geo.timezone"] = geoInfo.Timezone
			}
			if geoInfo.ISP != "" {
				labels["geo.isp"] = geoInfo.ISP
			}
		}

		// Overlay provider label
		if cfg.GlobalSettings.OverlayProvider != "" && cfg.GlobalSettings.OverlayProvider != "none" {
			labels["overlay.provider"] = cfg.GlobalSettings.OverlayProvider
		}

		// GlusterFS labels
		if node.GlusterEnabled {
			labels["glusterfs.enabled"] = "true"

			// Get effective mount path
			mountPath := node.GlusterMount
			if mountPath == "" {
				mountPath = cfg.GlobalSettings.GlusterMount
			}
			if mountPath != "" {
				labels["glusterfs.mount-path"] = mountPath
			}

			// Get effective brick path
			brickPath := node.GlusterBrick
			if brickPath == "" {
				brickPath = cfg.GlobalSettings.GlusterBrick
			}
			if brickPath != "" {
				labels["glusterfs.brick-path"] = brickPath
			}
		} else {
			labels["glusterfs.enabled"] = "false"
		}

		// Cluster name label
		if cfg.GlobalSettings.ClusterName != "" {
			labels["cluster.name"] = cfg.GlobalSettings.ClusterName
		}

		// Role label
		labels["node.role"] = node.Role

		// Merge custom labels from config (custom labels override automatic labels)
		for key, value := range node.Labels {
			labels[key] = value
		}

		// Apply labels to the node
		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "applying labels"), "count", len(labels))
		for key, value := range labels {
			// Escape special characters in label values
			escapedValue := strings.ReplaceAll(value, `"`, `\"`)
			labelCmd := fmt.Sprintf(`docker node update --label-add "%s=%s" $(docker node ls --filter "name=%s" -q)`,
				key, escapedValue, node.Hostname)

			if _, stderr, err := sshPool.Run(ctx, primaryMaster, labelCmd); err != nil {
				nodeLog.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "failed to apply label"), "key", key, "value", value, "error", err, "stderr", stderr)
			} else {
				nodeLog.Debugw(formatNodeMessage("✓", node.Hostname, node.NewHostname, "label applied"), "key", key, "value", value)
			}
		}

		nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "labels applied successfully"), "total", len(labels))
	}

	log.Infow("all node labels applied")
	return nil
}

// removeSSHPublicKeyFromNodes removes the automatic SSH public key from all nodes.
func removeSSHPublicKeyFromNodes(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool, keyPair *sshkeys.KeyPair) error {
	if keyPair == nil {
		return nil // No key pair to remove
	}

	log := logging.L().With("phase", "ssh-key-removal")

	for _, node := range cfg.Nodes {
		nodeLog := log.With("node", node.Hostname)
		nodeLog.Infow(formatNodeMessage("→", node.Hostname, node.NewHostname, "removing public key from node"))

		// Remove the public key from authorized_keys
		removeCmd := fmt.Sprintf(
			"sed -i '\\|%s|d' ~/.ssh/authorized_keys 2>/dev/null || true",
			strings.TrimSpace(keyPair.PublicKey),
		)

		if _, stderr, err := sshPool.Run(ctx, node.Hostname, removeCmd); err != nil {
			nodeLog.Warnw(formatNodeMessage("✗", node.Hostname, node.NewHostname, "failed to remove public key"), "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.Hostname, node.NewHostname, "public key removed successfully"))
		}
	}

	return nil
}

// removeStacks removes all deployed Docker stacks from the primary manager.
func removeStacks(ctx context.Context, sshPool *ssh.Pool, primaryManager string) error {
	log := logging.L().With("component", "teardown-stacks")

	// List all stacks
	listCmd := "docker stack ls --format '{{.Name}}'"
	log.Infow("listing Docker stacks", "host", primaryManager, "command", listCmd)
	stdout, stderr, err := sshPool.Run(ctx, primaryManager, listCmd)
	if err != nil {
		return fmt.Errorf("failed to list stacks: %w (stderr: %s)", err, stderr)
	}

	stacks := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(stacks) == 0 || (len(stacks) == 1 && stacks[0] == "") {
		log.Infow("no stacks found to remove")
		return nil
	}

	// Remove each stack
	for _, stack := range stacks {
		stack = strings.TrimSpace(stack)
		if stack == "" {
			continue
		}

		removeCmd := fmt.Sprintf("docker stack rm %s", stack)
		log.Infow("removing Docker stack", "host", primaryManager, "stack", stack, "command", removeCmd)
		if _, stderr, err := sshPool.Run(ctx, primaryManager, removeCmd); err != nil {
			log.Warnw("failed to remove stack", "stack", stack, "error", err, "stderr", stderr)
		} else {
			log.Infow("✅ stack removed", "stack", stack)
		}
	}

	return nil
}

// leaveSwarm makes all nodes leave the Docker Swarm.
func leaveSwarm(ctx context.Context, sshPool *ssh.Pool, allNodes []string) error {
	log := logging.L().With("component", "teardown-swarm")

	for _, node := range allNodes {
		leaveCmd := "docker swarm leave --force"
		log.Infow("leaving Docker Swarm", "host", node, "command", leaveCmd)
		if _, stderr, err := sshPool.Run(ctx, node, leaveCmd); err != nil {
			// Ignore errors if node is not in swarm
			if !strings.Contains(stderr, "not part of a swarm") {
				log.Warnw("failed to leave swarm", "host", node, "error", err, "stderr", stderr)
			}
		} else {
			log.Infow("✅ left swarm", "host", node)
		}
	}

	return nil
}

// unmountGlusterFS unmounts GlusterFS volumes on manager nodes.
func unmountGlusterFS(ctx context.Context, sshPool *ssh.Pool, managers []string, cfg *config.Config) error {
	log := logging.L().With("component", "teardown-gluster-unmount")

	for _, manager := range managers {
		if cfg.GlobalSettings.GlusterMount == "" {
			continue
		}

		unmountCmd := fmt.Sprintf("umount %s 2>/dev/null || true", cfg.GlobalSettings.GlusterMount)
		log.Infow("unmounting GlusterFS", "host", manager, "mountPoint", cfg.GlobalSettings.GlusterMount, "command", unmountCmd)
		if _, stderr, err := sshPool.Run(ctx, manager, unmountCmd); err != nil {
			log.Warnw("failed to unmount GlusterFS", "host", manager, "error", err, "stderr", stderr)
		} else {
			log.Infow("✅ GlusterFS unmounted", "host", manager)
		}

		// Remove from fstab
		removeFstabCmd := fmt.Sprintf("sed -i '\\|%s|d' /etc/fstab", cfg.GlobalSettings.GlusterMount)
		log.Infow("removing from fstab", "host", manager, "command", removeFstabCmd)
		if _, stderr, err := sshPool.Run(ctx, manager, removeFstabCmd); err != nil {
			log.Warnw("failed to remove from fstab", "host", manager, "error", err, "stderr", stderr)
		}
	}

	return nil
}

// deleteGlusterVolume stops and deletes the GlusterFS volume.
func deleteGlusterVolume(ctx context.Context, sshPool *ssh.Pool, workers []string, cfg *config.Config) error {
	log := logging.L().With("component", "teardown-gluster-volume")

	if len(workers) == 0 || cfg.GlobalSettings.GlusterVolume == "" {
		return nil
	}

	orchestrator := workers[0]

	// Stop volume
	stopCmd := fmt.Sprintf("gluster volume stop %s force 2>/dev/null || true", cfg.GlobalSettings.GlusterVolume)
	log.Infow("stopping GlusterFS volume", "host", orchestrator, "volume", cfg.GlobalSettings.GlusterVolume, "command", stopCmd)
	if _, stderr, err := sshPool.Run(ctx, orchestrator, stopCmd); err != nil {
		log.Warnw("failed to stop volume", "error", err, "stderr", stderr)
	} else {
		log.Infow("✅ volume stopped", "volume", cfg.GlobalSettings.GlusterVolume)
	}

	// Delete volume
	deleteCmd := fmt.Sprintf("gluster volume delete %s 2>/dev/null || true", cfg.GlobalSettings.GlusterVolume)
	log.Infow("deleting GlusterFS volume", "host", orchestrator, "volume", cfg.GlobalSettings.GlusterVolume, "command", deleteCmd)
	if _, stderr, err := sshPool.Run(ctx, orchestrator, deleteCmd); err != nil {
		log.Warnw("failed to delete volume", "error", err, "stderr", stderr)
	} else {
		log.Infow("✅ volume deleted", "volume", cfg.GlobalSettings.GlusterVolume)
	}

	// Detach peers
	for _, worker := range workers[1:] {
		detachCmd := fmt.Sprintf("gluster peer detach %s force 2>/dev/null || true", worker)
		log.Infow("detaching GlusterFS peer", "host", orchestrator, "peer", worker, "command", detachCmd)
		if _, stderr, err := sshPool.Run(ctx, orchestrator, detachCmd); err != nil {
			log.Warnw("failed to detach peer", "peer", worker, "error", err, "stderr", stderr)
		}
	}

	return nil
}

// removeGlusterData_func removes GlusterFS data directories on worker nodes.
func removeGlusterData_func(ctx context.Context, sshPool *ssh.Pool, workers []string, cfg *config.Config) error {
	log := logging.L().With("component", "teardown-gluster-data")

	if cfg.GlobalSettings.GlusterBrick == "" {
		return nil
	}

	for _, worker := range workers {
		removeCmd := fmt.Sprintf("rm -rf %s", cfg.GlobalSettings.GlusterBrick)
		log.Infow("removing GlusterFS data", "host", worker, "path", cfg.GlobalSettings.GlusterBrick, "command", removeCmd)
		if _, stderr, err := sshPool.Run(ctx, worker, removeCmd); err != nil {
			log.Warnw("failed to remove data", "host", worker, "error", err, "stderr", stderr)
		} else {
			log.Infow("✅ data removed", "host", worker, "path", cfg.GlobalSettings.GlusterBrick)
		}
	}

	return nil
}

// removeOverlayNetworks removes Docker overlay networks.
func removeOverlayNetworks(ctx context.Context, sshPool *ssh.Pool, primaryManager string) error {
	log := logging.L().With("component", "teardown-networks")

	networks := []string{
		swarm.DefaultInternalNetworkName,
		swarm.DefaultExternalNetworkName,
	}

	for _, network := range networks {
		removeCmd := fmt.Sprintf("docker network rm %s 2>/dev/null || true", network)
		log.Infow("removing overlay network", "host", primaryManager, "network", network, "command", removeCmd)
		if _, stderr, err := sshPool.Run(ctx, primaryManager, removeCmd); err != nil {
			log.Warnw("failed to remove network", "network", network, "error", err, "stderr", stderr)
		} else {
			log.Infow("✅ network removed", "network", network)
		}
	}

	return nil
}

// OverlayInfo contains overlay network information for a node
type OverlayInfo struct {
	FQDN      string // Fully qualified domain name (e.g., node1.netbird.cloud)
	IP        string // Overlay IP address without CIDR (e.g., 100.76.202.130)
	Interface string // Network interface name (e.g., wt0, tailscale0)
}

// IPAddrInfo represents address information from 'ip -j addr show'
type IPAddrInfo struct {
	IfName   string `json:"ifname"`
	AddrInfo []struct {
		Local string `json:"local"`
	} `json:"addr_info"`
}

// getInterfaceForIP finds the network interface name for a given IP address on a remote host.
// Uses the same precedence as IP detection: relay → local → public.
// Returns the interface name or empty string if not found.
func getInterfaceForIP(ctx context.Context, sshPool *ssh.Pool, sshHost, targetIP string) (string, error) {
	// Use 'ip -j addr show' to get JSON output of all interfaces and their IPs
	cmd := "ip -j addr show"

	stdout, stderr, err := sshPool.Run(ctx, sshHost, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get interface info: %w (stderr: %s)", err, stderr)
	}

	var interfaces []IPAddrInfo
	if err := json.Unmarshal([]byte(stdout), &interfaces); err != nil {
		return "", fmt.Errorf("failed to parse ip addr JSON: %w", err)
	}

	// Find the interface that has the target IP
	for _, iface := range interfaces {
		for _, addr := range iface.AddrInfo {
			if addr.Local == targetIP {
				return iface.IfName, nil
			}
		}
	}

	return "", fmt.Errorf("no interface found for IP %s", targetIP)
}

// NetbirdStatusJSON represents the JSON output from 'netbird status --json'
type NetbirdStatusJSON struct {
	FQDN      string `json:"fqdn"`
	NetbirdIP string `json:"netbirdIp"` // e.g., "100.76.202.130/16"
}

// TailscaleStatusJSON represents the JSON output from 'tailscale status --json'
type TailscaleStatusJSON struct {
	Self struct {
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
	} `json:"Self"`
}

// getOverlayInfoForNode retrieves the overlay network information for a single node.
// Returns the overlay FQDN, IP, and network interface name, or falls back to SSH hostname.
func getOverlayInfoForNode(ctx context.Context, sshPool *ssh.Pool, sshHost, provider string) (OverlayInfo, error) {
	switch provider {
	case "netbird":
		// Get netbird info via SSH using JSON output
		cmd := "netbird status --json"
		stdout, stderr, cmdErr := sshPool.Run(ctx, sshHost, cmd)
		if cmdErr != nil {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("netbird status failed: %w (stderr: %s)", cmdErr, stderr)
		}

		var status NetbirdStatusJSON
		if err := json.Unmarshal([]byte(stdout), &status); err != nil {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("failed to parse netbird JSON: %w", err)
		}

		if status.FQDN == "" || status.NetbirdIP == "" {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("netbird fqdn or ip empty")
		}

		// Remove CIDR notation from IP (e.g., "100.76.202.130/16" -> "100.76.202.130")
		ip := strings.Split(status.NetbirdIP, "/")[0]

		// Find the network interface for this IP
		ifname, err := getInterfaceForIP(ctx, sshPool, sshHost, ip)
		if err != nil {
			logging.L().Warnw("failed to detect interface for overlay IP, will use IP as fallback", "sshHost", sshHost, "ip", ip, "error", err)
			ifname = "" // Will fallback to IP in advertise-addr
		}

		return OverlayInfo{FQDN: status.FQDN, IP: ip, Interface: ifname}, nil

	case "tailscale":
		// Get tailscale info via SSH using JSON output
		cmd := "tailscale status --json"
		stdout, stderr, cmdErr := sshPool.Run(ctx, sshHost, cmd)
		if cmdErr != nil {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("tailscale status failed: %w (stderr: %s)", cmdErr, stderr)
		}

		var status TailscaleStatusJSON
		if err := json.Unmarshal([]byte(stdout), &status); err != nil {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("failed to parse tailscale JSON: %w", err)
		}

		if status.Self.DNSName == "" || len(status.Self.TailscaleIPs) == 0 {
			return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("tailscale DNSName or IPs empty")
		}

		fqdn := status.Self.DNSName
		ip := status.Self.TailscaleIPs[0]

		// Find the network interface for this IP
		ifname, err := getInterfaceForIP(ctx, sshPool, sshHost, ip)
		if err != nil {
			logging.L().Warnw("failed to detect interface for overlay IP, will use IP as fallback", "sshHost", sshHost, "ip", ip, "error", err)
			ifname = "" // Will fallback to IP in advertise-addr
		}

		return OverlayInfo{FQDN: fqdn, IP: ip, Interface: ifname}, nil

	default:
		return OverlayInfo{FQDN: sshHost, IP: sshHost}, fmt.Errorf("unknown overlay provider: %s", provider)
	}
}

// getOverlayHostnameForNode retrieves the overlay network hostname for a single node.
// Returns the overlay hostname (e.g., netbird FQDN or tailscale DNS name) or falls back to SSH hostname.
// This is a convenience wrapper around getOverlayInfoForNode that only returns the FQDN.
func getOverlayHostnameForNode(ctx context.Context, sshPool *ssh.Pool, sshHost, provider string) (string, error) {
	info, err := getOverlayInfoForNode(ctx, sshPool, sshHost, provider)
	return info.FQDN, err
}

// getGlusterHostnames returns the appropriate hostnames for GlusterFS based on overlay provider.
// If an overlay provider is configured, it retrieves the overlay hostnames (e.g., netbird FQDN).
// Otherwise, it returns the SSH connection hostnames.
func getGlusterHostnames(ctx context.Context, sshPool *ssh.Pool, cfg *config.Config, sshHostnames []string) ([]string, error) {
	log := logging.L().With("component", "gluster-hostnames")

	provider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.OverlayProvider))

	// If no overlay provider, use SSH hostnames directly
	if provider == "" || provider == "none" {
		log.Infow("no overlay provider, using SSH hostnames for GlusterFS", "hostnames", sshHostnames)
		return sshHostnames, nil
	}

	// Get overlay hostnames for each worker
	overlayHostnames := make([]string, 0, len(sshHostnames))

	for _, sshHost := range sshHostnames {
		overlayHost, err := getOverlayHostnameForNode(ctx, sshPool, sshHost, provider)
		if err != nil {
			log.Warnw("failed to get overlay hostname, falling back to SSH hostname", "sshHost", sshHost, "error", err)
			overlayHost = sshHost
		} else {
			log.Infow("retrieved overlay hostname", "sshHost", sshHost, "overlayHostname", overlayHost)
		}
		overlayHostnames = append(overlayHostnames, overlayHost)
	}

	return overlayHostnames, nil
}

// teardownGlusterFS tears down an existing GlusterFS cluster.
func teardownGlusterFS(ctx context.Context, sshPool *ssh.Pool, workers []string, volume, mount, brick string) error {
	log := logging.L().With("component", "gluster-teardown")

	if len(workers) == 0 {
		return nil
	}

	orchestrator := workers[0]

	// Stop and delete volume
	log.Infow("→ stopping GlusterFS volume", "volume", volume, "orchestrator", orchestrator)
	stopCmd := fmt.Sprintf("gluster volume stop %s force 2>/dev/null || true", volume)
	_, _, _ = sshPool.Run(ctx, orchestrator, stopCmd)

	log.Infow("→ deleting GlusterFS volume", "volume", volume, "orchestrator", orchestrator)
	deleteCmd := fmt.Sprintf("gluster volume delete %s 2>/dev/null || true", volume)
	_, _, _ = sshPool.Run(ctx, orchestrator, deleteCmd)

	// Detach peers
	if len(workers) > 1 {
		for _, worker := range workers[1:] {
			log.Infow("→ detaching peer", "peer", worker, "orchestrator", orchestrator)
			detachCmd := fmt.Sprintf("gluster peer detach %s force 2>/dev/null || true", worker)
			_, _, _ = sshPool.Run(ctx, orchestrator, detachCmd)
		}
	}

	// Unmount and clean up on all workers
	for _, worker := range workers {
		log.Infow("→ cleaning up GlusterFS on worker", "worker", worker)

		// Unmount
		unmountCmd := fmt.Sprintf("umount %s 2>/dev/null || true", mount)
		_, _, _ = sshPool.Run(ctx, worker, unmountCmd)

		// Remove from fstab
		fstabCmd := fmt.Sprintf("sed -i '\\|%s|d' /etc/fstab 2>/dev/null || true", volume)
		_, _, _ = sshPool.Run(ctx, worker, fstabCmd)

		// Remove brick directory contents (but keep the mount point if it's a dedicated disk)
		cleanCmd := fmt.Sprintf("rm -rf %s/* 2>/dev/null || true", brick)
		_, _, _ = sshPool.Run(ctx, worker, cleanCmd)

		// Remove mount directory if it's not a disk mount point
		removeMountCmd := fmt.Sprintf("mountpoint -q %s || rm -rf %s 2>/dev/null || true", mount, mount)
		_, _, _ = sshPool.Run(ctx, worker, removeMountCmd)
	}

	log.Infow("✓ GlusterFS teardown complete")
	return nil
}
