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
	"clusterctl/internal/storage"
	"clusterctl/internal/swarm"
)

// formatNodeMessage is a convenience wrapper around logging.FormatNodeMessage.
func formatNodeMessage(prefix, hostname, newHostname, role, message string) string {
	return logging.FormatNodeMessage(prefix, hostname, newHostname, role, message)
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

	// Phase 6: Setup distributed storage if enabled
	// Storage uses Swarm roles: managers become MON nodes, workers become OSD nodes
	storageManagers, storageWorkers, storageNodes := getStorageNodesByRole(cfg)
	ds := cfg.GetDistributedStorage()
	if ds.Enabled && len(storageNodes) > 0 {
		log.Infow("Phase 6: Setting up distributed storage",
			"provider", ds.Provider,
			"managers", len(storageManagers),
			"workers", len(storageWorkers),
			"forceRecreation", ds.ForceRecreation)

		// If force recreation is enabled, teardown existing storage cluster first
		if ds.ForceRecreation {
			log.Infow("→ Force recreation enabled, tearing down existing storage cluster")
			if err := teardownDistributedStorage(ctx, sshPool, storageNodes, cfg); err != nil {
				log.Warnw("⚠️ Storage teardown had errors (continuing anyway)", "error", err)
			} else {
				log.Infow("✓ Storage teardown complete")
			}

			// Verify teardown was successful on all nodes
			log.Infow("→ Verifying storage teardown...")
			allClean := true
			for _, node := range storageNodes {
				if !verifyStorageTeardown(ctx, sshPool, node, cfg) {
					log.Warnw("⚠️ Storage not fully cleaned on node", "node", node)
					allClean = false
				}
			}
			if allClean {
				log.Infow("✓ All nodes verified clean")
			} else {
				log.Warnw("⚠️ Some nodes may have residual storage data (continuing anyway)")
			}
		}

		// Setup distributed storage (MicroCeph: managers=MON, workers=OSD)
		if err := setupDistributedStorage(ctx, sshPool, storageManagers, storageWorkers, cfg); err != nil {
			return fmt.Errorf("failed to setup distributed storage: %w", err)
		}

		log.Infow("✅ Distributed storage setup complete",
			"managers", len(storageManagers),
			"workers", len(storageWorkers),
			"provider", ds.Provider)
	} else if !ds.Enabled {
		log.Infow("Phase 6: Skipping distributed storage (disabled in config)")
	} else {
		log.Infow("Phase 6: Skipping distributed storage (no nodes with storageEnabled)")
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
	primaryMasterInfo := overlayInfoMap[primaryMaster]

	// Build join address for remote nodes to connect to primary manager
	// Priority: FQDN > overlay IP (interface names like wt0 won't work remotely)
	var primaryMasterJoinAddr string
	if primaryMasterInfo.FQDN != "" && primaryMasterInfo.FQDN != primaryMaster {
		primaryMasterJoinAddr = primaryMasterInfo.FQDN + ":2377"
	} else {
		primaryMasterJoinAddr = primaryMasterInfo.IP + ":2377"
	}

	log.Infow("→ Using addresses for Docker Swarm",
		"primaryAdvertiseAddr", primaryMasterAdvertiseAddr,
		"primaryJoinAddr", primaryMasterJoinAddr,
		"overlayProvider", provider)

	if err := orchestrator.SwarmSetup(ctx, sshPool, sshManagers, sshWorkers, managerAdvertiseAddrs, workerAdvertiseAddrs, primaryMasterAdvertiseAddr, primaryMasterJoinAddr); err != nil {
		return fmt.Errorf("failed to setup Docker Swarm: %w", err)
	}
	log.Infow("✅ Docker Swarm setup complete", "primaryAdvertiseAddr", primaryMasterAdvertiseAddr, "primaryJoinAddr", primaryMasterJoinAddr)

	// Phase 7b: Create default overlay networks
	log.Infow("→ Creating default Docker Swarm overlay networks")
	if err := createDefaultOverlayNetworks(ctx, sshPool, primaryMaster); err != nil {
		return fmt.Errorf("failed to create overlay networks: %w", err)
	}
	log.Infow("✅ Overlay networks created")

	// Phase 8: Detect geolocation and apply node labels
	log.Infow("Phase 8: Detecting geolocation and applying node labels")
	if err := applyNodeLabels(ctx, cfg, sshPool, primaryMaster); err != nil {
		return fmt.Errorf("failed to apply node labels: %w", err)
	}
	log.Infow("✅ Node labels applied")

	// Phase 9: Deploy services from YAML files
	log.Infow("Phase 9: Deploying services")
	storageMountPath := ""
	if ds.Enabled {
		storageMountPath = ds.Providers.MicroCeph.MountPath
	}
	// Determine if cluster has dedicated workers for placement constraint handling
	// sshWorkers only contains nodes with role="worker" (not "both" or "manager")
	clusterInfo := services.ClusterInfo{
		HasDedicatedWorkers: len(sshWorkers) > 0,
	}
	metrics, err := services.DeployServices(ctx, sshPool, primaryMaster, cfg.GlobalSettings.ServiceDefinitionDirectory, storageMountPath, clusterInfo)
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
func Teardown(ctx context.Context, cfg *config.Config, disconnectOverlays bool) error {
	log := logging.L().With("component", "teardown")

	startTime := time.Now()
	ds := cfg.GetDistributedStorage()
	decom := cfg.GetDecommissioning()

	// Determine if storage should be removed (decommissioning.removeStorage overrides forceRecreation)
	removeStorage := decom.ShouldRemoveStorage(ds)

	log.Infow("🔥 Starting cluster decommissioning",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
		"disconnectOverlays", disconnectOverlays,
		"removeStorage", removeStorage,
		"removeDockerSwarm", decom.ShouldRemoveDockerSwarm(),
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

	// Phase 4: Unmount distributed storage volumes on all nodes
	storageNodes := getStorageNodes(cfg)
	if ds.Enabled && len(storageNodes) > 0 {
		log.Infow("Phase 4: Unmounting distributed storage volumes")
		if err := unmountDistributedStorage(ctx, sshPool, allNodes, cfg); err != nil {
			log.Warnw("failed to unmount distributed storage", "error", err)
		} else {
			log.Infow("✅ Distributed storage unmounted")
		}
	} else {
		log.Infow("Phase 4: Skipping storage unmount (not enabled)")
	}

	// Phase 5: Teardown distributed storage cluster if removeStorage is enabled
	if ds.Enabled && removeStorage && len(storageNodes) > 0 {
		log.Infow("Phase 5: Tearing down distributed storage cluster")
		if err := teardownDistributedStorage(ctx, sshPool, storageNodes, cfg); err != nil {
			log.Warnw("failed to teardown distributed storage", "error", err)
		} else {
			log.Infow("✅ Distributed storage cluster removed")
		}
	} else if ds.Enabled && !removeStorage {
		log.Infow("Phase 5: Skipping storage teardown (decommissioning.removeStorage=false)")
	} else {
		log.Infow("Phase 5: Skipping storage teardown (not enabled)")
	}

	// Phase 6: Disconnect overlay networks if requested
	if disconnectOverlays {
		log.Infow("Phase 6: Disconnecting overlay networks")
		if err := removeOverlayNetworks(ctx, sshPool, primaryManager); err != nil {
			log.Warnw("failed to disconnect overlay networks", "error", err)
		} else {
			log.Infow("✅ Overlay networks disconnected")
		}
	} else {
		log.Infow("Phase 6: Skipping overlay disconnect (decommissioning.disconnectOverlays=false)")
	}

	// Calculate final metrics
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	log.Infow("🎉 Cluster decommissioning complete!",
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

	// Get key type from config (default: ed25519)
	keyType := cfg.GlobalSettings.SSHKeyType
	if keyType == "" {
		keyType = sshkeys.DefaultKeyType
	}

	// Always generate SSH key pair for future passwordless access
	// Even if nodes currently use password auth, we'll install the key for subsequent operations
	keyPair, err := sshkeys.EnsureKeyPair("", keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure SSH key pair: %w", err)
	}

	log.Infow("SSH key pair ready", "privateKey", keyPair.PrivateKeyPath, "keyType", keyType)

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
			"hostname", node.SSHFQDNorIP,
			"user", node.Username,
			"port", node.SSHPort,
			"authMethod", authMethod,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "installing public key for future automatic authentication"))

		authConfig := ssh.AuthConfig{
			Username:           node.Username,
			Password:           node.Password,
			PrivateKeyPath:     node.PrivateKeyPath,
			PrivateKeyPassword: node.PrivateKeyPassword,
			Port:               node.SSHPort,
		}

		tempPool := ssh.NewPool(map[string]ssh.AuthConfig{
			node.SSHFQDNorIP: authConfig,
		})

		// Install public key
		installCmd := fmt.Sprintf(
			"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "+
				"echo '%s' >> ~/.ssh/authorized_keys && "+
				"chmod 600 ~/.ssh/authorized_keys && "+
				"sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys",
			strings.TrimSpace(keyPair.PublicKey),
		)

		if _, stderr, err := tempPool.Run(ctx, node.SSHFQDNorIP, installCmd); err != nil {
			nodeLog.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "failed to install public key"), "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "public key installed successfully"))
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
			"hostname", node.SSHFQDNorIP,
			"user", node.Username,
			"port", node.SSHPort,
			"authMethod", authMethod,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "configuring SSH connection"))

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
			authConfig.PrivateKeyPassword = node.PrivateKeyPassword
		}

		authConfigs[node.SSHFQDNorIP] = authConfig
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
			"hostname", node.SSHFQDNorIP,
			"role", node.Role,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "starting dependency installation"))

		// Install Docker
		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "installing Docker"))
		if err := installDocker(ctx, sshPool, node.SSHFQDNorIP); err != nil {
			return fmt.Errorf("failed to install Docker on %s: %w", node.SSHFQDNorIP, err)
		}
		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "Docker installed"))

		// Note: MicroCeph installation is handled in Phase 6 (storage setup) by the provider
		// to avoid duplicate installation and ensure proper cluster formation

		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "all dependencies installed"))
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

	// Fix any interrupted dpkg state before apt operations
	// This handles "dpkg was interrupted, you must manually run 'dpkg --configure -a'" errors
	logging.L().Debugw("repairing dpkg state if needed", "node", host)
	sshPool.Run(ctx, host, "DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true")

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
			"hostname", node.SSHFQDNorIP,
			"provider", provider,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "configuring overlay network"))
		if err := configureOverlayOnNode(ctx, sshPool, node, provider, overlayConfig); err != nil {
			return fmt.Errorf("failed to configure %s overlay on %s: %w", provider, node.SSHFQDNorIP, err)
		}
		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "overlay network configured"))
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
	log := logging.L().With("node", node.SSHFQDNorIP, "provider", "netbird")

	// Check if netbird is already running
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "checking netbird status"))
	checkCmd := "netbird status 2>/dev/null | grep -q 'Status: Connected' && echo 'CONNECTED' || echo 'NOT_CONNECTED'"
	stdout, _, err := sshPool.Run(ctx, node.SSHFQDNorIP, checkCmd)
	if err == nil && stdout == "CONNECTED\n" {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird already connected, skipping installation"))
		return nil
	}

	// Check if netbird is installed
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "checking if netbird is installed"))
	checkInstallCmd := "command -v netbird &> /dev/null && echo 'INSTALLED' || echo 'NOT_INSTALLED'"
	stdout, _, _ = sshPool.Run(ctx, node.SSHFQDNorIP, checkInstallCmd)

	if stdout != "INSTALLED\n" {
		// Fix any interrupted dpkg state before apt operations
		sshPool.Run(ctx, node.SSHFQDNorIP, "DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true")

		// Install netbird if not present (with retry)
		installURL := "https://pkgs.netbird.io/install.sh"
		installCmd := fmt.Sprintf("curl -fsSL %s | sh", installURL)

		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird not found, downloading and installing"))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("download URL: %s", installURL)))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("install command: %s", installCmd)))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "executing installation (this may take 30-60 seconds)..."))

		retryCfg := retry.NetworkConfig(fmt.Sprintf("install-netbird-%s", node.SSHFQDNorIP))
		err = retry.Do(ctx, retryCfg, func() error {
			_, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, installCmd)
			if err != nil {
				log.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird installation failed"), "error", err, "stderr", stderr)
				return fmt.Errorf("failed to install netbird: %w (stderr: %s)", err, stderr)
			}
			if stderr != "" {
				log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird installation completed"), "stderr", stderr)
			} else {
				log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird installation completed"))
			}
			return nil
		})
		if err != nil {
			return err
		}
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird installed successfully"))
	} else {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird already installed"))
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

	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "starting netbird and connecting to network"))
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("command: %s", maskedCmd)))
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "executing netbird up..."))

	retryCfg := retry.NetworkConfig(fmt.Sprintf("start-netbird-%s", node.SSHFQDNorIP))
	err = retry.Do(ctx, retryCfg, func() error {
		_, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, upCmd)
		if err != nil {
			log.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird up failed"), "error", err, "stderr", stderr)
			return fmt.Errorf("failed to start netbird: %w (stderr: %s)", err, stderr)
		}
		if stderr != "" {
			log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird up completed"), "stderr", stderr)
		} else {
			log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird up completed"))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Verify connection
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "verifying netbird connection"))
	verifyCmd := "netbird status"
	verifyStdout, verifyStderr, verifyErr := sshPool.Run(ctx, node.SSHFQDNorIP, verifyCmd)
	if verifyErr != nil {
		log.Warnw(formatNodeMessage("⚠", node.SSHFQDNorIP, node.NewHostname, node.Role, "failed to verify netbird status"), "error", verifyErr, "stderr", verifyStderr)
	} else {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird status"), "status", verifyStdout)
	}

	log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "netbird connected successfully"))
	return nil
}

// configureTailscaleOnNode configures Tailscale on a single node idempotently.
func configureTailscaleOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.SSHFQDNorIP, "provider", "tailscale")

	// Check if tailscale is already running
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "checking tailscale status"))
	checkCmd := "tailscale status --json 2>/dev/null | grep -q '\"BackendState\":\"Running\"' && echo 'RUNNING' || echo 'NOT_RUNNING'"
	stdout, _, err := sshPool.Run(ctx, node.SSHFQDNorIP, checkCmd)
	if err == nil && stdout == "RUNNING\n" {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale already running, skipping installation"))
		return nil
	}

	// Check if tailscale is installed
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "checking if tailscale is installed"))
	checkInstallCmd := "command -v tailscale &> /dev/null && echo 'INSTALLED' || echo 'NOT_INSTALLED'"
	stdout, _, _ = sshPool.Run(ctx, node.SSHFQDNorIP, checkInstallCmd)

	if stdout != "INSTALLED\n" {
		// Fix any interrupted dpkg state before apt operations
		sshPool.Run(ctx, node.SSHFQDNorIP, "DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true")

		// Install tailscale if not present (with retry)
		installURL := "https://tailscale.com/install.sh"
		installCmd := fmt.Sprintf("curl -fsSL %s | sh", installURL)

		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale not found, downloading and installing"))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("download URL: %s", installURL)))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("install command: %s", installCmd)))
		log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "executing installation (this may take 30-60 seconds)..."))

		retryCfg := retry.NetworkConfig(fmt.Sprintf("install-tailscale-%s", node.SSHFQDNorIP))
		err = retry.Do(ctx, retryCfg, func() error {
			_, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, installCmd)
			if err != nil {
				log.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale installation failed"), "error", err, "stderr", stderr)
				return fmt.Errorf("failed to install tailscale: %w (stderr: %s)", err, stderr)
			}
			if stderr != "" {
				log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale installation completed"), "stderr", stderr)
			} else {
				log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale installation completed"))
			}
			return nil
		})
		if err != nil {
			return err
		}
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale installed successfully"))
	} else {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale already installed"))
	}

	// Start tailscale with auth key if provided (with retry)
	upCmd := "tailscale up"
	maskedCmd := "tailscale up"
	if overlayConfig != "" {
		upCmd = fmt.Sprintf("tailscale up --authkey='%s'", overlayConfig)
		// Mask the auth key for logging
		maskedCmd = fmt.Sprintf("tailscale up --authkey='%s'", maskSetupKey(overlayConfig))
	}

	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "starting tailscale and connecting to network"))
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("command: %s", maskedCmd)))
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "executing tailscale up..."))

	retryCfg := retry.NetworkConfig(fmt.Sprintf("start-tailscale-%s", node.SSHFQDNorIP))
	err = retry.Do(ctx, retryCfg, func() error {
		_, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, upCmd)
		if err != nil {
			log.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale up failed"), "error", err, "stderr", stderr)
			return fmt.Errorf("failed to start tailscale: %w (stderr: %s)", err, stderr)
		}
		if stderr != "" {
			log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale up completed"), "stderr", stderr)
		} else {
			log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale up completed"))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Verify connection
	log.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "verifying tailscale connection"))
	verifyCmd := "tailscale status"
	verifyStdout, verifyStderr, verifyErr := sshPool.Run(ctx, node.SSHFQDNorIP, verifyCmd)
	if verifyErr != nil {
		log.Warnw(formatNodeMessage("⚠", node.SSHFQDNorIP, node.NewHostname, node.Role, "failed to verify tailscale status"), "error", verifyErr, "stderr", verifyStderr)
	} else {
		log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale status"), "status", verifyStdout)
	}

	log.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "tailscale connected successfully"))
	return nil
}

// configureWireGuardOnNode configures WireGuard on a single node idempotently.
func configureWireGuardOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.SSHFQDNorIP, "provider", "wireguard")

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
	stdout, _, err := sshPool.Run(ctx, node.SSHFQDNorIP, checkCmd)
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
	if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, installCmd); err != nil {
		return fmt.Errorf("failed to install wireguard: %w (stderr: %s)", err, stderr)
	}

	// Start wireguard interface
	upCmd := fmt.Sprintf("wg-quick up %s", overlayConfig)
	if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, upCmd); err != nil {
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

// getStorageNodes returns the hostnames of all enabled nodes with storage enabled.
func getStorageNodes(cfg *config.Config) []string {
	var nodes []string
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		if node.StorageEnabled {
			nodes = append(nodes, node.SSHFQDNorIP)
		}
	}
	return nodes
}

// getStorageNodesByRole returns storage-enabled nodes categorized by role.
// For MicroCeph: managers become MON nodes, workers become OSD nodes.
// "both" nodes are managers that also get OSD storage (they appear in both categories).
// Returns: managers (MON), workers (OSD), allUnique (deduplicated list of all storage nodes).
func getStorageNodesByRole(cfg *config.Config) (managers []string, workers []string, allUnique []string) {
	seen := make(map[string]bool)
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		if !node.StorageEnabled {
			continue
		}
		switch node.Role {
		case "manager":
			managers = append(managers, node.SSHFQDNorIP)
		case "worker":
			workers = append(workers, node.SSHFQDNorIP)
		case "both":
			// "both" nodes act as managers for MON and also get OSD storage like workers
			managers = append(managers, node.SSHFQDNorIP)
			workers = append(workers, node.SSHFQDNorIP)
		}
		// Build deduplicated list
		if !seen[node.SSHFQDNorIP] {
			seen[node.SSHFQDNorIP] = true
			allUnique = append(allUnique, node.SSHFQDNorIP)
		}
	}
	return
}

// categorizeNodes returns enabled managers and workers.
// For Docker Swarm: "both" nodes join as managers (they can run manager workloads).
func categorizeNodes(cfg *config.Config) (managers []string, workers []string) {
	enabledNodes := getEnabledNodes(cfg)
	for _, node := range enabledNodes {
		switch node.Role {
		case "manager", "both":
			// "both" nodes join swarm as managers
			managers = append(managers, node.SSHFQDNorIP)
		case "worker":
			workers = append(workers, node.SSHFQDNorIP)
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
			"hostname", node.SSHFQDNorIP,
			"newHostname", node.NewHostname,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "checking current hostname"))

		// Check current hostname
		stdout, _, err := sshPool.Run(ctx, node.SSHFQDNorIP, "hostname")
		if err == nil && stdout == node.NewHostname+"\n" {
			nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "hostname already set, skipping"))
			continue
		}

		// Set hostname idempotently
		setCmd := fmt.Sprintf("hostnamectl set-hostname %s", node.NewHostname)
		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, fmt.Sprintf("executing hostname change (command: %s)", setCmd)))

		if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, setCmd); err != nil {
			return fmt.Errorf("failed to set hostname on %s: %w (stderr: %s)", node.SSHFQDNorIP, err, stderr)
		}

		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "hostname set successfully"))
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
			"hostname", node.SSHFQDNorIP,
			"user", node.Username,
			"port", node.SSHPort,
		)

		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "setting root password"))

		// Use chpasswd to set password
		// Format: username:password
		setCmd := fmt.Sprintf("echo 'root:%s' | chpasswd", password)

		if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, setCmd); err != nil {
			return fmt.Errorf("failed to set root password on %s: %w (stderr: %s)", node.SSHFQDNorIP, err, stderr)
		}

		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "root password set successfully"))
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
				return fmt.Errorf("failed to evaluate conditions for script %s on node %s: %w", script.Name, node.SSHFQDNorIP, err)
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
				"hostname", node.SSHFQDNorIP,
				"user", node.Username,
				"port", node.SSHPort,
			)

			nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "executing script on node"))
			if err := executeScriptOnNode(ctx, sshPool, node, script); err != nil {
				if script.ContinueOnError {
					nodeLog.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "script failed but continuing (continueOnError=true)"), "error", err)
				} else {
					return fmt.Errorf("failed to execute script %s on %s: %w", script.Name, node.SSHFQDNorIP, err)
				}
			} else {
				nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "script executed successfully on node"))
			}
		}

		scriptLog.Infow("✓ script executed successfully on all nodes")
	}

	return nil
}

// executeScriptOnNode executes a single script on a single node.
func executeScriptOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, script config.ScriptConfig) error {
	log := logging.L().With("node", node.SSHFQDNorIP, "script", script.Name)

	// Determine if script is local or remote
	isRemote := len(script.Source) > 7 && (script.Source[:7] == "http://" || script.Source[:8] == "https://")

	var scriptPath string
	if isRemote {
		// Download remote script
		scriptPath = fmt.Sprintf("/tmp/clusterctl-script-%s.sh", script.Name)
		downloadCmd := fmt.Sprintf("curl -fsSL -o %s %s", scriptPath, script.Source)
		if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, downloadCmd); err != nil {
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
	if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, chmodCmd); err != nil {
		return fmt.Errorf("failed to make script executable: %w (stderr: %s)", err, stderr)
	}

	// Execute script with parameters
	execCmd := scriptPath
	if script.Parameters != "" {
		execCmd = fmt.Sprintf("%s %s", scriptPath, script.Parameters)
	}

	stdout, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, execCmd)
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

		nodeLog := log.With("node", node.SSHFQDNorIP)
		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "initiating reboot with 15 second delay"))

		// Initiate reboot with 15 second delay and terminate SSH connection cleanly
		rebootCmd := "nohup sh -c 'sleep 15 && reboot' > /dev/null 2>&1 &"
		if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, rebootCmd); err != nil {
			// Ignore errors as the connection may be terminated
			nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "reboot initiated (connection may have terminated)"), "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "reboot scheduled successfully"))
		}
	}

	return nil
}

// applyNodeLabels detects geolocation and applies automatic and custom labels to Docker nodes.
func applyNodeLabels(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool, primaryMaster string) error {
	log := logging.L().With("phase", "labels")
	ds := cfg.GetDistributedStorage()

	// Detect geolocation for all nodes in parallel
	log.Infow("detecting geolocation for all nodes")
	hostnames := make([]string, 0, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		hostnames = append(hostnames, node.SSHFQDNorIP)
	}
	geoInfoMap := geolocation.DetectGeoLocationBatch(ctx, sshPool, hostnames)

	// Apply labels to each node
	for _, node := range cfg.Nodes {
		nodeLog := log.With("node", node.SSHFQDNorIP)
		geoInfo := geoInfoMap[node.SSHFQDNorIP]

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

		// Distributed storage labels
		if ds.Enabled && node.StorageEnabled {
			labels["storage.enabled"] = "true"
			labels["storage.provider"] = string(ds.Provider)

			// Add mount path label
			mountPath := ds.Providers.MicroCeph.MountPath
			if mountPath != "" {
				labels["storage.mount-path"] = mountPath
			}
		} else {
			labels["storage.enabled"] = "false"
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

		// Determine the Docker Swarm node name (hostname, not SSH address)
		// Use NewHostname if set, otherwise fetch the hostname from the node
		swarmNodeName := node.NewHostname
		if swarmNodeName == "" {
			stdout, _, err := sshPool.Run(ctx, node.SSHFQDNorIP, "hostname 2>/dev/null")
			if err == nil {
				swarmNodeName = strings.TrimSpace(stdout)
			}
		}
		if swarmNodeName == "" {
			nodeLog.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "could not determine Docker Swarm node name, skipping labels"))
			continue
		}

		// Apply labels to the node
		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "applying labels"), "count", len(labels), "swarmNodeName", swarmNodeName)
		for key, value := range labels {
			// Escape special characters in label values
			escapedValue := strings.ReplaceAll(value, `"`, `\"`)
			labelCmd := fmt.Sprintf(`docker node update --label-add "%s=%s" $(docker node ls --filter "name=%s" -q)`,
				key, escapedValue, swarmNodeName)

			if _, stderr, err := sshPool.Run(ctx, primaryMaster, labelCmd); err != nil {
				nodeLog.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "failed to apply label"), "key", key, "value", value, "error", err, "stderr", stderr)
			} else {
				nodeLog.Debugw(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "label applied"), "key", key, "value", value)
			}
		}

		nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "labels applied successfully"), "total", len(labels))
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
		nodeLog := log.With("node", node.SSHFQDNorIP)
		nodeLog.Infow(formatNodeMessage("→", node.SSHFQDNorIP, node.NewHostname, node.Role, "removing public key from node"))

		// Remove the public key from authorized_keys
		removeCmd := fmt.Sprintf(
			"sed -i '\\|%s|d' ~/.ssh/authorized_keys 2>/dev/null || true",
			strings.TrimSpace(keyPair.PublicKey),
		)

		if _, stderr, err := sshPool.Run(ctx, node.SSHFQDNorIP, removeCmd); err != nil {
			nodeLog.Warnw(formatNodeMessage("✗", node.SSHFQDNorIP, node.NewHostname, node.Role, "failed to remove public key"), "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow(formatNodeMessage("✓", node.SSHFQDNorIP, node.NewHostname, node.Role, "public key removed successfully"))
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

// unmountDistributedStorage unmounts distributed storage volumes on all nodes.
func unmountDistributedStorage(ctx context.Context, sshPool *ssh.Pool, nodes []string, cfg *config.Config) error {
	log := logging.L().With("component", "teardown-storage-unmount")
	ds := cfg.GetDistributedStorage()

	// Get mount path from provider config
	mountPath := ds.Providers.MicroCeph.MountPath
	if mountPath == "" {
		mountPath = "/mnt/cephfs"
	}

	for _, node := range nodes {
		unmountCmd := fmt.Sprintf("umount %s 2>/dev/null || true", mountPath)
		log.Infow("unmounting distributed storage", "host", node, "mountPoint", mountPath, "command", unmountCmd)
		if _, stderr, err := sshPool.Run(ctx, node, unmountCmd); err != nil {
			log.Warnw("failed to unmount storage", "host", node, "error", err, "stderr", stderr)
		} else {
			log.Infow("✅ storage unmounted", "host", node)
		}

		// Remove from fstab
		removeFstabCmd := fmt.Sprintf("sed -i '\\|%s|d' /etc/fstab", mountPath)
		log.Infow("removing from fstab", "host", node, "command", removeFstabCmd)
		if _, stderr, err := sshPool.Run(ctx, node, removeFstabCmd); err != nil {
			log.Warnw("failed to remove from fstab", "host", node, "error", err, "stderr", stderr)
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

// createDefaultOverlayNetworks creates the default internal and external overlay networks via SSH.
// Uses 10.10.x.x and 10.20.x.x ranges to avoid conflicts with Docker's default bridge (172.17.0.0/16).
// The external network is created as an ingress network for routing mesh.
func createDefaultOverlayNetworks(ctx context.Context, sshPool *ssh.Pool, primaryManager string) error {
	log := logging.L().With("component", "overlay-networks")

	// First, remove the default "ingress" network to free up the ingress slot
	// Docker only allows one ingress network at a time
	log.Infow("checking for default ingress network to replace")
	removeIngressCmd := "docker network rm ingress 2>/dev/null || true"
	log.Infow("removing default ingress network", "command", removeIngressCmd)
	if _, stderr, err := sshPool.Run(ctx, primaryManager, removeIngressCmd); err != nil {
		log.Warnw("could not remove default ingress network (may have services attached)", "error", err, "stderr", stderr)
	}

	// Define the networks with their specs
	// Uses 10.x.x.x ranges to avoid conflict with Docker bridge (172.17.0.0/16)
	networks := []struct {
		Name     string
		Subnet   string
		Gateway  string
		Internal bool
		Ingress  bool
	}{
		{
			Name:     swarm.DefaultInternalNetworkName,
			Subnet:   "10.10.0.0/20",
			Gateway:  "10.10.0.1",
			Internal: true,
			Ingress:  false,
		},
		{
			Name:     swarm.DefaultExternalNetworkName,
			Subnet:   "10.20.0.0/20",
			Gateway:  "10.20.0.1",
			Internal: false,
			Ingress:  true, // This is the ingress network for routing mesh
		},
	}

	for _, network := range networks {
		// Check if network already exists with correct subnet
		checkSubnetCmd := fmt.Sprintf("docker network inspect %s --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null", network.Name)
		existingSubnet, _, _ := sshPool.Run(ctx, primaryManager, checkSubnetCmd)
		existingSubnet = strings.TrimSpace(existingSubnet)

		if existingSubnet != "" {
			if existingSubnet == network.Subnet {
				log.Infow("overlay network already exists with correct subnet", "network", network.Name, "subnet", existingSubnet)
				continue
			}
			// Subnet mismatch - need to remove and recreate
			log.Warnw("network exists with different subnet, will recreate", "network", network.Name, "existing", existingSubnet, "desired", network.Subnet)
			removeCmd := fmt.Sprintf("docker network rm %s", network.Name)
			log.Infow("removing network with wrong subnet", "command", removeCmd)
			if _, stderr, err := sshPool.Run(ctx, primaryManager, removeCmd); err != nil {
				return fmt.Errorf("failed to remove network %s with wrong subnet: %w (stderr: %s)", network.Name, err, stderr)
			}
		}

		// Build create command
		createCmd := "docker network create --driver overlay"
		if network.Ingress {
			createCmd += " --ingress"
		} else {
			// Only attachable for non-ingress networks (ingress cannot be attachable)
			createCmd += " --attachable"
		}
		createCmd += fmt.Sprintf(" --subnet %s --gateway %s", network.Subnet, network.Gateway)
		if network.Internal {
			createCmd += " --internal"
		}
		createCmd += " " + network.Name

		log.Infow("creating overlay network", "host", primaryManager, "network", network.Name, "command", createCmd)
		if _, stderr, err := sshPool.Run(ctx, primaryManager, createCmd); err != nil {
			return fmt.Errorf("failed to create network %s: %w (stderr: %s)", network.Name, err, stderr)
		}

		netType := "overlay"
		if network.Ingress {
			netType = "ingress"
		} else if network.Internal {
			netType = "internal"
		}
		log.Infow("✅ overlay network created", "network", network.Name, "subnet", network.Subnet, "type", netType)
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

// getStorageHostnames returns the appropriate hostnames for distributed storage based on overlay provider.
// If an overlay provider is configured, it retrieves the overlay hostnames (e.g., netbird FQDN).
// Otherwise, it returns the SSH connection hostnames.
func getStorageHostnames(ctx context.Context, sshPool *ssh.Pool, cfg *config.Config, sshHostnames []string) ([]string, error) {
	log := logging.L().With("component", "storage-hostnames")

	provider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.OverlayProvider))

	// If no overlay provider, use SSH hostnames directly
	if provider == "" || provider == "none" {
		log.Infow("no overlay provider, using SSH hostnames for storage", "hostnames", sshHostnames)
		return sshHostnames, nil
	}

	// Get overlay info for each node
	overlayHostnames := make([]string, 0, len(sshHostnames))

	for _, sshHost := range sshHostnames {
		overlayInfo, err := getOverlayInfoForNode(ctx, sshPool, sshHost, provider)
		if err != nil {
			log.Warnw("failed to get overlay info, falling back to SSH hostname", "sshHost", sshHost, "error", err)
			overlayHostnames = append(overlayHostnames, sshHost)
		} else {
			log.Infow("→ overlay info for storage", "sshHost", sshHost, "fqdn", overlayInfo.FQDN, "ip", overlayInfo.IP, "interface", overlayInfo.Interface)
			overlayHostnames = append(overlayHostnames, overlayInfo.FQDN)
		}
	}

	return overlayHostnames, nil
}

// setupDistributedStorage sets up the distributed storage cluster using the provider framework.
// managers become MON nodes (cluster brain/quorum), workers become OSD nodes (data storage).
func setupDistributedStorage(ctx context.Context, sshPool *ssh.Pool, managers []string, workers []string, cfg *config.Config) error {
	ds := cfg.GetDistributedStorage()
	log := logging.L().With("component", "storage-setup", "provider", ds.Provider)

	allNodes := append(managers, workers...)
	if len(allNodes) == 0 {
		return nil
	}

	// Create the storage provider
	provider, err := storage.NewProvider(cfg)
	if err != nil {
		return fmt.Errorf("failed to create storage provider: %w", err)
	}

	// Build node info map for formatted logging
	nodeInfoMap := buildStorageNodeInfoMap(cfg)

	log.Infow("setting up distributed storage cluster",
		"provider", provider.Name(),
		"managers", len(managers),
		"workers", len(workers),
		"poolName", ds.PoolName,
		"mountPath", provider.GetMountPath())

	// Use the storage framework to set up the cluster
	if err := storage.SetupCluster(ctx, sshPool, provider, managers, workers, cfg, nodeInfoMap); err != nil {
		return fmt.Errorf("storage cluster setup failed: %w", err)
	}

	return nil
}

// buildStorageNodeInfoMap creates a map of SSH hostname/IP to NodeInfo for storage logging.
func buildStorageNodeInfoMap(cfg *config.Config) map[string]storage.NodeInfo {
	nodeInfoMap := make(map[string]storage.NodeInfo)
	for i := range cfg.Nodes {
		node := &cfg.Nodes[i]
		if !node.IsEnabled() || !node.StorageEnabled {
			continue
		}
		nodeInfoMap[node.SSHFQDNorIP] = storage.NodeInfo{
			SSHFQDNorIP: node.SSHFQDNorIP,
			NewHostname: node.NewHostname,
			Role:        node.Role,
		}
	}
	return nodeInfoMap
}

// teardownDistributedStorage tears down an existing distributed storage cluster using the provider framework.
func teardownDistributedStorage(ctx context.Context, sshPool *ssh.Pool, nodes []string, cfg *config.Config) error {
	ds := cfg.GetDistributedStorage()
	log := logging.L().With("component", "storage-teardown", "provider", ds.Provider)

	if len(nodes) == 0 {
		return nil
	}

	// Build node info map for formatted logging
	nodeInfoMap := buildStorageNodeInfoMap(cfg)

	// Helper to format node messages
	fmtNode := func(prefix, node, message string) string {
		if info, ok := nodeInfoMap[node]; ok {
			return logging.FormatNodeMessage(prefix, info.SSHFQDNorIP, info.NewHostname, info.Role, message)
		}
		return logging.FormatNodeMessage(prefix, node, "", "", message)
	}

	// Create the storage provider
	provider, err := storage.NewProvider(cfg)
	if err != nil {
		// If we can't create a provider, fall back to basic cleanup
		log.Warnw("failed to create storage provider, using basic cleanup", "error", err)
		return basicStorageTeardown(ctx, sshPool, nodes, cfg)
	}

	log.Infow("tearing down distributed storage cluster",
		"provider", provider.Name(),
		"nodes", len(nodes))

	var lastErr error
	for _, node := range nodes {
		log.Infow(fmtNode("→", node, "cleaning up storage"))

		// Unmount storage
		if err := provider.Unmount(ctx, sshPool, node); err != nil {
			log.Warnw(fmtNode("⚠", node, fmt.Sprintf("failed to unmount storage: %v", err)))
			lastErr = err
		}

		// Teardown the provider
		if err := provider.Teardown(ctx, sshPool, node); err != nil {
			log.Warnw(fmtNode("⚠", node, fmt.Sprintf("failed to teardown storage: %v", err)))
			lastErr = err
		}

		log.Infow(fmtNode("✓", node, "cleanup complete"))
	}

	log.Infow("✓ distributed storage teardown complete")
	return lastErr
}

// basicStorageTeardown performs basic storage cleanup when provider is unavailable.
func basicStorageTeardown(ctx context.Context, sshPool *ssh.Pool, nodes []string, cfg *config.Config) error {
	ds := cfg.GetDistributedStorage()
	log := logging.L().With("component", "storage-teardown-basic")

	// Build node info map for formatted logging
	nodeInfoMap := buildStorageNodeInfoMap(cfg)

	// Helper to format node messages
	fmtNode := func(prefix, node, message string) string {
		if info, ok := nodeInfoMap[node]; ok {
			return logging.FormatNodeMessage(prefix, info.SSHFQDNorIP, info.NewHostname, info.Role, message)
		}
		return logging.FormatNodeMessage(prefix, node, "", "", message)
	}

	// Get mount path from provider config
	mountPath := ds.Providers.MicroCeph.MountPath
	if mountPath == "" {
		mountPath = "/mnt/cephfs"
	}

	for _, node := range nodes {
		log.Infow(fmtNode("→", node, "basic cleanup"))

		// Unmount storage
		unmountCmd := fmt.Sprintf("umount -f %s 2>/dev/null || umount -l %s 2>/dev/null || true",
			mountPath, mountPath)
		_, _, _ = sshPool.Run(ctx, node, unmountCmd)

		// Remove mount directory
		removeMountCmd := fmt.Sprintf("rm -rf %s 2>/dev/null || true", mountPath)
		_, _, _ = sshPool.Run(ctx, node, removeMountCmd)

		// Remove MicroCeph if installed
		removeCmds := []string{
			"snap remove microceph --purge 2>/dev/null || true",
			"rm -rf /var/snap/microceph 2>/dev/null || true",
			"rm -rf /var/lib/ceph 2>/dev/null || true",
		}

		for _, cmd := range removeCmds {
			_, _, _ = sshPool.Run(ctx, node, cmd)
		}

		log.Infow(fmtNode("✓", node, "basic cleanup complete"))
	}

	return nil
}

// verifyStorageTeardown checks if storage has been fully removed from a node.
func verifyStorageTeardown(ctx context.Context, sshPool *ssh.Pool, node string, cfg *config.Config) bool {
	ds := cfg.GetDistributedStorage()
	log := logging.L().With("component", "storage-verify")
	allClean := true

	// Build node info map for formatted logging
	nodeInfoMap := buildStorageNodeInfoMap(cfg)

	// Helper to format node messages
	fmtNode := func(prefix, message string) string {
		if info, ok := nodeInfoMap[node]; ok {
			return logging.FormatNodeMessage(prefix, info.SSHFQDNorIP, info.NewHostname, info.Role, message)
		}
		return logging.FormatNodeMessage(prefix, node, "", "", message)
	}

	// Check 1: MicroCeph snap should not be installed
	snapCheck := "snap list microceph 2>/dev/null"
	stdout, _, _ := sshPool.Run(ctx, node, snapCheck)
	if strings.Contains(stdout, "microceph") {
		log.Warnw(fmtNode("⚠", "MicroCeph snap still installed"))
		allClean = false
	}

	// Check 2: No ceph processes should be running (excluding kernel worker threads)
	// Kernel worker threads like [kworker/R-ceph-] are normal and should be ignored
	procCheck := "pgrep -la ceph 2>/dev/null | grep -v '\\[kworker' || true"
	stdout, _, _ = sshPool.Run(ctx, node, procCheck)
	if strings.TrimSpace(stdout) != "" {
		log.Warnw(fmtNode("⚠", "Ceph processes still running"))
		allClean = false
	}

	// Check 3: Mount path should not exist or be empty
	mountPath := ds.Providers.MicroCeph.MountPath
	if mountPath == "" {
		mountPath = "/mnt/cephfs"
	}
	mountCheck := fmt.Sprintf("mountpoint -q %s 2>/dev/null && echo 'mounted' || echo 'not mounted'", mountPath)
	stdout, _, _ = sshPool.Run(ctx, node, mountCheck)
	if strings.Contains(stdout, "mounted") && !strings.Contains(stdout, "not mounted") {
		log.Warnw(fmtNode("⚠", fmt.Sprintf("mount path still mounted: %s", mountPath)))
		allClean = false
	}

	// Check 4: /var/snap/microceph should not exist
	dirCheck := "test -d /var/snap/microceph && echo 'exists' || echo 'clean'"
	stdout, _, _ = sshPool.Run(ctx, node, dirCheck)
	if strings.Contains(stdout, "exists") {
		log.Warnw(fmtNode("⚠", "/var/snap/microceph directory still exists"))
		allClean = false
	}

	if allClean {
		log.Infow(fmtNode("✓", "verified clean"))
	}

	return allClean
}