package deployer

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/config"
	"clusterctl/internal/geolocation"
	"clusterctl/internal/logging"
	"clusterctl/internal/orchestrator"
	"clusterctl/internal/services"
	"clusterctl/internal/ssh"
	"clusterctl/internal/sshkeys"
)

// Deploy orchestrates the complete cluster deployment from the configuration.
func Deploy(ctx context.Context, cfg *config.Config) error {
	log := logging.L().With("component", "deployer")

	log.Infow("🚀 Starting cluster deployment",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
	)

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
	glusterWorkers := getGlusterWorkers(cfg)
	if len(glusterWorkers) > 0 {
		log.Infow("Phase 6: Setting up GlusterFS", "workers", len(glusterWorkers))
		if err := orchestrator.GlusterSetup(ctx, sshPool, glusterWorkers,
			cfg.GlobalSettings.GlusterVolume,
			cfg.GlobalSettings.GlusterMount,
			cfg.GlobalSettings.GlusterBrick); err != nil {
			return fmt.Errorf("failed to setup GlusterFS: %w", err)
		}
		log.Infow("✅ GlusterFS setup complete")
	} else {
		log.Infow("Phase 6: Skipping GlusterFS (no workers with glusterEnabled)")
	}

	// Phase 7: Setup Docker Swarm
	log.Infow("Phase 7: Setting up Docker Swarm")
	managers, workers := categorizeNodes(cfg)
	if len(managers) == 0 {
		return fmt.Errorf("no manager nodes found")
	}
	primaryMaster := managers[0] // Use first manager as primary
	if err := orchestrator.SwarmSetup(ctx, sshPool, primaryMaster, managers, workers, primaryMaster); err != nil {
		return fmt.Errorf("failed to setup Docker Swarm: %w", err)
	}
	log.Infow("✅ Docker Swarm setup complete", "primaryMaster", primaryMaster)

	// Phase 8: Detect geolocation and apply node labels
	log.Infow("Phase 8: Detecting geolocation and applying node labels")
	if err := applyNodeLabels(ctx, cfg, sshPool, primaryMaster); err != nil {
		return fmt.Errorf("failed to apply node labels: %w", err)
	}
	log.Infow("✅ Node labels applied")

	// Phase 9: Deploy services from YAML files
	log.Infow("Phase 9: Deploying services")
	metrics, err := services.DeployServices(ctx, sshPool, primaryMaster, cfg.GlobalSettings.ServicesDir)
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

	log.Infow("🎉 Cluster deployment complete!")
	return nil
}

// prepareSSHKeys ensures SSH key pair exists and installs public keys on nodes that need it.
func prepareSSHKeys(cfg *config.Config) (*sshkeys.KeyPair, error) {
	log := logging.L().With("component", "ssh-keys")

	// Check if any nodes use automatic key pair
	needsKeyPair := false
	for _, node := range cfg.Nodes {
		if node.UseSSHAutomaticKeyPair {
			needsKeyPair = true
			break
		}
	}

	if !needsKeyPair {
		log.Infow("no nodes use automatic SSH key pair, skipping key generation")
		return nil, nil
	}

	// Ensure key pair exists (generate if needed)
	keyPair, err := sshkeys.EnsureKeyPair("")
	if err != nil {
		return nil, fmt.Errorf("failed to ensure SSH key pair: %w", err)
	}

	log.Infow("SSH key pair ready", "privateKey", keyPair.PrivateKeyPath)

	// Install public key on nodes that don't use automatic key pair
	// (these nodes will use password/privateKeyPath for initial connection)
	ctx := context.Background()
	for _, node := range cfg.Nodes {
		if node.UseSSHAutomaticKeyPair {
			continue // Will use automatic key pair directly
		}

		// Connect using password or privateKeyPath and install public key
		nodeLog := log.With("node", node.Hostname)
		nodeLog.Infow("installing public key on node")

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
			nodeLog.Warnw("failed to install public key", "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow("public key installed successfully")
		}
	}

	return keyPair, nil
}

// createSSHPool creates an SSH connection pool from the configuration.
func createSSHPool(cfg *config.Config, keyPair *sshkeys.KeyPair) (*ssh.Pool, error) {
	authConfigs := make(map[string]ssh.AuthConfig)

	for _, node := range cfg.Nodes {
		authConfig := ssh.AuthConfig{
			Username: node.Username,
			Port:     node.SSHPort,
		}

		if node.UseSSHAutomaticKeyPair && keyPair != nil {
			// Use automatic key pair
			authConfig.PrivateKeyPath = keyPair.PrivateKeyPath
		} else {
			// Use configured credentials
			authConfig.Password = node.Password
			authConfig.PrivateKeyPath = node.PrivateKeyPath
		}

		authConfigs[node.Hostname] = authConfig
	}

	return ssh.NewPool(authConfigs), nil
}

// installDependencies installs required dependencies on all nodes.
func installDependencies(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "dependencies")

	for _, node := range cfg.Nodes {
		log.Infow("installing dependencies", "node", node.Hostname, "role", node.Role)

		// Install Docker
		if err := installDocker(ctx, sshPool, node.Hostname); err != nil {
			return fmt.Errorf("failed to install Docker on %s: %w", node.Hostname, err)
		}

		// Install GlusterFS if needed
		if node.GlusterEnabled {
			if err := installGlusterFS(ctx, sshPool, node.Hostname, true); err != nil {
				return fmt.Errorf("failed to install GlusterFS on %s: %w", node.Hostname, err)
			}
		} else if node.Role == "manager" && len(getGlusterWorkers(cfg)) > 0 {
			// Managers need GlusterFS client if any workers have GlusterFS
			if err := installGlusterFS(ctx, sshPool, node.Hostname, false); err != nil {
				return fmt.Errorf("failed to install GlusterFS client on %s: %w", node.Hostname, err)
			}
		}
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

	// Install Docker
	cmd := "curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker"
	_, stderr, err := sshPool.Run(ctx, host, cmd)
	if err != nil {
		return fmt.Errorf("docker install failed: %w (stderr: %s)", err, stderr)
	}
	return nil
}

// installGlusterFS installs GlusterFS on a node via SSH.
func installGlusterFS(ctx context.Context, sshPool *ssh.Pool, host string, server bool) error {
	// Check if GlusterFS is already installed
	_, _, err := sshPool.Run(ctx, host, "gluster --version")
	if err == nil {
		logging.L().Infow("GlusterFS already installed", "node", host)
		return nil
	}

	var cmd string
	if server {
		cmd = "apt-get update && apt-get install -y glusterfs-server && systemctl enable glusterd && systemctl start glusterd"
	} else {
		cmd = "apt-get update && apt-get install -y glusterfs-client"
	}

	_, stderr, err := sshPool.Run(ctx, host, cmd)
	if err != nil {
		return fmt.Errorf("glusterfs install failed: %w (stderr: %s)", err, stderr)
	}
	return nil
}

// configureOverlay configures the overlay network on all nodes idempotently.
func configureOverlay(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "overlay")

	provider := cfg.GlobalSettings.OverlayProvider
	if provider == "" || provider == "none" {
		log.Infow("no overlay provider configured, skipping overlay setup")
		return nil
	}

	overlayConfig := cfg.GlobalSettings.OverlayConfig
	log.Infow("configuring overlay network", "provider", provider, "nodes", len(cfg.Nodes))

	// Configure overlay on all nodes in parallel
	for _, node := range cfg.Nodes {
		if err := configureOverlayOnNode(ctx, sshPool, node, provider, overlayConfig); err != nil {
			return fmt.Errorf("failed to configure %s overlay on %s: %w", provider, node.Hostname, err)
		}
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

// configureNetbirdOnNode configures Netbird on a single node idempotently.
func configureNetbirdOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.Hostname, "provider", "netbird")

	// Check if netbird is already running
	checkCmd := "netbird status 2>/dev/null | grep -q 'Status: Connected' && echo 'CONNECTED' || echo 'NOT_CONNECTED'"
	stdout, _, err := sshPool.Run(ctx, node.Hostname, checkCmd)
	if err == nil && stdout == "CONNECTED\n" {
		log.Infow("netbird already connected")
		return nil
	}

	// Install netbird if not present
	installCmd := `
if ! command -v netbird &> /dev/null; then
    echo "Installing Netbird..."
    curl -fsSL https://pkgs.netbird.io/install.sh | sh
fi
`
	if _, stderr, err := sshPool.Run(ctx, node.Hostname, installCmd); err != nil {
		return fmt.Errorf("failed to install netbird: %w (stderr: %s)", err, stderr)
	}

	// Start netbird with setup key if provided
	upCmd := "netbird up"
	if overlayConfig != "" {
		upCmd = fmt.Sprintf("NB_SETUP_KEY='%s' netbird up", overlayConfig)
	}

	if _, stderr, err := sshPool.Run(ctx, node.Hostname, upCmd); err != nil {
		return fmt.Errorf("failed to start netbird: %w (stderr: %s)", err, stderr)
	}

	log.Infow("netbird configured successfully")
	return nil
}

// configureTailscaleOnNode configures Tailscale on a single node idempotently.
func configureTailscaleOnNode(ctx context.Context, sshPool *ssh.Pool, node config.NodeConfig, overlayConfig string) error {
	log := logging.L().With("node", node.Hostname, "provider", "tailscale")

	// Check if tailscale is already running
	checkCmd := "tailscale status --json 2>/dev/null | grep -q '\"BackendState\":\"Running\"' && echo 'RUNNING' || echo 'NOT_RUNNING'"
	stdout, _, err := sshPool.Run(ctx, node.Hostname, checkCmd)
	if err == nil && stdout == "RUNNING\n" {
		log.Infow("tailscale already running")
		return nil
	}

	// Install tailscale if not present
	installCmd := `
if ! command -v tailscale &> /dev/null; then
    echo "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
fi
`
	if _, stderr, err := sshPool.Run(ctx, node.Hostname, installCmd); err != nil {
		return fmt.Errorf("failed to install tailscale: %w (stderr: %s)", err, stderr)
	}

	// Start tailscale with auth key if provided
	upCmd := "tailscale up"
	if overlayConfig != "" {
		upCmd = fmt.Sprintf("TS_AUTHKEY='%s' tailscale up", overlayConfig)
	}

	if _, stderr, err := sshPool.Run(ctx, node.Hostname, upCmd); err != nil {
		return fmt.Errorf("failed to start tailscale: %w (stderr: %s)", err, stderr)
	}

	log.Infow("tailscale configured successfully")
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

// getGlusterWorkers returns the hostnames of all workers with GlusterFS enabled.
func getGlusterWorkers(cfg *config.Config) []string {
	var workers []string
	for _, node := range cfg.Nodes {
		if node.Role == "worker" && node.GlusterEnabled {
			workers = append(workers, node.Hostname)
		}
	}
	return workers
}

// categorizeNodes returns managers and workers.
func categorizeNodes(cfg *config.Config) (managers []string, workers []string) {
	for _, node := range cfg.Nodes {
		if node.Role == "manager" {
			managers = append(managers, node.Hostname)
		} else if node.Role == "worker" {
			workers = append(workers, node.Hostname)
		}
	}
	return
}

// setHostnames sets hostnames on nodes if configured.
func setHostnames(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	log := logging.L().With("phase", "hostnames")

	for _, node := range cfg.Nodes {
		if node.NewHostname == "" {
			continue
		}

		nodeLog := log.With("node", node.Hostname, "newHostname", node.NewHostname)

		// Check current hostname
		stdout, _, err := sshPool.Run(ctx, node.Hostname, "hostname")
		if err == nil && stdout == node.NewHostname+"\n" {
			nodeLog.Infow("hostname already set")
			continue
		}

		// Set hostname idempotently
		setCmd := fmt.Sprintf("hostnamectl set-hostname %s", node.NewHostname)
		if _, stderr, err := sshPool.Run(ctx, node.Hostname, setCmd); err != nil {
			return fmt.Errorf("failed to set hostname on %s: %w (stderr: %s)", node.Hostname, err, stderr)
		}

		nodeLog.Infow("hostname set successfully")
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

	for i, script := range scripts {
		if !script.Enabled {
			log.Infow("skipping disabled script", "name", script.Name)
			continue
		}

		scriptLog := log.With("script", script.Name, "index", i)
		scriptLog.Infow("executing script", "source", script.Source)

		// Execute script on all nodes (or only enabled nodes)
		for _, node := range cfg.Nodes {
			if !node.ScriptsEnabled {
				continue
			}

			if err := executeScriptOnNode(ctx, sshPool, node, script); err != nil {
				return fmt.Errorf("failed to execute script %s on %s: %w", script.Name, node.Hostname, err)
			}
		}

		scriptLog.Infow("script executed successfully")
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
		nodeLog.Infow("initiating reboot with 15 second delay")

		// Initiate reboot with 15 second delay and terminate SSH connection cleanly
		rebootCmd := "nohup sh -c 'sleep 15 && reboot' > /dev/null 2>&1 &"
		if _, stderr, err := sshPool.Run(ctx, node.Hostname, rebootCmd); err != nil {
			// Ignore errors as the connection may be terminated
			nodeLog.Infow("reboot initiated (connection may have terminated)", "stderr", stderr)
		} else {
			nodeLog.Infow("reboot scheduled successfully")
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
		nodeLog.Infow("applying labels", "count", len(labels))
		for key, value := range labels {
			// Escape special characters in label values
			escapedValue := strings.ReplaceAll(value, `"`, `\"`)
			labelCmd := fmt.Sprintf(`docker node update --label-add "%s=%s" $(docker node ls --filter "name=%s" -q)`,
				key, escapedValue, node.Hostname)

			if _, stderr, err := sshPool.Run(ctx, primaryMaster, labelCmd); err != nil {
				nodeLog.Warnw("failed to apply label", "key", key, "value", value, "error", err, "stderr", stderr)
			} else {
				nodeLog.Debugw("label applied", "key", key, "value", value)
			}
		}

		nodeLog.Infow("labels applied successfully", "total", len(labels))
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
		nodeLog.Infow("removing public key from node")

		// Remove the public key from authorized_keys
		removeCmd := fmt.Sprintf(
			"sed -i '\\|%s|d' ~/.ssh/authorized_keys 2>/dev/null || true",
			strings.TrimSpace(keyPair.PublicKey),
		)

		if _, stderr, err := sshPool.Run(ctx, node.Hostname, removeCmd); err != nil {
			nodeLog.Warnw("failed to remove public key", "error", err, "stderr", stderr)
		} else {
			nodeLog.Infow("public key removed successfully")
		}
	}

	return nil
}
