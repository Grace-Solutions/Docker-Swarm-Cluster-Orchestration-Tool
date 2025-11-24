package deployer

import (
	"context"
	"fmt"

	"clusterctl/internal/config"
	"clusterctl/internal/logging"
	"clusterctl/internal/orchestrator"
	"clusterctl/internal/ssh"
)

// Deploy orchestrates the complete cluster deployment from the configuration.
func Deploy(ctx context.Context, cfg *config.Config) error {
	log := logging.L().With("component", "deployer")

	log.Infow("🚀 Starting cluster deployment",
		"clusterName", cfg.GlobalSettings.ClusterName,
		"nodes", len(cfg.Nodes),
	)

	// Phase 1: Prepare SSH connection pool
	log.Infow("Phase 1: Preparing SSH connections")
	sshPool, err := createSSHPool(cfg)
	if err != nil {
		return fmt.Errorf("failed to create SSH pool: %w", err)
	}
	log.Infow("✅ SSH connection pool ready")

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
	primaryMaster, managers, workers := categorizeNodes(cfg)
	if err := orchestrator.SwarmSetup(ctx, sshPool, primaryMaster, managers, workers, primaryMaster); err != nil {
		return fmt.Errorf("failed to setup Docker Swarm: %w", err)
	}
	log.Infow("✅ Docker Swarm setup complete")

	// Phase 8: Deploy Portainer if enabled
	if cfg.GlobalSettings.DeployPortainer {
		log.Infow("Phase 8: Deploying Portainer")
		// TODO: Implement Portainer deployment
		log.Infow("⚠️  Portainer deployment not yet implemented")
	}

	// Phase 9: Execute post-deployment scripts
	log.Infow("Phase 9: Executing post-deployment scripts")
	if err := executeScripts(ctx, cfg, sshPool, cfg.GlobalSettings.PostScripts, "post"); err != nil {
		return fmt.Errorf("failed to execute post-deployment scripts: %w", err)
	}
	log.Infow("✅ Post-deployment scripts complete")

	// Phase 10: Reboot nodes if configured
	log.Infow("Phase 10: Rebooting nodes if configured")
	if err := rebootNodes(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to reboot nodes: %w", err)
	}
	log.Infow("✅ Reboot initiated for configured nodes")

	log.Infow("🎉 Cluster deployment complete!")
	return nil
}

// createSSHPool creates an SSH connection pool from the configuration.
func createSSHPool(cfg *config.Config) (*ssh.Pool, error) {
	authConfigs := make(map[string]ssh.AuthConfig)

	for _, node := range cfg.Nodes {
		authConfigs[node.Hostname] = ssh.AuthConfig{
			Username:       node.Username,
			Password:       node.Password,
			PrivateKeyPath: node.PrivateKeyPath,
			Port:           node.SSHPort,
		}
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

// categorizeNodes returns the primary master, managers, and workers.
func categorizeNodes(cfg *config.Config) (primaryMaster string, managers []string, workers []string) {
	for _, node := range cfg.Nodes {
		if node.PrimaryMaster {
			primaryMaster = node.Hostname
		} else if node.Role == "manager" {
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

// NOTE: SSH key cleanup is not needed for config-based deployment.
// We use credentials from the config file (password or privateKeyPath),
// so we don't add/remove SSH keys during deployment.

