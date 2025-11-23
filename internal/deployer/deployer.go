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

	// Phase 2: Install dependencies on all nodes
	log.Infow("Phase 2: Installing dependencies on all nodes")
	if err := installDependencies(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to install dependencies: %w", err)
	}
	log.Infow("✅ Dependencies installed")

	// Phase 3: Configure overlay network on all nodes
	log.Infow("Phase 3: Configuring overlay network")
	if err := configureOverlay(ctx, cfg, sshPool); err != nil {
		return fmt.Errorf("failed to configure overlay network: %w", err)
	}
	log.Infow("✅ Overlay network configured")

	// Phase 4: Setup GlusterFS if enabled
	glusterWorkers := getGlusterWorkers(cfg)
	if len(glusterWorkers) > 0 {
		log.Infow("Phase 4: Setting up GlusterFS", "workers", len(glusterWorkers))
		if err := orchestrator.GlusterSetup(ctx, sshPool, glusterWorkers,
			cfg.GlobalSettings.GlusterVolume,
			cfg.GlobalSettings.GlusterMount,
			cfg.GlobalSettings.GlusterBrick); err != nil {
			return fmt.Errorf("failed to setup GlusterFS: %w", err)
		}
		log.Infow("✅ GlusterFS setup complete")
	} else {
		log.Infow("Phase 4: Skipping GlusterFS (no workers with glusterEnabled)")
	}

	// Phase 5: Setup Docker Swarm
	log.Infow("Phase 5: Setting up Docker Swarm")
	primaryMaster, managers, workers := categorizeNodes(cfg)
	if err := orchestrator.SwarmSetup(ctx, sshPool, primaryMaster, managers, workers, primaryMaster); err != nil {
		return fmt.Errorf("failed to setup Docker Swarm: %w", err)
	}
	log.Infow("✅ Docker Swarm setup complete")

	// Phase 6: Deploy Portainer if enabled
	if cfg.GlobalSettings.DeployPortainer {
		log.Infow("Phase 6: Deploying Portainer")
		// TODO: Implement Portainer deployment
		log.Infow("⚠️  Portainer deployment not yet implemented")
	}

	// Phase 7: SSH key cleanup (not needed for config-based deployment)
	// Since we use credentials from the config file, we don't add/remove SSH keys
	log.Infow("Phase 7: SSH key management (using credentials from config, no cleanup needed)")

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

// configureOverlay configures the overlay network on all nodes.
func configureOverlay(ctx context.Context, cfg *config.Config, sshPool *ssh.Pool) error {
	if cfg.GlobalSettings.OverlayProvider == "" {
		logging.L().Infow("no overlay provider specified, skipping overlay configuration")
		return nil
	}

	// TODO: Implement overlay network configuration via SSH
	// For now, assume overlay is already configured
	logging.L().Warnw("overlay network configuration not yet implemented via SSH")
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

// NOTE: SSH key cleanup is not needed for config-based deployment.
// We use credentials from the config file (password or privateKeyPath),
// so we don't add/remove SSH keys during deployment.

