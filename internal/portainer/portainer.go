package portainer

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"clusterctl/internal/ipdetect"
	"clusterctl/internal/logging"
)

const (
	portainerAgentImage = "portainer/agent:latest"
	portainerCEImage    = "portainer/portainer-ce:latest"
	portainerDataPath   = "/mnt/GlusterFS/Docker/Swarm/0001/data/Portainer"
)

// DeployPortainer deploys Portainer Agent as a global service and Portainer CE as a replicated service.
// This should only be called on a worker node after the swarm is initialized and the controller
// has assigned this worker to deploy Portainer.
// It uses the existing Docker Swarm overlay networks (DOCKER-SWARM-INTERNAL and DOCKER-SWARM-EXTERNAL).
// If glusterEnabled is true, it will wait for the GlusterFS mount to be ready before deploying.
func DeployPortainer(ctx context.Context, glusterEnabled bool, glusterMount string) error {
	log := logging.L()
	log.Infow("deploying Portainer and Portainer Agent to Docker Swarm")

	// Check if we're in a swarm.
	if err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.Swarm.LocalNodeState}}").Run(); err != nil {
		return fmt.Errorf("portainer: not in a swarm or docker not available: %w", err)
	}

	// If GlusterFS is enabled, wait for the mount to be ready before deploying.
	if glusterEnabled && glusterMount != "" {
		if err := waitForGlusterMount(ctx, glusterMount); err != nil {
			return fmt.Errorf("portainer: gluster mount not ready: %w", err)
		}
	}

	// Deploy Portainer Agent as a global service.
	if err := deployPortainerAgent(ctx); err != nil {
		return fmt.Errorf("portainer: failed to deploy agent: %w", err)
	}

	// Deploy Portainer CE as a replicated service (replica=1).
	if err := deployPortainerCE(ctx); err != nil {
		return fmt.Errorf("portainer: failed to deploy portainer: %w", err)
	}

	log.Infow("portainer deployment completed successfully")
	return nil
}

// deployPortainerAgent deploys the Portainer Agent as a global service.
func deployPortainerAgent(ctx context.Context) error {
	log := logging.L()
	log.Infow("deploying portainer agent as global service")

	// Create the Portainer Agent service.
	args := []string{
		"service", "create",
		"--name", "portainer_agent",
		"--mode", "global",
		"--constraint", "node.platform.os==linux",
		"--network", "DOCKER-SWARM-INTERNAL",
		"--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock",
		"--mount", "type=bind,src=/var/lib/docker/volumes,dst=/var/lib/docker/volumes",
		portainerAgentImage,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// If the service already exists (e.g., from a previous run), treat as success.
		if strings.Contains(string(output), "already exists") || strings.Contains(err.Error(), "already exists") {
			log.Infow("portainer agent service already exists, skipping creation")
			return nil
		}
		return fmt.Errorf("failed to create portainer agent service: %w, output: %s", err, string(output))
	}

	log.Infow("portainer agent service created successfully")
	return nil
}

// deployPortainerCE deploys Portainer CE as a replicated service with replica count of 1.
// Runs on worker nodes only.
func deployPortainerCE(ctx context.Context) error {
	log := logging.L()
	log.Infow("deploying portainer CE as replicated service (replica=1, workers only)")

	// Ensure the data directory exists.
	mkdirCmd := exec.CommandContext(ctx, "mkdir", "-p", portainerDataPath)
	if err := mkdirCmd.Run(); err != nil {
		log.Warnw(fmt.Sprintf("failed to create portainer data directory (may already exist): %v", err))
	}

	// Detect the primary IP for logging purposes.
	// Priority: overlay (CGNAT) > private (RFC1918) > other non-loopback > loopback.
	primaryIP, err := ipdetect.DetectPrimary()
	primaryIPStr := "<node-ip>"
	if err != nil {
		log.Warnw(fmt.Sprintf("failed to detect primary IP: %v", err))
	} else {
		primaryIPStr = primaryIP.String()
	}

	// Create the Portainer CE service.
	// Use mode=ingress (default) to enable routing mesh - accessible on any node.
	// This provides automatic failover: if Portainer moves to another worker, clients don't need to change IPs.
	args := []string{
		"service", "create",
		"--name", "portainer",
		"--replicas", "1",
		"--constraint", "node.platform.os==linux",
		"--constraint", "node.role==worker",
		"--network", "DOCKER-SWARM-INTERNAL",
		"--network", "DOCKER-SWARM-EXTERNAL",
		"--publish", "published=9443,target=9443,protocol=tcp",
		"--publish", "published=8000,target=8000,protocol=tcp",
		"--mount", fmt.Sprintf("type=bind,src=%s,dst=/data", portainerDataPath),
		portainerCEImage,
		"-H", "tcp://tasks.portainer_agent:9001",
		"--tlsskipverify",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		// If the service already exists (e.g., from a previous run), treat as success.
		if strings.Contains(string(output), "already exists") || strings.Contains(err.Error(), "already exists") {
			log.Infow("portainer service already exists, skipping creation")
			return nil
		}
		return fmt.Errorf("failed to create portainer service: %w, output: %s", err, string(output))
	}

	log.Infow(fmt.Sprintf("portainer service created successfully: accessible at https://<any-node-ip>:9443 (routing mesh enabled), data stored at %s", portainerDataPath))
	log.Infow(fmt.Sprintf("example: https://%s:9443", primaryIPStr))
	return nil
}

// waitForGlusterMount waits for the GlusterFS mount to be ready and accessible.
// It checks that the mount point exists, is a directory, and is writable.
// Retries for up to 60 seconds with exponential backoff.
func waitForGlusterMount(ctx context.Context, mountPath string) error {
	log := logging.L()
	log.Infow("waiting for GlusterFS mount to be ready", "mountPath", mountPath)

	maxWait := 60 * time.Second
	backoff := 2 * time.Second
	deadline := time.Now().Add(maxWait)

	for {
		// Check if we've exceeded the deadline.
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for GlusterFS mount at %s", mountPath)
		}

		// Check if context is cancelled.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Check if mount point exists and is a directory.
		info, err := os.Stat(mountPath)
		if err == nil && info.IsDir() {
			// Try to create a test file to verify write access.
			testFile := mountPath + "/.portainer-mount-test"
			if err := os.WriteFile(testFile, []byte("test"), 0o644); err == nil {
				// Clean up test file.
				os.Remove(testFile)
				log.Infow("GlusterFS mount is ready and writable", "mountPath", mountPath)
				return nil
			} else {
				log.Infow("GlusterFS mount exists but not writable yet, retrying", "mountPath", mountPath, "err", err)
			}
		} else {
			log.Infow("GlusterFS mount not ready yet, retrying", "mountPath", mountPath, "err", err)
		}

		// Wait before retrying.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		// Increase backoff up to 10 seconds.
		if backoff < 10*time.Second {
			backoff += 2 * time.Second
		}
	}
}

