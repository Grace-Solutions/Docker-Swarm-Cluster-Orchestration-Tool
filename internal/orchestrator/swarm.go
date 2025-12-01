package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/logging"
	"clusterctl/internal/retry"
	"clusterctl/internal/ssh"
)

// SwarmSetup orchestrates Docker Swarm setup across all nodes via SSH.
// It initializes the swarm on the primary manager and joins all other nodes.
func SwarmSetup(ctx context.Context, sshPool *ssh.Pool, primaryManager string, managers, workers []string, advertiseAddr string) error {
	log := logging.L().With("component", "orchestrator", "phase", "swarm")

	log.Infow(fmt.Sprintf("starting Docker Swarm setup: primaryManager=%s managers=%d workers=%d advertiseAddr=%s",
		primaryManager, len(managers), len(workers), advertiseAddr))

	// Phase 1: Initialize swarm on primary manager
	log.Infow("phase 1: initializing Docker Swarm on primary manager")
	if err := initSwarm(ctx, sshPool, primaryManager, advertiseAddr); err != nil {
		return fmt.Errorf("failed to initialize swarm: %w", err)
	}

	// Phase 2: Get join tokens
	log.Infow("phase 2: retrieving join tokens")
	managerToken, workerToken, err := getJoinTokens(ctx, sshPool, primaryManager)
	if err != nil {
		return fmt.Errorf("failed to get join tokens: %w", err)
	}

	log.Infow(fmt.Sprintf("manager join token: %s", managerToken))
	log.Infow(fmt.Sprintf("worker join token: %s", workerToken))

	// Phase 3: Join managers
	if len(managers) > 0 {
		log.Infow(fmt.Sprintf("phase 3: joining %d manager nodes", len(managers)))
		if err := joinNodes(ctx, sshPool, managers, managerToken, advertiseAddr); err != nil {
			return fmt.Errorf("failed to join managers: %w", err)
		}
	}

	// Phase 4: Join workers
	if len(workers) > 0 {
		log.Infow(fmt.Sprintf("phase 4: joining %d worker nodes", len(workers)))
		if err := joinNodes(ctx, sshPool, workers, workerToken, advertiseAddr); err != nil {
			return fmt.Errorf("failed to join workers: %w", err)
		}
	}

	// Phase 5: Verify swarm status
	log.Infow("phase 5: verifying Docker Swarm status")
	if err := verifySwarm(ctx, sshPool, primaryManager, len(managers)+1, len(workers)); err != nil {
		return fmt.Errorf("failed to verify swarm: %w", err)
	}

	log.Infow("Docker Swarm setup completed successfully")
	return nil
}

func initSwarm(ctx context.Context, sshPool *ssh.Pool, primaryManager, advertiseAddr string) error {
	// Check if swarm is already initialized AND this node is a manager
	checkCmd := "docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'"
	logging.L().Infow("checking swarm status", "host", primaryManager, "command", checkCmd)
	stdout, _, err := sshPool.Run(ctx, primaryManager, checkCmd)
	if err == nil && strings.Contains(stdout, "active") && strings.Contains(stdout, "true") {
		logging.L().Infow("swarm already initialized on primary manager (node is active manager)")
		return nil
	}

	// If node is active but not a manager, it needs to leave first
	if err == nil && strings.Contains(stdout, "active") && !strings.Contains(stdout, "true") {
		logging.L().Warnw("node is active in swarm but not a manager, leaving swarm first", "host", primaryManager)
		leaveCmd := "docker swarm leave --force"
		_, stderr, leaveErr := sshPool.Run(ctx, primaryManager, leaveCmd)
		if leaveErr != nil {
			logging.L().Warnw("failed to leave swarm", "host", primaryManager, "error", leaveErr, "stderr", stderr)
		} else {
			logging.L().Infow("left swarm successfully", "host", primaryManager)
		}
	}

	// Initialize swarm with retry logic
	retryCfg := retry.DefaultConfig(fmt.Sprintf("swarm-init-%s", primaryManager))
	err = retry.Do(ctx, retryCfg, func() error {
		cmd := fmt.Sprintf("docker swarm init --advertise-addr %s", advertiseAddr)
		logging.L().Infow("initializing Docker Swarm", "host", primaryManager, "command", cmd)
		stdout, stderr, err := sshPool.Run(ctx, primaryManager, cmd)
		if err != nil {
			// Check if it's already initialized (race condition)
			if strings.Contains(stderr, "already part of a swarm") {
				logging.L().Infow("swarm already initialized (detected during init)")
				return nil
			}
			return fmt.Errorf("failed to init swarm: %w (stderr: %s)", err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("✅ swarm initialized: %s", strings.TrimSpace(stdout)))
		return nil
	})

	return err
}

func getJoinTokens(ctx context.Context, sshPool *ssh.Pool, primaryManager string) (managerToken, workerToken string, err error) {
	// Get manager token with retry
	retryCfg := retry.DefaultConfig("get-manager-token")
	err = retry.Do(ctx, retryCfg, func() error {
		cmd := "docker swarm join-token manager -q"
		logging.L().Infow("retrieving manager join token", "host", primaryManager, "command", cmd)
		stdout, stderr, err := sshPool.Run(ctx, primaryManager, cmd)
		if err != nil {
			return fmt.Errorf("failed to get manager token: %w (stderr: %s)", err, stderr)
		}
		managerToken = strings.TrimSpace(stdout)
		return nil
	})
	if err != nil {
		return "", "", err
	}

	// Get worker token with retry
	retryCfg = retry.DefaultConfig("get-worker-token")
	err = retry.Do(ctx, retryCfg, func() error {
		cmd := "docker swarm join-token worker -q"
		logging.L().Infow("retrieving worker join token", "host", primaryManager, "command", cmd)
		stdout, stderr, err := sshPool.Run(ctx, primaryManager, cmd)
		if err != nil {
			return fmt.Errorf("failed to get worker token: %w (stderr: %s)", err, stderr)
		}
		workerToken = strings.TrimSpace(stdout)
		return nil
	})
	if err != nil {
		return "", "", err
	}

	return managerToken, workerToken, nil
}

func joinNodes(ctx context.Context, sshPool *ssh.Pool, nodes []string, token, managerAddr string) error {
	// Ensure manager address includes port
	if !strings.Contains(managerAddr, ":") {
		managerAddr = managerAddr + ":2377"
	}

	for _, node := range nodes {
		// Check if already joined
		checkCmd := "docker info --format '{{.Swarm.LocalNodeState}}'"
		logging.L().Infow("checking swarm status", "host", node, "command", checkCmd)
		stdout, _, err := sshPool.Run(ctx, node, checkCmd)
		if err == nil && strings.Contains(stdout, "active") {
			logging.L().Infow(fmt.Sprintf("%s: already joined swarm", node))
			continue
		}

		// Join swarm with retry logic
		retryCfg := retry.DefaultConfig(fmt.Sprintf("swarm-join-%s", node))
		err = retry.Do(ctx, retryCfg, func() error {
			cmd := fmt.Sprintf("docker swarm join --token %s %s", token, managerAddr)
			logging.L().Infow("joining node to swarm", "host", node, "command", cmd)
			stdout, stderr, err := sshPool.Run(ctx, node, cmd)
			if err != nil {
				// Check if already joined (race condition)
				if strings.Contains(stderr, "already part of a swarm") {
					logging.L().Infow(fmt.Sprintf("%s: already joined swarm (detected during join)", node))
					return nil
				}
				// Retry on network/connection errors
				if strings.Contains(stderr, "Timeout") ||
				   strings.Contains(stderr, "connection refused") ||
				   strings.Contains(stderr, "no route to host") {
					return fmt.Errorf("failed to join %s: %w (stderr: %s)", node, err, stderr)
				}
				// Non-retryable error
				return fmt.Errorf("failed to join %s (non-retryable): %w (stderr: %s)", node, err, stderr)
			}
			logging.L().Infow(fmt.Sprintf("✅ %s joined swarm: %s", node, strings.TrimSpace(stdout)))
			return nil
		})
		if err != nil {
			return err
		}

		logging.L().Infow(fmt.Sprintf("✅ %s: joined swarm: %s", node, strings.TrimSpace(stdout)))
	}

	return nil
}

func verifySwarm(ctx context.Context, sshPool *ssh.Pool, primaryManager string, expectedManagers, expectedWorkers int) error {
	cmd := "docker node ls --format '{{.Hostname}} {{.Status}} {{.ManagerStatus}} {{.Availability}}'"
	logging.L().Infow("verifying swarm status", "host", primaryManager, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, primaryManager, cmd)
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w (stderr: %s)", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	managerCount := 0
	workerCount := 0

	for _, line := range lines {
		if strings.Contains(line, "Leader") || strings.Contains(line, "Reachable") {
			managerCount++
		} else {
			workerCount++
		}
	}

	logging.L().Infow(fmt.Sprintf("swarm status: %d managers, %d workers", managerCount, workerCount))
	logging.L().Infow(fmt.Sprintf("node list:\n%s", stdout))

	if managerCount != expectedManagers {
		return fmt.Errorf("manager count mismatch: got %d, expected %d", managerCount, expectedManagers)
	}

	if workerCount != expectedWorkers {
		return fmt.Errorf("worker count mismatch: got %d, expected %d", workerCount, expectedWorkers)
	}

	logging.L().Infow("✅ Docker Swarm verification PASSED")
	return nil
}

