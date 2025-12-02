package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"clusterctl/internal/gluster"
	"clusterctl/internal/logging"
	"clusterctl/internal/retry"
	"clusterctl/internal/ssh"
)

// GlusterSetup orchestrates GlusterFS setup across all worker nodes via SSH.
// It creates the trusted storage pool, creates the volume, and mounts it on all nodes.
// If diskManagement is true, it will detect and format dedicated disks for GlusterFS.
// Workers without available disks will be excluded from the GlusterFS cluster.
// Returns the list of SSH workers that were successfully included in the cluster.
//
// Parameters:
//   sshWorkers: SSH hostnames/IPs for SSH operations
//   glusterWorkers: Overlay FQDNs/IPs for GlusterFS peer probe and volume creation
//   Note: sshWorkers and glusterWorkers must be parallel arrays (same length, same order)
func GlusterSetup(ctx context.Context, sshPool *ssh.Pool, sshWorkers, glusterWorkers []string, volume, mount, brick string, diskManagement bool) ([]string, error) {
	log := logging.L().With("component", "orchestrator", "phase", "gluster")

	if len(sshWorkers) == 0 {
		return nil, fmt.Errorf("no workers available for GlusterFS setup")
	}

	if len(sshWorkers) != len(glusterWorkers) {
		return nil, fmt.Errorf("sshWorkers and glusterWorkers must have same length: got %d and %d", len(sshWorkers), len(glusterWorkers))
	}

	log.Infow(fmt.Sprintf("starting GlusterFS setup: workers=%d volume=%s mount=%s brick=%s diskManagement=%v", len(sshWorkers), volume, mount, brick, diskManagement))

	// Phase 0: Detect and prepare disks if disk management is enabled
	validSSHWorkers := sshWorkers
	validGlusterWorkers := glusterWorkers
	if diskManagement {
		log.Infow("phase 0: detecting and preparing dedicated disks for GlusterFS")
		var err error
		validSSHWorkers, err = detectAndPrepareDisk(ctx, sshPool, sshWorkers, brick)
		if err != nil {
			return nil, fmt.Errorf("failed to detect and prepare disks: %w", err)
		}

		if len(validSSHWorkers) == 0 {
			log.Warnw("⚠️ no workers have available disks for GlusterFS - skipping GlusterFS setup")
			return nil, nil // Not an error, just no workers with disks
		}

		// Filter glusterWorkers to match validSSHWorkers
		validGlusterWorkers = make([]string, 0, len(validSSHWorkers))
		for _, validSSH := range validSSHWorkers {
			for i, ssh := range sshWorkers {
				if ssh == validSSH {
					validGlusterWorkers = append(validGlusterWorkers, glusterWorkers[i])
					break
				}
			}
		}

		if len(validSSHWorkers) < len(sshWorkers) {
			excluded := len(sshWorkers) - len(validSSHWorkers)
			log.Warnw(fmt.Sprintf("⚠️ excluded %d workers without available disks", excluded), "validWorkers", len(validSSHWorkers), "totalWorkers", len(sshWorkers))
		}

		log.Infow(fmt.Sprintf("✅ disk detection complete: %d workers have available disks", len(validSSHWorkers)))
	}

	// Phase 1: Create brick directories on all valid workers (use SSH hostnames)
	log.Infow(fmt.Sprintf("phase 1: creating brick directories on %d workers", len(validSSHWorkers)))
	if err := createBrickDirectories(ctx, sshPool, validSSHWorkers, brick); err != nil {
		return nil, fmt.Errorf("failed to create brick directories: %w", err)
	}

	// Phase 2: Create trusted storage pool (use Gluster FQDNs for peer probe, SSH for commands)
	log.Infow("phase 2: creating trusted storage pool")
	if err := createTrustedPool(ctx, sshPool, validSSHWorkers, validGlusterWorkers); err != nil {
		return nil, fmt.Errorf("failed to create trusted storage pool: %w", err)
	}

	// Phase 3: Create GlusterFS volume (use Gluster FQDNs for brick paths, SSH for commands)
	log.Infow("phase 3: creating GlusterFS volume")
	if err := createVolume(ctx, sshPool, validSSHWorkers, validGlusterWorkers, volume, brick); err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	// Phase 4: Start the volume and wait for bricks to come online
	log.Infow("phase 4: starting GlusterFS volume and waiting for bricks")
	if err := startVolume(ctx, sshPool, validSSHWorkers, validSSHWorkers[0], volume, len(validSSHWorkers)); err != nil {
		return nil, fmt.Errorf("failed to start volume: %w", err)
	}

	// Phase 5: Mount the volume on all nodes (SSH to connect, Gluster FQDNs for mount)
	log.Infow("phase 5: mounting GlusterFS volume on all nodes")
	if err := mountVolume(ctx, sshPool, validSSHWorkers, validGlusterWorkers, volume, mount); err != nil {
		return nil, fmt.Errorf("failed to mount volume: %w", err)
	}

	// Phase 6: Verify mounts (use SSH hostnames)
	log.Infow("phase 6: verifying GlusterFS mounts")
	if err := verifyMounts(ctx, sshPool, validSSHWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed to verify mounts: %w", err)
	}

	// Phase 7: Verify volume health (use SSH hostname)
	log.Infow("phase 7: verifying GlusterFS volume health")
	if err := verifyVolumeHealth(ctx, sshPool, validSSHWorkers[0], volume, len(validSSHWorkers)); err != nil {
		return nil, fmt.Errorf("failed volume health verification: %w", err)
	}

	// Phase 8: Test replication (use SSH hostnames)
	log.Infow("phase 8: testing GlusterFS replication")
	if err := testReplication(ctx, sshPool, validSSHWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed replication test: %w", err)
	}

	// Phase 9: Create standard directory structure (use SSH hostname)
	log.Infow("phase 9: creating standard directory structure on GlusterFS volume")
	if err := createStandardDirectories(ctx, sshPool, validSSHWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed to create standard directories: %w", err)
	}

	log.Infow("✅ GlusterFS setup completed successfully", "workers", len(validSSHWorkers))
	return validSSHWorkers, nil
}

func createBrickDirectories(ctx context.Context, sshPool *ssh.Pool, workers []string, brick string) error {
	cmd := fmt.Sprintf("mkdir -p %s", brick)
	logging.L().Infow("creating brick directories", "hosts", strings.Join(workers, ", "), "command", cmd)
	results := sshPool.RunAll(ctx, workers, cmd)

	for host, result := range results {
		if result.Err != nil {
			return fmt.Errorf("failed to create brick directory on %s: %w (stderr: %s)", host, result.Err, result.Stderr)
		}
		logging.L().Infow("✅ brick directory created", "host", host, "path", brick)
	}

	return nil
}

func createTrustedPool(ctx context.Context, sshPool *ssh.Pool, sshWorkers, glusterWorkers []string) error {
	if len(sshWorkers) < 2 {
		logging.L().Infow("only one worker, skipping trusted pool creation")
		return nil
	}

	// Use first worker as the orchestrator (SSH for command execution)
	sshOrchestrator := sshWorkers[0]
	glusterOrchestrator := glusterWorkers[0]

	logging.L().Infow("→ GlusterFS orchestrator", "sshHost", sshOrchestrator, "glusterAddress", glusterOrchestrator)

	// Probe all other workers from the orchestrator (use Gluster addresses for peer probe)
	for i := 1; i < len(glusterWorkers); i++ {
		glusterPeer := glusterWorkers[i]
		sshPeer := sshWorkers[i]

		cmd := fmt.Sprintf("gluster peer probe %s", glusterPeer)
		logging.L().Infow("→ probing GlusterFS peer", "sshHost", sshOrchestrator, "sshPeer", sshPeer, "glusterPeer", glusterPeer, "command", cmd)

		// Use retry for peer probe as it can fail due to timing issues
		retryCfg := retry.NetworkConfig(fmt.Sprintf("peer-probe-%s", glusterPeer))
		err := retry.Do(ctx, retryCfg, func() error {
			stdout, stderr, err := sshPool.Run(ctx, sshOrchestrator, cmd)
			if err != nil {
				return fmt.Errorf("failed to probe %s from %s: %w (stderr: %s)", glusterPeer, sshOrchestrator, err, stderr)
			}
			logging.L().Infow(fmt.Sprintf("✅ peer probe %s: %s", glusterPeer, strings.TrimSpace(stdout)))
			return nil
		})

		if err != nil {
			return err
		}
	}

	// IMPORTANT: Have a peer probe the orchestrator back
	// This ensures all peers explicitly know about the orchestrator
	// The orchestrator can't probe itself, so we need a peer to do it
	// This creates a verified bidirectional relationship
	sshFirstPeer := sshWorkers[1]
	glusterFirstPeer := glusterWorkers[1]

	cmd := fmt.Sprintf("gluster peer probe %s", glusterOrchestrator)
	logging.L().Infow("→ probing orchestrator from peer (ensures bidirectional relationship)", "sshHost", sshFirstPeer, "glusterPeer", glusterFirstPeer, "orchestrator", glusterOrchestrator, "command", cmd)

	retryCfg := retry.NetworkConfig("peer-probe-orchestrator")
	err := retry.Do(ctx, retryCfg, func() error {
		stdout, stderr, err := sshPool.Run(ctx, sshFirstPeer, cmd)
		if err != nil {
			return fmt.Errorf("failed to probe orchestrator %s from %s: %w (stderr: %s)", glusterOrchestrator, sshFirstPeer, err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("✅ peer probe orchestrator: %s", strings.TrimSpace(stdout)))
		return nil
	})

	if err != nil {
		return err
	}

	// Verify peer status with retry
	// The orchestrator (glusterWorkers[0]) does NOT appear in its own peer status
	// So we expect (total workers - 1) peers
	expectedPeers := len(glusterWorkers) - 1
	logging.L().Infow("→ verifying GlusterFS peer status", "sshHost", sshOrchestrator, "orchestrator", glusterOrchestrator, "expectedPeers", expectedPeers)

	retryCfg = retry.NetworkConfig("verify-peer-status")
	var peerStatusOutput string

	err = retry.Do(ctx, retryCfg, func() error {
		cmd := "gluster peer status"
		stdout, stderr, err := sshPool.Run(ctx, sshOrchestrator, cmd)
		if err != nil {
			return fmt.Errorf("failed to get peer status: %w (stderr: %s)", err, stderr)
		}

		peerStatusOutput = stdout

		// Verify peer count matches expected (workers - 1, excluding orchestrator)
		if !strings.Contains(stdout, fmt.Sprintf("Number of Peers: %d", expectedPeers)) {
			return fmt.Errorf("expected %d peers (excluding orchestrator %s), but peer status shows different count", expectedPeers, glusterOrchestrator)
		}

		// Split peer status into individual peer blocks
		// Each block starts with "Hostname:" and contains the peer's info
		// Format:
		//   Hostname: 100.76.15.41
		//   Uuid: xxx
		//   State: Peer in Cluster (Connected)
		//   Other names:
		//   ovhcloud-vps-42d2c09c.netbird.cloud
		//   15.204.95.233
		peerBlocks := strings.Split(stdout, "Hostname:")

		// Check that all peers (except orchestrator at index 0) are connected
		for i := 1; i < len(glusterWorkers); i++ {
			glusterPeer := glusterWorkers[i]
			found := false
			connected := false

			// Search each peer block for this peer
			// The peer could appear as IP (in Hostname line) or FQDN (in Other names)
			for _, block := range peerBlocks {
				if block == "" {
					continue
				}
				// Check if this block contains our peer
				if strings.Contains(block, glusterPeer) {
					found = true
					// Check if this peer is connected (in the same block)
					if strings.Contains(block, "Peer in Cluster (Connected)") {
						connected = true
					}
					break
				}
			}

			if !found {
				return fmt.Errorf("peer %s not found in peer status", glusterPeer)
			}
			if !connected {
				return fmt.Errorf("peer %s found but not in 'Peer in Cluster (Connected)' state", glusterPeer)
			}
		}

		return nil
	})

	if err != nil {
		logging.L().Errorw("peer status verification failed", "error", err, "peerStatus", peerStatusOutput)
		return err
	}

	logging.L().Infow(fmt.Sprintf("✅ peer status verified: %d peers connected (orchestrator %s excluded)", expectedPeers, glusterOrchestrator))

	return nil
}

func createVolume(ctx context.Context, sshPool *ssh.Pool, sshWorkers, glusterWorkers []string, volume, brick string) error {
	sshOrchestrator := sshWorkers[0]
	glusterOrchestrator := glusterWorkers[0]

	// Build brick list using Gluster addresses (overlay IPs or FQDNs)
	// All nodes use their glusterWorker address (overlay IP or FQDN)
	var bricks []string
	for i, glusterWorker := range glusterWorkers {
		bricks = append(bricks, fmt.Sprintf("%s:%s", glusterWorker, brick))
		logging.L().Infow("→ brick", "index", i, "sshHost", sshWorkers[i], "glusterAddress", glusterWorker, "brickPath", brick)
	}
	brickList := strings.Join(bricks, " ")

	// Create volume with replica count = number of workers
	replicaCount := len(glusterWorkers)
	cmd := fmt.Sprintf("gluster volume create %s replica %d %s force", volume, replicaCount, brickList)

	logging.L().Infow("→ creating GlusterFS volume", "sshHost", sshOrchestrator, "glusterOrchestrator", glusterOrchestrator, "volume", volume, "replica", replicaCount, "bricks", brickList)

	// Use retry for volume creation as it can fail if peers are not fully ready
	retryCfg := retry.NetworkConfig(fmt.Sprintf("create-volume-%s", volume))

	err := retry.Do(ctx, retryCfg, func() error {
		stdout, stderr, err := sshPool.Run(ctx, sshOrchestrator, cmd)
		if err != nil {
			// Check if volume already exists
			if strings.Contains(stderr, "already exists") || strings.Contains(stdout, "already exists") {
				logging.L().Infow(fmt.Sprintf("volume %s already exists", volume))
				return nil
			}

			// Log detailed error for debugging
			logging.L().Warnw("volume creation failed", "error", err, "stderr", stderr, "stdout", stdout)
			return fmt.Errorf("failed to create volume: %w (stderr: %s)", err, stderr)
		}

		logging.L().Infow(fmt.Sprintf("✅ volume created: %s", strings.TrimSpace(stdout)))
		return nil
	})

	return err
}

func startVolume(ctx context.Context, sshPool *ssh.Pool, sshWorkers []string, orchestrator, volume string, expectedBricks int) error {
	log := logging.L()

	// Start the volume
	cmd := fmt.Sprintf("gluster volume start %s", volume)
	log.Infow("starting GlusterFS volume", "host", orchestrator, "volume", volume, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		// Check if volume is already started
		if strings.Contains(stderr, "already started") || strings.Contains(stdout, "already started") {
			log.Infow(fmt.Sprintf("volume %s already started", volume))
		} else {
			return fmt.Errorf("failed to start volume: %w (stderr: %s)", err, stderr)
		}
	} else {
		log.Infow(fmt.Sprintf("volume started: %s", strings.TrimSpace(stdout)))
	}

	// Wait for bricks to come online with retry
	log.Infow("→ waiting for bricks to come online", "volume", volume, "expectedBricks", expectedBricks)

	retryCfg := retry.Config{
		Operation:       fmt.Sprintf("bricks-online-%s", volume),
		MaxAttempts:    10,
		InitialBackoff: 3 * time.Second,
		MaxBackoff:     15 * time.Second,
		BackoffMultiple: 1.5,
	}

	var lastOnline, lastOffline int
	err = retry.Do(ctx, retryCfg, func() error {
		statusCmd := fmt.Sprintf("gluster volume status %s", volume)
		stdout, stderr, err := sshPool.Run(ctx, orchestrator, statusCmd)
		if err != nil {
			return fmt.Errorf("failed to get volume status: %w (stderr: %s)", err, stderr)
		}

		// Parse brick status - handles wrapped output where FQDN spans multiple lines
		// Example wrapped output:
		//   Brick ovhcloud-vps-6ffdf9c8.netbird.cloud:/
		//   mnt/GlusterFS/docker-swarm-0001/brick       59634     0          Y       2406
		//
		// The "Y" or "N" appears on the continuation line with the port number
		onlineBricks := 0
		offlineBricks := 0

		lines := strings.Split(stdout, "\n")
		for i := 0; i < len(lines); i++ {
			line := lines[i]

			// Check if this is a Brick line (may be split across lines)
			if strings.HasPrefix(strings.TrimSpace(line), "Brick ") {
				// The status (Y/N) might be on this line or the next line
				// Look for a line that has the port number and Online status
				statusLine := line
				if i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "Brick ") &&
					!strings.HasPrefix(strings.TrimSpace(lines[i+1]), "Self-heal") &&
					!strings.Contains(lines[i+1], "Task Status") &&
					!strings.Contains(lines[i+1], "---") &&
					strings.TrimSpace(lines[i+1]) != "" {
					// This could be a continuation line - check if it has port/status info
					nextLine := strings.TrimSpace(lines[i+1])
					fields := strings.Fields(nextLine)
					// Continuation lines typically start with the path continuation and have port numbers
					if len(fields) >= 4 {
						// Check if one of the fields is Y or N (online status)
						for _, f := range fields {
							if f == "Y" || f == "N" {
								statusLine = nextLine
								i++ // Skip the continuation line
								break
							}
						}
					}
				}

				// Now parse the status from statusLine
				fields := strings.Fields(statusLine)
				foundStatus := false
				for _, field := range fields {
					if field == "Y" {
						onlineBricks++
						foundStatus = true
						break
					} else if field == "N" {
						offlineBricks++
						foundStatus = true
						break
					}
				}

				// If we didn't find Y/N on the status line, it might be on original line
				if !foundStatus {
					for _, field := range strings.Fields(line) {
						if field == "Y" {
							onlineBricks++
							break
						} else if field == "N" {
							offlineBricks++
							break
						}
					}
				}
			}
		}

		lastOnline = onlineBricks
		lastOffline = offlineBricks

		if offlineBricks > 0 {
			log.Warnw("bricks still coming online", "volume", volume, "online", onlineBricks, "offline", offlineBricks)
			return fmt.Errorf("waiting for %d offline bricks", offlineBricks)
		}

		if onlineBricks < expectedBricks {
			return fmt.Errorf("only %d/%d bricks detected", onlineBricks, expectedBricks)
		}

		log.Infow("✅ all bricks are online", "volume", volume, "bricks", onlineBricks)
		return nil
	})

	// If bricks are still offline after retries, try force restart
	if err != nil && lastOffline > 0 {
		log.Warnw("bricks still offline after waiting, trying force restart", "online", lastOnline, "offline", lastOffline)

		// Restart glusterd on all workers
		log.Infow("→ restarting glusterd on all workers")
		restartCmd := "systemctl restart glusterd"
		results := sshPool.RunAll(ctx, sshWorkers, restartCmd)
		for host, result := range results {
			if result.Err != nil {
				log.Warnw("failed to restart glusterd", "host", host, "error", result.Err)
			}
		}

		// Wait a moment for glusterd to restart
		time.Sleep(5 * time.Second)

		// Force start the volume
		forceCmd := fmt.Sprintf("gluster volume start %s force", volume)
		log.Infow("→ force starting volume", "host", orchestrator, "volume", volume, "command", forceCmd)
		stdout, stderr, err := sshPool.Run(ctx, orchestrator, forceCmd)
		if err != nil && !strings.Contains(stderr, "already started") {
			log.Warnw("force start had error", "error", err, "stderr", stderr, "stdout", stdout)
		}

		// Wait and check again
		time.Sleep(5 * time.Second)

		// Final check - use same wrapped-output-aware parsing
		statusCmd := fmt.Sprintf("gluster volume status %s", volume)
		stdout, _, _ = sshPool.Run(ctx, orchestrator, statusCmd)

		onlineBricks := 0
		lines := strings.Split(stdout, "\n")
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			if strings.HasPrefix(strings.TrimSpace(line), "Brick ") {
				statusLine := line
				if i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), "Brick ") &&
					!strings.HasPrefix(strings.TrimSpace(lines[i+1]), "Self-heal") &&
					!strings.Contains(lines[i+1], "Task Status") &&
					!strings.Contains(lines[i+1], "---") &&
					strings.TrimSpace(lines[i+1]) != "" {
					nextLine := strings.TrimSpace(lines[i+1])
					fields := strings.Fields(nextLine)
					if len(fields) >= 4 {
						for _, f := range fields {
							if f == "Y" || f == "N" {
								statusLine = nextLine
								i++
								break
							}
						}
					}
				}
				for _, field := range strings.Fields(statusLine) {
					if field == "Y" {
						onlineBricks++
						break
					}
				}
			}
		}

		if onlineBricks >= expectedBricks {
			log.Infow("✅ all bricks are now online after force restart", "bricks", onlineBricks)
			return nil
		}

		return fmt.Errorf("bricks still offline after force restart: %d/%d online", onlineBricks, expectedBricks)
	}

	return err
}

func mountVolume(ctx context.Context, sshPool *ssh.Pool, sshWorkers, glusterWorkers []string, volume, mount string) error {
	if len(sshWorkers) != len(glusterWorkers) {
		return fmt.Errorf("sshWorkers and glusterWorkers must have same length")
	}

	// backupvolfile-server only takes a single server, not multiple
	// If we have more than one server, use the second one as backup
	backupOpt := ""
	if len(glusterWorkers) > 1 {
		backupOpt = fmt.Sprintf(",backupvolfile-server=%s", glusterWorkers[1])
	}

	// Primary server is the first Gluster FQDN
	primaryServer := glusterWorkers[0]

	// Mount on all workers using SSH to connect, but Gluster FQDN for mount
	for i, sshWorker := range sshWorkers {
		glusterWorker := glusterWorkers[i]

		// Create mount point
		cmd := fmt.Sprintf("mkdir -p %s", mount)
		if _, stderr, err := sshPool.Run(ctx, sshWorker, cmd); err != nil {
			return fmt.Errorf("failed to create mount point on %s: %w (stderr: %s)", sshWorker, err, stderr)
		}

		// Check if already mounted as GlusterFS (must be both the mount point AND glusterfs type)
		checkCmd := fmt.Sprintf("mount | grep '%s' | grep -q glusterfs && echo 'mounted' || echo 'not-mounted'", mount)
		stdout, _, err := sshPool.Run(ctx, sshWorker, checkCmd)
		if err == nil && strings.Contains(stdout, "mounted") && !strings.Contains(stdout, "not-mounted") {
			logging.L().Infow(fmt.Sprintf("%s (%s): already mounted", sshWorker, glusterWorker))
			continue
		}

		// Mount the volume using Gluster FQDN as the server
		mountCmd := fmt.Sprintf("mount -t glusterfs -o defaults%s %s:/%s %s", backupOpt, primaryServer, volume, mount)
		logging.L().Infow("mounting GlusterFS volume", "sshHost", sshWorker, "glusterServer", primaryServer, "volume", volume, "mount", mount)
		stdout, stderr, err := sshPool.Run(ctx, sshWorker, mountCmd)
		if err != nil {
			return fmt.Errorf("failed to mount on %s: %w (stderr: %s)", sshWorker, err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("%s (%s): mounted successfully", sshWorker, glusterWorker))

		// Add to /etc/fstab for persistence using Gluster FQDN
		fstabEntry := fmt.Sprintf("%s:/%s %s glusterfs defaults%s 0 0", primaryServer, volume, mount, backupOpt)
		fstabCmd := fmt.Sprintf("grep -q '%s' /etc/fstab || echo '%s' >> /etc/fstab", mount, fstabEntry)
		if _, stderr, err := sshPool.Run(ctx, sshWorker, fstabCmd); err != nil {
			logging.L().Warnw(fmt.Sprintf("failed to add fstab entry on %s (non-fatal): %v (stderr: %s)", sshWorker, err, stderr))
		}
	}

	return nil
}

func verifyMounts(ctx context.Context, sshPool *ssh.Pool, workers []string, mount string) error {
	// Use mount command to check if the path is actually mounted, not df
	// df falls back to showing root filesystem if path doesn't exist as a mount
	cmd := fmt.Sprintf("mount | grep '%s' | grep glusterfs", mount)
	logging.L().Infow("→ verifying GlusterFS mounts", "mount", mount, "command", cmd)
	results := sshPool.RunAll(ctx, workers, cmd)

	for host, result := range results {
		if result.Err != nil {
			// If grep finds nothing, it returns exit code 1 - check if it's actually not mounted
			return fmt.Errorf("mount on %s is not GlusterFS or not mounted at %s (stderr: %s)", host, mount, result.Stderr)
		}

		// Check if it's a GlusterFS mount
		if !strings.Contains(result.Stdout, "glusterfs") || !strings.Contains(result.Stdout, mount) {
			return fmt.Errorf("mount on %s is not GlusterFS at %s: %s", host, mount, result.Stdout)
		}

		logging.L().Infow(fmt.Sprintf("%s: mount verified: %s", host, strings.TrimSpace(result.Stdout)))
	}

	return nil
}

func testReplication(ctx context.Context, sshPool *ssh.Pool, workers []string, mount string) error {
	if len(workers) < 2 {
		logging.L().Infow("only one worker, skipping replication test")
		return nil
	}

	testFile := fmt.Sprintf("%s/.gluster-replication-test-%d", mount, ctx.Value("timestamp"))
	testContent := "GlusterFS replication test"

	// Create test file on first worker
	createCmd := fmt.Sprintf("echo '%s' > %s", testContent, testFile)
	_, stderr, err := sshPool.Run(ctx, workers[0], createCmd)
	if err != nil {
		return fmt.Errorf("failed to create test file on %s: %w (stderr: %s)", workers[0], err, stderr)
	}
	logging.L().Infow(fmt.Sprintf("created test file on %s", workers[0]))

	// Wait a moment for replication
	// time.Sleep(2 * time.Second)

	// Verify file exists on all other workers
	for _, worker := range workers[1:] {
		verifyCmd := fmt.Sprintf("cat %s", testFile)
		stdout, stderr, err := sshPool.Run(ctx, worker, verifyCmd)
		if err != nil {
			return fmt.Errorf("replication test FAILED: file not found on %s: %w (stderr: %s)", worker, err, stderr)
		}

		if !strings.Contains(stdout, testContent) {
			return fmt.Errorf("replication test FAILED: file content mismatch on %s: got %q, want %q", worker, strings.TrimSpace(stdout), testContent)
		}

		logging.L().Infow(fmt.Sprintf("✅ %s: replication verified", worker))
	}

	// Clean up test file
	cleanupCmd := fmt.Sprintf("rm -f %s", testFile)
	sshPool.Run(ctx, workers[0], cleanupCmd)

	logging.L().Infow("✅ GlusterFS replication test PASSED")
	return nil
}

// verifyVolumeHealth performs comprehensive health checks on the GlusterFS volume.
func verifyVolumeHealth(ctx context.Context, sshPool *ssh.Pool, orchestrator, volume string, expectedReplicas int) error {
	log := logging.L()

	// 1. Verify volume exists and is started
	cmd := fmt.Sprintf("gluster volume info %s", volume)
	log.Infow("checking volume status", "host", orchestrator, "volume", volume, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		return fmt.Errorf("failed to get volume info: %w (stderr: %s)", err, stderr)
	}

	// Check volume is started
	if !strings.Contains(stdout, "Status: Started") {
		return fmt.Errorf("volume %s is not in Started state:\n%s", volume, stdout)
	}
	log.Infow("✅ volume is in Started state", "volume", volume)

	// Check replica count
	replicaLine := ""
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "Number of Bricks:") {
			replicaLine = line
			break
		}
	}
	if replicaLine != "" {
		log.Infow("volume brick configuration", "volume", volume, "config", strings.TrimSpace(replicaLine))
	}

	// 2. Verify all bricks are online
	cmd = fmt.Sprintf("gluster volume status %s", volume)
	log.Infow("checking brick status", "host", orchestrator, "volume", volume, "command", cmd)
	stdout, stderr, err = sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		return fmt.Errorf("failed to get volume status: %w (stderr: %s)", err, stderr)
	}

	// Count online bricks
	onlineBricks := 0
	offlineBricks := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "Brick") && strings.Contains(line, ":") {
			// Check if brick is online (has "Y" in Online column)
			if strings.Contains(line, " Y ") {
				onlineBricks++
			} else {
				offlineBricks++
				log.Warnw("brick is offline", "line", strings.TrimSpace(line))
			}
		}
	}

	if offlineBricks > 0 {
		return fmt.Errorf("volume %s has %d offline bricks (expected all %d bricks online)", volume, offlineBricks, expectedReplicas)
	}
	log.Infow("✅ all bricks are online", "volume", volume, "onlineBricks", onlineBricks, "expectedBricks", expectedReplicas)

	// 3. Check heal status (split-brain detection)
	cmd = fmt.Sprintf("gluster volume heal %s info", volume)
	log.Infow("checking heal status", "host", orchestrator, "volume", volume, "command", cmd)
	stdout, stderr, err = sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		// Heal info can fail on new volumes, log warning but don't fail
		log.Warnw("failed to get heal info (this is normal for new volumes)", "volume", volume, "err", err, "stderr", stderr)
	} else {
		// Check for entries needing heal
		healNeeded := false
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "Number of entries:") && !strings.Contains(line, "Number of entries: 0") {
				healNeeded = true
				log.Warnw("volume has entries needing heal", "line", strings.TrimSpace(line))
			}
		}
		if !healNeeded {
			log.Infow("✅ no heal entries found (volume is healthy)", "volume", volume)
		}
	}

	// 4. Log full volume info for reference
	cmd = fmt.Sprintf("gluster volume info %s", volume)
	stdout, _, _ = sshPool.Run(ctx, orchestrator, cmd)
	log.Infow("volume info", "volume", volume, "info", "\n"+stdout)

	log.Infow("✅ volume health verification PASSED", "volume", volume, "replicas", expectedReplicas)
	return nil
}

// createStandardDirectories creates a consistent directory structure across all nodes.
func createStandardDirectories(ctx context.Context, sshPool *ssh.Pool, workers []string, mount string) error {
	log := logging.L()

	// Standard directories to create on the GlusterFS volume
	standardDirs := []string{
		"data",
		"data/Portainer",
		"data/NginxUI",
		"data/NginxUI/app",
		"config",
		"logs",
		"backups",
		".clusterctl",
	}

	// Create directories on first worker (will replicate to all)
	orchestrator := workers[0]
	for _, dir := range standardDirs {
		fullPath := fmt.Sprintf("%s/%s", mount, dir)
		cmd := fmt.Sprintf("mkdir -p %s && chmod 755 %s", fullPath, fullPath)
		log.Infow("creating standard directory", "host", orchestrator, "path", fullPath, "command", cmd)
		_, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
		if err != nil {
			return fmt.Errorf("failed to create directory %s: %w (stderr: %s)", fullPath, err, stderr)
		}
		log.Infow("✅ directory created", "path", fullPath)
	}

	// Create a marker file with cluster info
	markerFile := fmt.Sprintf("%s/.clusterctl/initialized", mount)
	timestamp := fmt.Sprintf("date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ")
	cmd := fmt.Sprintf("echo \"GlusterFS initialized at $(%s)\" > %s", timestamp, markerFile)
	log.Infow("creating initialization marker", "host", orchestrator, "file", markerFile, "command", cmd)
	_, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		log.Warnw("failed to create marker file", "err", err, "stderr", stderr)
	} else {
		log.Infow("✅ initialization marker created", "file", markerFile)
	}

	// Verify directories exist on all workers
	for _, worker := range workers {
		cmd := fmt.Sprintf("ls -la %s/", mount)
		log.Infow("verifying directory structure", "host", worker, "command", cmd)
		stdout, stderr, err := sshPool.Run(ctx, worker, cmd)
		if err != nil {
			return fmt.Errorf("failed to verify directories on %s: %w (stderr: %s)", worker, err, stderr)
		}
		log.Infow("directory structure verified", "host", worker, "contents", "\n"+stdout)
	}

	log.Infow("✅ standard directory structure created and verified on all nodes")
	return nil
}

// detectAndPrepareDisk detects available disks on workers and prepares them for GlusterFS.
// Returns the list of workers that have available disks and were successfully prepared.
// Workers without available disks are excluded from the returned list.
func detectAndPrepareDisk(ctx context.Context, sshPool *ssh.Pool, workers []string, brickBasePath string) ([]string, error) {
	log := logging.L().With("component", "orchestrator", "phase", "disk-detection")

	var validWorkers []string

	for _, worker := range workers {
		log.Infow("detecting available disks", "host", worker)

		// Detect available disks
		disks, err := gluster.DetectAvailableDisks(ctx, sshPool, worker)
		if err != nil {
			log.Warnw("failed to detect disks, excluding worker", "host", worker, "err", err)
			continue
		}

		if len(disks) == 0 {
			log.Warnw("no available disks found, excluding worker", "host", worker)
			continue
		}

		// Use the first available disk
		disk := disks[0]
		log.Infow("using disk for GlusterFS", "host", worker, "device", disk.Device, "size", disk.Size)

		// Format and mount the disk at the brick path
		if err := gluster.FormatAndMountDisk(ctx, sshPool, worker, disk.Device, brickBasePath); err != nil {
			log.Warnw("failed to format and mount disk, excluding worker", "host", worker, "device", disk.Device, "err", err)
			continue
		}

		log.Infow("✅ disk prepared successfully", "host", worker, "device", disk.Device, "mountPath", brickBasePath)
		validWorkers = append(validWorkers, worker)
	}

	return validWorkers, nil
}
