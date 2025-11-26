package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/gluster"
	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// GlusterSetup orchestrates GlusterFS setup across all worker nodes via SSH.
// It creates the trusted storage pool, creates the volume, and mounts it on all nodes.
// If diskManagement is true, it will detect and format dedicated disks for GlusterFS.
// Workers without available disks will be excluded from the GlusterFS cluster.
// Returns the list of workers that were successfully included in the cluster.
func GlusterSetup(ctx context.Context, sshPool *ssh.Pool, workers []string, volume, mount, brick string, diskManagement bool) ([]string, error) {
	log := logging.L().With("component", "orchestrator", "phase", "gluster")

	if len(workers) == 0 {
		return nil, fmt.Errorf("no workers available for GlusterFS setup")
	}

	log.Infow(fmt.Sprintf("starting GlusterFS setup: workers=%d volume=%s mount=%s brick=%s diskManagement=%v", len(workers), volume, mount, brick, diskManagement))

	// Phase 0: Detect and prepare disks if disk management is enabled
	validWorkers := workers
	if diskManagement {
		log.Infow("phase 0: detecting and preparing dedicated disks for GlusterFS")
		var err error
		validWorkers, err = detectAndPrepareDisk(ctx, sshPool, workers, brick)
		if err != nil {
			return nil, fmt.Errorf("failed to detect and prepare disks: %w", err)
		}

		if len(validWorkers) == 0 {
			log.Warnw("⚠️ no workers have available disks for GlusterFS - skipping GlusterFS setup")
			return nil, nil // Not an error, just no workers with disks
		}

		if len(validWorkers) < len(workers) {
			excluded := len(workers) - len(validWorkers)
			log.Warnw(fmt.Sprintf("⚠️ excluded %d workers without available disks", excluded), "validWorkers", len(validWorkers), "totalWorkers", len(workers))
		}

		log.Infow(fmt.Sprintf("✅ disk detection complete: %d workers have available disks", len(validWorkers)))
	}

	// Phase 1: Create brick directories on all valid workers
	log.Infow(fmt.Sprintf("phase 1: creating brick directories on %d workers", len(validWorkers)))
	if err := createBrickDirectories(ctx, sshPool, validWorkers, brick); err != nil {
		return nil, fmt.Errorf("failed to create brick directories: %w", err)
	}

	// Phase 2: Create trusted storage pool
	log.Infow("phase 2: creating trusted storage pool")
	if err := createTrustedPool(ctx, sshPool, validWorkers); err != nil {
		return nil, fmt.Errorf("failed to create trusted storage pool: %w", err)
	}

	// Phase 3: Create GlusterFS volume
	log.Infow("phase 3: creating GlusterFS volume")
	if err := createVolume(ctx, sshPool, validWorkers, volume, brick); err != nil {
		return nil, fmt.Errorf("failed to create volume: %w", err)
	}

	// Phase 4: Start the volume
	log.Infow("phase 4: starting GlusterFS volume")
	if err := startVolume(ctx, sshPool, validWorkers[0], volume); err != nil {
		return nil, fmt.Errorf("failed to start volume: %w", err)
	}

	// Phase 5: Mount the volume on all nodes
	log.Infow("phase 5: mounting GlusterFS volume on all nodes")
	if err := mountVolume(ctx, sshPool, validWorkers, volume, mount); err != nil {
		return nil, fmt.Errorf("failed to mount volume: %w", err)
	}

	// Phase 6: Verify mounts
	log.Infow("phase 6: verifying GlusterFS mounts")
	if err := verifyMounts(ctx, sshPool, validWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed to verify mounts: %w", err)
	}

	// Phase 7: Verify volume health
	log.Infow("phase 7: verifying GlusterFS volume health")
	if err := verifyVolumeHealth(ctx, sshPool, validWorkers[0], volume, len(validWorkers)); err != nil {
		return nil, fmt.Errorf("failed volume health verification: %w", err)
	}

	// Phase 8: Test replication
	log.Infow("phase 8: testing GlusterFS replication")
	if err := testReplication(ctx, sshPool, validWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed replication test: %w", err)
	}

	// Phase 9: Create standard directory structure
	log.Infow("phase 9: creating standard directory structure on GlusterFS volume")
	if err := createStandardDirectories(ctx, sshPool, validWorkers, mount); err != nil {
		return nil, fmt.Errorf("failed to create standard directories: %w", err)
	}

	log.Infow("✅ GlusterFS setup completed successfully", "workers", len(validWorkers))
	return validWorkers, nil
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

func createTrustedPool(ctx context.Context, sshPool *ssh.Pool, workers []string) error {
	if len(workers) < 2 {
		logging.L().Infow("only one worker, skipping trusted pool creation")
		return nil
	}

	// Use first worker as the orchestrator
	orchestrator := workers[0]

	// Probe all other workers from the orchestrator
	for _, worker := range workers[1:] {
		cmd := fmt.Sprintf("gluster peer probe %s", worker)
		logging.L().Infow("probing GlusterFS peer", "host", orchestrator, "peer", worker, "command", cmd)
		stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
		if err != nil {
			return fmt.Errorf("failed to probe %s from %s: %w (stderr: %s)", worker, orchestrator, err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("✅ peer probe %s: %s", worker, strings.TrimSpace(stdout)))
	}

	// Verify peer status
	cmd := "gluster peer status"
	logging.L().Infow("verifying GlusterFS peer status", "host", orchestrator, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		return fmt.Errorf("failed to get peer status: %w (stderr: %s)", err, stderr)
	}
	logging.L().Infow(fmt.Sprintf("peer status:\n%s", stdout))

	return nil
}

func createVolume(ctx context.Context, sshPool *ssh.Pool, workers []string, volume, brick string) error {
	orchestrator := workers[0]

	// Build brick list: worker1:/path worker2:/path ...
	var bricks []string
	for _, worker := range workers {
		bricks = append(bricks, fmt.Sprintf("%s:%s", worker, brick))
	}
	brickList := strings.Join(bricks, " ")

	// Create volume with replica count = number of workers
	replicaCount := len(workers)
	cmd := fmt.Sprintf("gluster volume create %s replica %d %s force", volume, replicaCount, brickList)

	logging.L().Infow("creating GlusterFS volume", "host", orchestrator, "volume", volume, "replica", replicaCount, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		// Check if volume already exists
		if strings.Contains(stderr, "already exists") || strings.Contains(stdout, "already exists") {
			logging.L().Infow(fmt.Sprintf("volume %s already exists", volume))
			return nil
		}
		return fmt.Errorf("failed to create volume: %w (stderr: %s)", err, stderr)
	}

	logging.L().Infow(fmt.Sprintf("✅ volume created: %s", strings.TrimSpace(stdout)))
	return nil
}

func startVolume(ctx context.Context, sshPool *ssh.Pool, orchestrator, volume string) error {
	cmd := fmt.Sprintf("gluster volume start %s", volume)
	logging.L().Infow("starting GlusterFS volume", "host", orchestrator, "volume", volume, "command", cmd)
	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		// Check if volume is already started
		if strings.Contains(stderr, "already started") || strings.Contains(stdout, "already started") {
			logging.L().Infow(fmt.Sprintf("volume %s already started", volume))
			return nil
		}
		return fmt.Errorf("failed to start volume: %w (stderr: %s)", err, stderr)
	}

	logging.L().Infow(fmt.Sprintf("volume started: %s", strings.TrimSpace(stdout)))
	return nil
}

func mountVolume(ctx context.Context, sshPool *ssh.Pool, workers []string, volume, mount string) error {
	// Build backup volfile servers list (all workers except the first one)
	var backupServers []string
	for _, worker := range workers[1:] {
		backupServers = append(backupServers, worker)
	}
	backupOpt := ""
	if len(backupServers) > 0 {
		backupOpt = fmt.Sprintf(",backupvolfile-server=%s", strings.Join(backupServers, ":"))
	}

	// Mount on all workers
	for _, worker := range workers {
		// Create mount point
		cmd := fmt.Sprintf("mkdir -p %s", mount)
		if _, stderr, err := sshPool.Run(ctx, worker, cmd); err != nil {
			return fmt.Errorf("failed to create mount point on %s: %w (stderr: %s)", worker, err, stderr)
		}

		// Check if already mounted
		checkCmd := fmt.Sprintf("mount | grep -q '%s' && echo 'mounted' || echo 'not-mounted'", mount)
		stdout, _, err := sshPool.Run(ctx, worker, checkCmd)
		if err == nil && strings.Contains(stdout, "mounted") {
			logging.L().Infow(fmt.Sprintf("%s: already mounted", worker))
			continue
		}

		// Mount the volume
		mountCmd := fmt.Sprintf("mount -t glusterfs -o defaults%s %s:/%s %s", backupOpt, workers[0], volume, mount)
		stdout, stderr, err := sshPool.Run(ctx, worker, mountCmd)
		if err != nil {
			return fmt.Errorf("failed to mount on %s: %w (stderr: %s)", worker, err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("%s: mounted successfully", worker))

		// Add to /etc/fstab for persistence
		fstabEntry := fmt.Sprintf("%s:/%s %s glusterfs defaults%s 0 0", workers[0], volume, mount, backupOpt)
		fstabCmd := fmt.Sprintf("grep -q '%s' /etc/fstab || echo '%s' >> /etc/fstab", mount, fstabEntry)
		if _, stderr, err := sshPool.Run(ctx, worker, fstabCmd); err != nil {
			logging.L().Warnw(fmt.Sprintf("failed to add fstab entry on %s (non-fatal): %v (stderr: %s)", worker, err, stderr))
		}
	}

	return nil
}

func verifyMounts(ctx context.Context, sshPool *ssh.Pool, workers []string, mount string) error {
	cmd := fmt.Sprintf("df -T %s | tail -n 1", mount)
	results := sshPool.RunAll(ctx, workers, cmd)

	for host, result := range results {
		if result.Err != nil {
			return fmt.Errorf("failed to verify mount on %s: %w (stderr: %s)", host, result.Err, result.Stderr)
		}

		// Check if it's a GlusterFS mount
		if !strings.Contains(result.Stdout, "fuse.glusterfs") {
			return fmt.Errorf("mount on %s is not GlusterFS: %s", host, result.Stdout)
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
