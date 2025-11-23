package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// GlusterSetup orchestrates GlusterFS setup across all worker nodes via SSH.
// It creates the trusted storage pool, creates the volume, and mounts it on all nodes.
func GlusterSetup(ctx context.Context, sshPool *ssh.Pool, workers []string, volume, mount, brick string) error {
	log := logging.L().With("component", "orchestrator", "phase", "gluster")

	if len(workers) == 0 {
		return fmt.Errorf("no workers available for GlusterFS setup")
	}

	log.Infow(fmt.Sprintf("starting GlusterFS setup: workers=%d volume=%s mount=%s brick=%s", len(workers), volume, mount, brick))

	// Phase 1: Create brick directories on all workers
	log.Infow("phase 1: creating brick directories on all workers")
	if err := createBrickDirectories(ctx, sshPool, workers, brick); err != nil {
		return fmt.Errorf("failed to create brick directories: %w", err)
	}

	// Phase 2: Create trusted storage pool
	log.Infow("phase 2: creating trusted storage pool")
	if err := createTrustedPool(ctx, sshPool, workers); err != nil {
		return fmt.Errorf("failed to create trusted storage pool: %w", err)
	}

	// Phase 3: Create GlusterFS volume
	log.Infow("phase 3: creating GlusterFS volume")
	if err := createVolume(ctx, sshPool, workers, volume, brick); err != nil {
		return fmt.Errorf("failed to create volume: %w", err)
	}

	// Phase 4: Start the volume
	log.Infow("phase 4: starting GlusterFS volume")
	if err := startVolume(ctx, sshPool, workers[0], volume); err != nil {
		return fmt.Errorf("failed to start volume: %w", err)
	}

	// Phase 5: Mount the volume on all nodes
	log.Infow("phase 5: mounting GlusterFS volume on all nodes")
	if err := mountVolume(ctx, sshPool, workers, volume, mount); err != nil {
		return fmt.Errorf("failed to mount volume: %w", err)
	}

	// Phase 6: Verify mounts
	log.Infow("phase 6: verifying GlusterFS mounts")
	if err := verifyMounts(ctx, sshPool, workers, mount); err != nil {
		return fmt.Errorf("failed to verify mounts: %w", err)
	}

	// Phase 7: Test replication
	log.Infow("phase 7: testing GlusterFS replication")
	if err := testReplication(ctx, sshPool, workers, mount); err != nil {
		return fmt.Errorf("failed replication test: %w", err)
	}

	log.Infow("GlusterFS setup completed successfully")
	return nil
}

func createBrickDirectories(ctx context.Context, sshPool *ssh.Pool, workers []string, brick string) error {
	cmd := fmt.Sprintf("mkdir -p %s", brick)
	results := sshPool.RunAll(ctx, workers, cmd)

	for host, result := range results {
		if result.Err != nil {
			return fmt.Errorf("failed to create brick directory on %s: %w (stderr: %s)", host, result.Err, result.Stderr)
		}
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
		stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
		if err != nil {
			return fmt.Errorf("failed to probe %s from %s: %w (stderr: %s)", worker, orchestrator, err, stderr)
		}
		logging.L().Infow(fmt.Sprintf("peer probe %s: %s", worker, strings.TrimSpace(stdout)))
	}

	// Verify peer status
	cmd := "gluster peer status"
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

	stdout, stderr, err := sshPool.Run(ctx, orchestrator, cmd)
	if err != nil {
		// Check if volume already exists
		if strings.Contains(stderr, "already exists") || strings.Contains(stdout, "already exists") {
			logging.L().Infow(fmt.Sprintf("volume %s already exists", volume))
			return nil
		}
		return fmt.Errorf("failed to create volume: %w (stderr: %s)", err, stderr)
	}

	logging.L().Infow(fmt.Sprintf("volume created: %s", strings.TrimSpace(stdout)))
	return nil
}

func startVolume(ctx context.Context, sshPool *ssh.Pool, orchestrator, volume string) error {
	cmd := fmt.Sprintf("gluster volume start %s", volume)
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

