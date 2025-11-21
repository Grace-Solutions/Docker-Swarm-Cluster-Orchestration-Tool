package gluster

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"clusterctl/internal/deps"
	"clusterctl/internal/logging"
)

// Global retry configuration for GlusterFS operations.
const (
	glusterMaxRetries     = 10
	glusterInitialBackoff = 2 * time.Second
	glusterMaxBackoff     = 30 * time.Second
)

// retryWithBackoff executes a function with exponential backoff retry logic.
// It's used for GlusterFS operations that may need time to converge.
func retryWithBackoff(ctx context.Context, operation string, fn func() error) error {
	backoff := glusterInitialBackoff

	for attempt := 1; attempt <= glusterMaxRetries; attempt++ {
		err := fn()
		if err == nil {
			if attempt > 1 {
				logging.L().Infow(fmt.Sprintf("gluster operation succeeded: operation=%s attempt=%d", operation, attempt))
			}
			return nil
		}

		if attempt < glusterMaxRetries {
			logging.L().Infow(fmt.Sprintf("gluster operation failed, retrying: operation=%s attempt=%d/%d backoff=%v err=%v",
				operation, attempt, glusterMaxRetries, backoff, err))

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}

			// Exponential backoff with cap.
			backoff *= 2
			if backoff > glusterMaxBackoff {
				backoff = glusterMaxBackoff
			}
			continue
		}

		return fmt.Errorf("gluster: %s failed after %d attempts: %w", operation, attempt, err)
	}

	return fmt.Errorf("gluster: %s failed: max retries exceeded", operation)
}

// Ensure converges the local GlusterFS state for this node based on the
// controller's instructions. It is designed to be idempotent: repeated calls
// with the same parameters should converge cleanly.
func Ensure(ctx context.Context, volume, mountPoint, brickPath string) error {
	if volume == "" && mountPoint == "" && brickPath == "" {
		// Gluster not requested for this node.
		return nil
	}

	// Only install Gluster when we actually need to manage a volume or mount.
	// Brick preparation alone only touches the local filesystem.
	if volume != "" || mountPoint != "" {
		if err := deps.EnsureGluster(ctx); err != nil {
			return err
		}
	}

	if brickPath != "" {
		if err := ensureBrick(brickPath); err != nil {
			return err
		}
	}

	if volume != "" {
		if err := ensureVolume(ctx, volume, brickPath); err != nil {
			return err
		}
	}

	if mountPoint != "" && volume != "" {
		if err := ensureMount(ctx, volume, mountPoint); err != nil {
			return err
		}
	}

	logStatus(ctx, volume, mountPoint)
	return nil
}

// Teardown attempts to unmount the GlusterFS mount on this node and remove
// the fstab entry. It does not destroy the volume itself; that is a
// cluster-level operation.
func Teardown(ctx context.Context, mountPoint string) error {
	if mountPoint == "" {
		return nil
	}

	// Remove from fstab first.
	if err := RemoveFromFstab(mountPoint); err != nil {
		logging.L().Warnw(fmt.Sprintf("failed to remove fstab entry for %s: %v", mountPoint, err))
		// Non-fatal; continue with unmount.
	}

	if !isMounted(mountPoint) {
		logging.L().Infow(fmt.Sprintf("gluster mount %s not mounted; skipping unmount", mountPoint))
		return nil
	}

	cmd := exec.CommandContext(ctx, "umount", mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: umount failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow(fmt.Sprintf("gluster unmounted: %s", mountPoint))
	return nil
}

func ensureBrick(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	logging.L().Infow("gluster brick ensured", "path", path)
	return nil
}

func ensureVolume(ctx context.Context, name, brickPath string) error {
	if name == "" {
		return nil
	}

	// If the volume already exists, we do nothing.
	cmd := exec.CommandContext(ctx, "gluster", "volume", "info", name)
	if err := cmd.Run(); err == nil {
		return nil
	}

	if brickPath == "" {
		return fmt.Errorf("gluster: brick path required to create volume %q", name)
	}

	create := exec.CommandContext(ctx, "gluster", "volume", "create", name, brickPath, "force")
	out, err := create.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: volume create failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	start := exec.CommandContext(ctx, "gluster", "volume", "start", name)
	out, err = start.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: volume start failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("gluster volume ensured", "name", name, "brick", brickPath)
	return nil
}

func ensureMount(ctx context.Context, volume, mountPoint string) error {
	return ensureMountFrom(ctx, "localhost", volume, mountPoint)
}

func ensureMountFrom(ctx context.Context, hostname, volume, mountPoint string) error {
	log := logging.L()

	if isMounted(mountPoint) {
		log.Infow(fmt.Sprintf("gluster already mounted: mount=%s", mountPoint))
		// Verify mount is actually working by checking if we can stat it.
		if info, err := os.Stat(mountPoint); err == nil && info.IsDir() {
			log.Infow(fmt.Sprintf("gluster mount verified accessible: mount=%s", mountPoint))
		} else {
			log.Warnw(fmt.Sprintf("gluster mount point exists but not accessible: mount=%s err=%v", mountPoint, err))
		}
		return nil
	}

	log.Infow(fmt.Sprintf("gluster mount not detected, creating mount point: mount=%s", mountPoint))
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Errorf("failed to create mount point %s: %w", mountPoint, err)
	}

	source := fmt.Sprintf("%s:%s", hostname, volume)
	log.Infow(fmt.Sprintf("gluster mounting: source=%s mount=%s", source, mountPoint))

	// Use retry logic for mounting as it may fail if the volume is still initializing.
	err := retryWithBackoff(ctx, fmt.Sprintf("mount %s", source), func() error {
		if isMounted(mountPoint) {
			return nil
		}

		cmd := exec.CommandContext(ctx, "mount", "-t", "glusterfs", source, mountPoint)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Warnw(fmt.Sprintf("gluster mount attempt failed: source=%s mount=%s output=%s", source, mountPoint, strings.TrimSpace(string(out))))
			return fmt.Errorf("mount failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
		log.Infow(fmt.Sprintf("gluster mount command succeeded: source=%s mount=%s", source, mountPoint))
		return nil
	})

	if err != nil {
		return fmt.Errorf("gluster: %w", err)
	}

	// Verify the mount is actually working.
	if !isMounted(mountPoint) {
		return fmt.Errorf("gluster: mount command succeeded but mount point %s is not showing as mounted", mountPoint)
	}

	log.Infow(fmt.Sprintf("gluster mount ensured and verified: source=%s mount=%s", source, mountPoint))
	return nil
}

func logStatus(ctx context.Context, volume, mountPoint string) {
	if volume == "" {
		return
	}

	cmd := exec.CommandContext(ctx, "gluster", "volume", "info", volume)
	out, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		logging.L().Infow(fmt.Sprintf("gluster volume info failed for %s: %v (output: %s)", volume, err, truncate(trimmed, 400)))
	} else {
		logging.L().Infow(fmt.Sprintf("gluster volume info for %s: %s", volume, truncate(trimmed, 400)))
	}

	if mountPoint == "" {
		return
	}

	log := logging.L()
	mounted := isMounted(mountPoint)
	if mounted {
		log.Infow(fmt.Sprintf("gluster mount status: MOUNTED at %s", mountPoint))

		// Show what's in the mount.
		if entries, err := os.ReadDir(mountPoint); err == nil {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if len(names) > 0 {
				log.Infow(fmt.Sprintf("gluster mount contents: %v", names))
			} else {
				log.Infow(fmt.Sprintf("gluster mount is empty (this is normal for new volumes)"))
			}
		} else {
			log.Warnw(fmt.Sprintf("gluster mount exists but cannot read contents: %v", err))
		}
	} else {
		log.Warnw(fmt.Sprintf("gluster mount status: NOT MOUNTED at %s", mountPoint))
	}
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func isMounted(mountPoint string) bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[1] == mountPoint {
			return true
		}
	}
	return false
}

// PeerProbe adds a peer to the GlusterFS trusted storage pool.
// It is idempotent: if the peer is already probed, the command succeeds.
// It retries with exponential backoff if the peer's glusterd daemon is not yet ready.
func PeerProbe(ctx context.Context, hostname string) error {
	maxRetries := 5
	backoff := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		cmd := exec.CommandContext(ctx, "gluster", "peer", "probe", hostname)
		out, err := cmd.CombinedOutput()
		outStr := strings.TrimSpace(string(out))

		if err == nil || strings.Contains(outStr, "success") || strings.Contains(outStr, "already in peer list") {
			logging.L().Infow(fmt.Sprintf("gluster peer probe succeeded: hostname=%s attempt=%d", hostname, attempt))
			return nil
		}

		// Check if it's a transient error (daemon not ready yet).
		if strings.Contains(outStr, "Transport endpoint is not connected") ||
		   strings.Contains(outStr, "Connection refused") ||
		   strings.Contains(outStr, "Probe returned with") {
			if attempt < maxRetries {
				logging.L().Infow(fmt.Sprintf("gluster peer probe failed (daemon not ready), retrying: hostname=%s attempt=%d/%d backoff=%v",
					hostname, attempt, maxRetries, backoff))

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}

				// Exponential backoff: 2s, 4s, 8s, 16s
				backoff *= 2
				continue
			}
		}

		// Non-retryable error or max retries exceeded.
		return fmt.Errorf("gluster: peer probe failed for %s after %d attempts: %w (output: %s)", hostname, attempt, err, outStr)
	}

	return fmt.Errorf("gluster: peer probe failed for %s: max retries exceeded", hostname)
}

// WaitForPeersInCluster waits for all workers to be ready in the GlusterFS cluster.
// This includes checking that:
// 1. Localhost (self) is Connected via `gluster pool list`
// 2. All other peers (excluding self) are in "Peer in Cluster" state via `gluster peer status`
// expectedPeers should include ALL workers (including self).
func WaitForPeersInCluster(ctx context.Context, expectedPeers []string, selfHostname string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 2 * time.Second

	// Count how many peers we expect to see (excluding self).
	expectedPeerCount := 0
	for _, peer := range expectedPeers {
		if peer != selfHostname && peer != "localhost" {
			expectedPeerCount++
		}
	}

	logging.L().Infow(fmt.Sprintf("waiting for cluster to be ready: total_workers=%d other_peers=%d self=%s",
		len(expectedPeers), expectedPeerCount, selfHostname))

	for {
		allReady := true

		// First, check that localhost (self) is connected via `gluster pool list`.
		cmd := exec.CommandContext(ctx, "gluster", "pool", "list")
		out, err := cmd.CombinedOutput()
		if err != nil {
			logging.L().Warnw(fmt.Sprintf("gluster pool list check failed, retrying: %v", err))
			allReady = false
		} else {
			outStr := string(out)
			localhostConnected := false

			// Look for "localhost" with "Connected" state.
			lines := strings.Split(outStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "localhost") && strings.Contains(line, "Connected") {
					localhostConnected = true
					break
				}
			}

			if !localhostConnected {
				logging.L().Infow("gluster localhost not yet connected in pool")
				allReady = false
			}
		}

		// Second, check that all other peers are in "Peer in Cluster" state via `gluster peer status`.
		if allReady {
			cmd = exec.CommandContext(ctx, "gluster", "peer", "status")
			out, err = cmd.CombinedOutput()
			if err != nil {
				logging.L().Warnw(fmt.Sprintf("gluster peer status check failed, retrying: %v", err))
				allReady = false
			} else {
				outStr := string(out)
				peersChecked := 0

				for _, peer := range expectedPeers {
					// Skip checking self - we validated it via pool list above.
					if peer == selfHostname || peer == "localhost" {
						continue
					}

					peersChecked++

					// Look for the peer in the output and check its state.
					// Format: "Hostname: <hostname>\nUuid: ...\nState: Peer in Cluster (Connected)"
					if !strings.Contains(outStr, peer) {
						logging.L().Infow(fmt.Sprintf("gluster peer not yet in status output: hostname=%s (checked %d/%d)", peer, peersChecked, expectedPeerCount))
						allReady = false
						break
					}

					// Find the state line for this peer.
					lines := strings.Split(outStr, "\n")
					foundPeer := false
					for i, line := range lines {
						if strings.Contains(line, "Hostname:") && strings.Contains(line, peer) {
							foundPeer = true
							// Look for the State line (should be within next few lines).
							for j := i + 1; j < len(lines) && j < i+5; j++ {
								if strings.Contains(lines[j], "State:") {
									if !strings.Contains(lines[j], "Peer in Cluster") {
										logging.L().Infow(fmt.Sprintf("gluster peer not yet in cluster state: hostname=%s state=%s", peer, strings.TrimSpace(lines[j])))
										allReady = false
									}
									break
								}
							}
							break
						}
					}

					if !foundPeer {
						logging.L().Infow(fmt.Sprintf("gluster peer not found in status: hostname=%s", peer))
						allReady = false
						break
					}
				}

				if allReady && peersChecked == expectedPeerCount {
					logging.L().Infow(fmt.Sprintf("all gluster workers are ready in cluster: total=%d (localhost + %d peers)",
						len(expectedPeers), peersChecked))
					return nil
				}
			}
		}

		// Check timeout.
		if time.Now().After(deadline) {
			return fmt.Errorf("gluster: timeout waiting for peers to join cluster after %v", timeout)
		}

		// Wait before next check.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(checkInterval):
		}
	}
}

// CreateReplicaVolume creates a replicated GlusterFS volume across multiple bricks.
// brickPaths should be in the format "hostname:/path/to/brick".
// It is idempotent: if the volume already exists, it returns nil.
func CreateReplicaVolume(ctx context.Context, name string, brickPaths []string) error {
	if name == "" || len(brickPaths) == 0 {
		return fmt.Errorf("gluster: volume name and brick paths are required")
	}

	// Check if volume already exists.
	cmd := exec.CommandContext(ctx, "gluster", "volume", "info", name)
	if err := cmd.Run(); err == nil {
		logging.L().Infow("gluster volume already exists", "name", name)
		return nil
	}

	// Create replica volume.
	replicaCount := fmt.Sprintf("%d", len(brickPaths))
	args := []string{"volume", "create", name, "replica", replicaCount}
	args = append(args, brickPaths...)
	args = append(args, "force")

	create := exec.CommandContext(ctx, "gluster", args...)
	out, err := create.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: volume create failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// Start the volume.
	start := exec.CommandContext(ctx, "gluster", "volume", "start", name)
	out, err = start.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: volume start failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("gluster replica volume created and started", "name", name, "replica", replicaCount, "bricks", len(brickPaths))
	return nil
}

// WaitForVolumeReady polls until the volume is started or the timeout expires.
func WaitForVolumeReady(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	checkInterval := 2 * time.Second

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("gluster: volume %s did not become ready within %v", name, timeout)
		}

		cmd := exec.CommandContext(ctx, "gluster", "volume", "info", name)
		out, err := cmd.CombinedOutput()
		if err == nil {
			outStr := strings.TrimSpace(string(out))
			if strings.Contains(outStr, "Status: Started") {
				logging.L().Infow(fmt.Sprintf("gluster volume is ready: name=%s", name))
				return nil
			}
			logging.L().Infow(fmt.Sprintf("gluster volume not yet started: name=%s", name))
		} else {
			logging.L().Infow(fmt.Sprintf("gluster volume info check failed: name=%s err=%v", name, err))
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(checkInterval):
		}
	}
}

// AddToFstab idempotently adds a GlusterFS mount entry to /etc/fstab.
func AddToFstab(volume, mountPoint string) error {
	const fstabPath = "/etc/fstab"

	// Read existing fstab.
	data, err := os.ReadFile(fstabPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("gluster: failed to read %s: %w", fstabPath, err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Check if entry already exists.
	source := fmt.Sprintf("localhost:%s", volume)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == source && fields[1] == mountPoint {
			logging.L().Infow("gluster fstab entry already exists", "volume", volume, "mount", mountPoint)
			return nil
		}
	}

	// Append new entry.
	entry := fmt.Sprintf("%s %s glusterfs defaults,_netdev 0 0\n", source, mountPoint)
	f, err := os.OpenFile(fstabPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("gluster: failed to open %s for append: %w", fstabPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("gluster: failed to write to %s: %w", fstabPath, err)
	}

	logging.L().Infow("gluster fstab entry added", "volume", volume, "mount", mountPoint)
	return nil
}

// RemoveFromFstab idempotently removes a GlusterFS mount entry from /etc/fstab.
func RemoveFromFstab(mountPoint string) error {
	const fstabPath = "/etc/fstab"

	// Read existing fstab.
	data, err := os.ReadFile(fstabPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No fstab, nothing to remove.
		}
		return fmt.Errorf("gluster: failed to read %s: %w", fstabPath, err)
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Filter out lines matching the mount point.
	var newLines []string
	removed := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			newLines = append(newLines, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[1] == mountPoint {
			// Skip this line (remove it).
			removed = true
			continue
		}
		newLines = append(newLines, line)
	}

	if !removed {
		logging.L().Infow(fmt.Sprintf("gluster fstab entry not found for mount %s; nothing to remove", mountPoint))
		return nil
	}

	// Write back the filtered content.
	newContent := strings.Join(newLines, "\n")
	if err := os.WriteFile(fstabPath, []byte(newContent), 0o644); err != nil {
		return fmt.Errorf("gluster: failed to write %s: %w", fstabPath, err)
	}

	logging.L().Infow(fmt.Sprintf("gluster fstab entry removed for mount %s", mountPoint))
	return nil
}

// PrintClusterStatus logs comprehensive GlusterFS cluster status information.
func PrintClusterStatus(ctx context.Context, volume, mountPoint string) {
	logging.L().Infow("========== GlusterFS Cluster Status ==========")

	// Peer status.
	cmd := exec.CommandContext(ctx, "gluster", "peer", "status")
	out, err := cmd.CombinedOutput()
	if err != nil {
		logging.L().Warnw(fmt.Sprintf("gluster peer status failed: %v", err))
	} else {
		outStr := strings.TrimSpace(string(out))
		lines := strings.Split(outStr, "\n")
		peerCount := 0
		for _, line := range lines {
			if strings.Contains(line, "Number of Peers:") {
				logging.L().Infow(fmt.Sprintf("gluster cluster: %s", line))
			} else if strings.Contains(line, "Hostname:") || strings.Contains(line, "State:") || strings.Contains(line, "Uuid:") {
				logging.L().Infow(fmt.Sprintf("  %s", strings.TrimSpace(line)))
				if strings.Contains(line, "Hostname:") {
					peerCount++
				}
			}
		}
		if peerCount == 0 {
			logging.L().Infow("gluster cluster: no peers (single-node or self only)")
		}
	}

	// Volume info.
	if volume != "" {
		cmd = exec.CommandContext(ctx, "gluster", "volume", "info", volume)
		out, err = cmd.CombinedOutput()
		if err != nil {
			logging.L().Warnw(fmt.Sprintf("gluster volume info failed: %v", err))
		} else {
			outStr := strings.TrimSpace(string(out))
			lines := strings.Split(outStr, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					logging.L().Infow(fmt.Sprintf("  %s", trimmed))
				}
			}
		}

		// Volume status.
		cmd = exec.CommandContext(ctx, "gluster", "volume", "status", volume)
		out, err = cmd.CombinedOutput()
		if err != nil {
			logging.L().Warnw(fmt.Sprintf("gluster volume status failed: %v", err))
		} else {
			outStr := strings.TrimSpace(string(out))
			lines := strings.Split(outStr, "\n")
			logging.L().Infow(fmt.Sprintf("gluster volume status for %s:", volume))
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					logging.L().Infow(fmt.Sprintf("  %s", trimmed))
				}
			}
		}
	}

	// Mount status.
	if mountPoint != "" {
		mounted := isMounted(mountPoint)
		logging.L().Infow(fmt.Sprintf("gluster mount status: path=%s mounted=%t", mountPoint, mounted))

		// Show mount details from /proc/mounts.
		f, err := os.Open("/proc/mounts")
		if err == nil {
			defer f.Close()
			s := bufio.NewScanner(f)
			for s.Scan() {
				fields := strings.Fields(s.Text())
				if len(fields) >= 4 && fields[1] == mountPoint {
					logging.L().Infow(fmt.Sprintf("  mount: source=%s type=%s options=%s", fields[0], fields[2], fields[3]))
				}
			}
		}
	}

	logging.L().Infow("========== End GlusterFS Cluster Status ==========")
}

// Orchestrate performs the full multi-node GlusterFS setup as the orchestrator worker.
// It peers all workers, creates the replica volume, waits for readiness, mounts locally, and adds to fstab.
// workerHostnames should include ALL GlusterFS-enabled workers (including this orchestrator).
// selfIdentity is this orchestrator's identity (hostname or IP) as it appears in workerHostnames.
func Orchestrate(ctx context.Context, volume, brickPath, mountPoint string, workerHostnames []string, selfIdentity string) error {
	logging.L().Infow(fmt.Sprintf("gluster orchestration starting: volume=%s workers=%d self=%s", volume, len(workerHostnames), selfIdentity))

	if err := deps.EnsureGluster(ctx); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to install gluster: %w", err)
	}

	// Ensure local brick directory.
	if err := ensureBrick(brickPath); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to ensure brick: %w", err)
	}

	// Peer probe all other workers (skip self).
	for _, wh := range workerHostnames {
		if wh == selfIdentity || wh == "localhost" {
			continue
		}
		if err := PeerProbe(ctx, wh); err != nil {
			return fmt.Errorf("gluster: orchestrator failed to peer probe %s: %w", wh, err)
		}
	}

	// Wait for all peers to be in "Peer in Cluster" state before creating volume.
	// This is necessary because peer probe can return success before the peer is fully joined.
	if err := WaitForPeersInCluster(ctx, workerHostnames, selfIdentity, 60*time.Second); err != nil {
		return fmt.Errorf("gluster: orchestrator failed waiting for peers: %w", err)
	}

	// Build brick paths for volume creation.
	var brickPaths []string
	for _, wh := range workerHostnames {
		brickPaths = append(brickPaths, fmt.Sprintf("%s:%s", wh, brickPath))
	}

	// Create replica volume.
	if err := CreateReplicaVolume(ctx, volume, brickPaths); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to create volume: %w", err)
	}

	// Wait for volume to be ready.
	if err := WaitForVolumeReady(ctx, volume, 60*time.Second); err != nil {
		return fmt.Errorf("gluster: orchestrator volume not ready: %w", err)
	}

	// Mount locally.
	if err := ensureMount(ctx, volume, mountPoint); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to mount: %w", err)
	}

	// Add to fstab.
	if err := AddToFstab(volume, mountPoint); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to add fstab entry: %w", err)
	}

	logging.L().Infow("gluster orchestration completed successfully", "volume", volume, "mount", mountPoint)

	// Print comprehensive cluster status.
	PrintClusterStatus(ctx, volume, mountPoint)

	return nil
}

