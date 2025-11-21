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

// Teardown attempts to unmount the GlusterFS mount on this node. It does not
// destroy the volume itself; that is a cluster-level operation.
func Teardown(ctx context.Context, mountPoint string) error {
	if mountPoint == "" {
		return nil
	}
	if !isMounted(mountPoint) {
		return nil
	}

	cmd := exec.CommandContext(ctx, "umount", mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: umount failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("gluster unmounted", "mount", mountPoint)
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
	if isMounted(mountPoint) {
		return nil
	}

	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return err
	}

	source := fmt.Sprintf("%s:%s", hostname, volume)
	cmd := exec.CommandContext(ctx, "mount", "-t", "glusterfs", source, mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: mount failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("gluster mount ensured", "source", source, "mount", mountPoint)
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

	mounted := isMounted(mountPoint)
	logging.L().Infow(fmt.Sprintf("gluster mount status: mount=%s mounted=%t", mountPoint, mounted))
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
func PeerProbe(ctx context.Context, hostname string) error {
	cmd := exec.CommandContext(ctx, "gluster", "peer", "probe", hostname)
	out, err := cmd.CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		// "peer probe: success" or "already in peer list" are both OK.
		if strings.Contains(outStr, "success") || strings.Contains(outStr, "already in peer list") {
			logging.L().Infow("gluster peer probe succeeded", "hostname", hostname)
			return nil
		}
		return fmt.Errorf("gluster: peer probe failed for %s: %w (output: %s)", hostname, err, outStr)
	}
	logging.L().Infow("gluster peer probe succeeded", "hostname", hostname)
	return nil
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
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("gluster: volume %s did not become ready within %v", name, timeout)
		}

		cmd := exec.CommandContext(ctx, "gluster", "volume", "info", name)
		out, err := cmd.CombinedOutput()
		if err == nil {
			outStr := strings.TrimSpace(string(out))
			if strings.Contains(outStr, "Status: Started") {
				logging.L().Infow("gluster volume is ready", "name", name)
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
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

// Orchestrate performs the full multi-node GlusterFS setup as the orchestrator worker.
// It peers all workers, creates the replica volume, waits for readiness, mounts locally, and adds to fstab.
// workerHostnames should include ALL GlusterFS-enabled workers (including this orchestrator).
func Orchestrate(ctx context.Context, volume, brickPath, mountPoint string, workerHostnames []string) error {
	logging.L().Infow("gluster orchestration starting", "volume", volume, "workers", len(workerHostnames))

	if err := deps.EnsureGluster(ctx); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to install gluster: %w", err)
	}

	// Ensure local brick directory.
	if err := ensureBrick(brickPath); err != nil {
		return fmt.Errorf("gluster: orchestrator failed to ensure brick: %w", err)
	}

	// Peer probe all other workers (skip self).
	selfHostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("gluster: orchestrator failed to get hostname: %w", err)
	}

	for _, wh := range workerHostnames {
		if wh == selfHostname || wh == "localhost" {
			continue
		}
		if err := PeerProbe(ctx, wh); err != nil {
			return fmt.Errorf("gluster: orchestrator failed to peer probe %s: %w", wh, err)
		}
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
	return nil
}

