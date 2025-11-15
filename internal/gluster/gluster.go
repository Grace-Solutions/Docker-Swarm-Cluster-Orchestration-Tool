package gluster

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	if isMounted(mountPoint) {
		return nil
	}

	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return err
	}

	source := fmt.Sprintf("localhost:%s", volume)
	cmd := exec.CommandContext(ctx, "mount", "-t", "glusterfs", source, mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gluster: mount failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("gluster mount ensured", "volume", volume, "mount", mountPoint)
	return nil
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

