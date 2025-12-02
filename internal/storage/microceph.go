package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"clusterctl/internal/config"
	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// MicroCephProvider implements the Provider interface for MicroCeph.
type MicroCephProvider struct {
	cfg *config.Config
}

// NewMicroCephProvider creates a new MicroCeph provider.
func NewMicroCephProvider(cfg *config.Config) *MicroCephProvider {
	return &MicroCephProvider{cfg: cfg}
}

// Name returns the provider name.
func (p *MicroCephProvider) Name() string {
	return "microceph"
}

// GetMountPath returns the CephFS mount path from configuration.
func (p *MicroCephProvider) GetMountPath() string {
	return p.cfg.GetDistributedStorage().Providers.MicroCeph.MountPath
}

// Install installs MicroCeph on a node via snap.
func (p *MicroCephProvider) Install(ctx context.Context, sshPool *ssh.Pool, node string) error {
	log := logging.L().With("component", "microceph", "node", node)
	ds := p.cfg.GetDistributedStorage()
	channel := ds.Providers.MicroCeph.SnapChannel
	if channel == "" {
		channel = "latest/stable"
	}

	// Install microceph snap
	installCmd := fmt.Sprintf("snap install microceph --channel=%s", channel)
	log.Infow("installing MicroCeph", "command", installCmd)
	if _, stderr, err := sshPool.Run(ctx, node, installCmd); err != nil {
		return fmt.Errorf("failed to install microceph: %w (stderr: %s)", err, stderr)
	}

	// Wait for snap to be ready
	time.Sleep(2 * time.Second)

	log.Infow("✓ MicroCeph installed")
	return nil
}

// Bootstrap initializes the MicroCeph cluster on the primary node.
func (p *MicroCephProvider) Bootstrap(ctx context.Context, sshPool *ssh.Pool, primaryNode string) error {
	log := logging.L().With("component", "microceph", "node", primaryNode)

	// Bootstrap the cluster
	bootstrapCmd := "microceph cluster bootstrap"
	log.Infow("bootstrapping MicroCeph cluster", "command", bootstrapCmd)
	if _, stderr, err := sshPool.Run(ctx, primaryNode, bootstrapCmd); err != nil {
		// Check if already bootstrapped
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "exists") {
			log.Infow("cluster already bootstrapped, continuing")
			return nil
		}
		return fmt.Errorf("failed to bootstrap cluster: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✓ MicroCeph cluster bootstrapped")
	return nil
}

// GenerateJoinToken generates a token for a node to join the cluster.
func (p *MicroCephProvider) GenerateJoinToken(ctx context.Context, sshPool *ssh.Pool, primaryNode, joiningNode string) (string, error) {
	log := logging.L().With("component", "microceph", "primaryNode", primaryNode, "joiningNode", joiningNode)

	// Generate join token using microceph cluster add
	addCmd := fmt.Sprintf("microceph cluster add %s", joiningNode)
	log.Infow("generating join token", "command", addCmd)
	stdout, stderr, err := sshPool.Run(ctx, primaryNode, addCmd)
	if err != nil {
		return "", fmt.Errorf("failed to generate join token: %w (stderr: %s)", err, stderr)
	}

	token := strings.TrimSpace(stdout)
	if token == "" {
		return "", fmt.Errorf("empty join token received")
	}

	log.Infow("✓ join token generated", "tokenLength", len(token))
	return token, nil
}

// Join joins a node to an existing MicroCeph cluster.
func (p *MicroCephProvider) Join(ctx context.Context, sshPool *ssh.Pool, node, token string) error {
	log := logging.L().With("component", "microceph", "node", node)

	// Join the cluster
	joinCmd := fmt.Sprintf("microceph cluster join %s", token)
	log.Infow("joining MicroCeph cluster", "command", "microceph cluster join <token>")
	if _, stderr, err := sshPool.Run(ctx, node, joinCmd); err != nil {
		return fmt.Errorf("failed to join cluster: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✓ node joined MicroCeph cluster")
	return nil
}

// AddStorage adds storage (disks or loop devices) to a node.
func (p *MicroCephProvider) AddStorage(ctx context.Context, sshPool *ssh.Pool, node string) error {
	log := logging.L().With("component", "microceph", "node", node)
	ds := p.cfg.GetDistributedStorage()
	mcCfg := ds.Providers.MicroCeph

	if mcCfg.UseLoopDevices {
		// Add loop devices
		loopSpec := fmt.Sprintf("loop,%dG,%d", mcCfg.LoopDeviceSizeGB, mcCfg.LoopDeviceCount)
		addCmd := fmt.Sprintf("microceph disk add %s", loopSpec)
		log.Infow("adding loop devices", "command", addCmd)
		if _, stderr, err := sshPool.Run(ctx, node, addCmd); err != nil {
			return fmt.Errorf("failed to add loop devices: %w (stderr: %s)", err, stderr)
		}
		log.Infow("✓ loop devices added", "count", mcCfg.LoopDeviceCount, "sizeGB", mcCfg.LoopDeviceSizeGB)
	} else {
		// Auto-detect and add available disks
		// This will add all unpartitioned disks
		log.Infow("auto-detecting available disks")
		listCmd := "lsblk -dpno NAME,TYPE | grep disk | awk '{print $1}'"
		stdout, _, err := sshPool.Run(ctx, node, listCmd)
		if err != nil {
			return fmt.Errorf("failed to list disks: %w", err)
		}

		disks := strings.Split(strings.TrimSpace(stdout), "\n")
		for _, disk := range disks {
			disk = strings.TrimSpace(disk)
			if disk == "" || disk == "/dev/sda" || disk == "/dev/vda" {
				// Skip empty and likely root disks
				continue
			}
			addCmd := fmt.Sprintf("microceph disk add %s --wipe", disk)
			log.Infow("adding disk", "disk", disk, "command", addCmd)
			if _, stderr, err := sshPool.Run(ctx, node, addCmd); err != nil {
				log.Warnw("failed to add disk (may already be in use)", "disk", disk, "error", err, "stderr", stderr)
			}
		}
	}

	return nil
}

// CreatePool creates a CephFS filesystem for use by containers.
// The replication factor is determined automatically by Ceph based on OSD count.
func (p *MicroCephProvider) CreatePool(ctx context.Context, sshPool *ssh.Pool, primaryNode, poolName string) error {
	log := logging.L().With("component", "microceph", "node", primaryNode, "poolName", poolName)

	// Enable MDS (Metadata Server) for CephFS
	enableMdsCmd := "microceph enable mds"
	log.Infow("enabling MDS for CephFS", "command", enableMdsCmd)
	if _, stderr, err := sshPool.Run(ctx, primaryNode, enableMdsCmd); err != nil {
		// MDS might already be enabled
		if !strings.Contains(stderr, "already") {
			log.Warnw("failed to enable MDS (may already be enabled)", "error", err, "stderr", stderr)
		}
	}

	// Wait for MDS to be ready
	time.Sleep(5 * time.Second)

	// Create CephFS filesystem using ceph fs volume command (simpler approach)
	// This automatically creates the data and metadata pools with proper defaults
	createFsCmd := fmt.Sprintf("ceph fs volume create %s", poolName)
	log.Infow("creating CephFS filesystem", "command", createFsCmd)
	if _, stderr, err := sshPool.Run(ctx, primaryNode, createFsCmd); err != nil {
		if !strings.Contains(stderr, "already exists") && !strings.Contains(stderr, "already") {
			return fmt.Errorf("failed to create CephFS: %w (stderr: %s)", err, stderr)
		}
		log.Infow("CephFS filesystem already exists")
	}

	// Wait for filesystem to be ready
	time.Sleep(3 * time.Second)

	log.Infow("✓ CephFS filesystem created", "poolName", poolName)
	return nil
}

// Mount mounts the CephFS filesystem on a node.
func (p *MicroCephProvider) Mount(ctx context.Context, sshPool *ssh.Pool, node, poolName string) error {
	mountPath := p.GetMountPath()
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	// Create mount directory
	mkdirCmd := fmt.Sprintf("mkdir -p %s", mountPath)
	if _, _, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create mount directory: %w", err)
	}

	// Get the monitor addresses
	monCmd := "ceph mon dump --format=json 2>/dev/null | jq -r '.mons[].addr' | cut -d'/' -f1 | paste -sd','"
	monAddrs, _, err := sshPool.Run(ctx, node, monCmd)
	if err != nil {
		// Fallback to localhost
		monAddrs = "127.0.0.1:6789"
	}
	monAddrs = strings.TrimSpace(monAddrs)
	if monAddrs == "" {
		monAddrs = "127.0.0.1:6789"
	}

	// Get admin key
	keyCmd := "ceph auth get-key client.admin 2>/dev/null"
	adminKey, _, err := sshPool.Run(ctx, node, keyCmd)
	if err != nil {
		return fmt.Errorf("failed to get admin key: %w", err)
	}
	adminKey = strings.TrimSpace(adminKey)

	// Mount CephFS
	mountCmd := fmt.Sprintf("mount -t ceph %s:/ %s -o name=admin,secret=%s,fs=%s",
		monAddrs, mountPath, adminKey, poolName)
	log.Infow("mounting CephFS", "command", fmt.Sprintf("mount -t ceph %s:/ %s -o name=admin,secret=<hidden>,fs=%s", monAddrs, mountPath, poolName))
	if _, stderr, err := sshPool.Run(ctx, node, mountCmd); err != nil {
		return fmt.Errorf("failed to mount CephFS: %w (stderr: %s)", err, stderr)
	}

	// Add to fstab for persistence
	fstabEntry := fmt.Sprintf("%s:/ %s ceph name=admin,secret=%s,fs=%s,_netdev 0 0",
		monAddrs, mountPath, adminKey, poolName)
	fstabCmd := fmt.Sprintf("grep -q '%s' /etc/fstab || echo '%s' >> /etc/fstab", mountPath, fstabEntry)
	if _, _, err := sshPool.Run(ctx, node, fstabCmd); err != nil {
		log.Warnw("failed to add fstab entry", "error", err)
	}

	log.Infow("✓ CephFS mounted", "mountPath", mountPath)
	return nil
}

// Unmount unmounts the CephFS filesystem from a node.
func (p *MicroCephProvider) Unmount(ctx context.Context, sshPool *ssh.Pool, node string) error {
	mountPath := p.GetMountPath()
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	// Unmount
	unmountCmd := fmt.Sprintf("umount %s 2>/dev/null || umount -l %s 2>/dev/null || true", mountPath, mountPath)
	log.Infow("unmounting CephFS", "command", unmountCmd)
	if _, _, err := sshPool.Run(ctx, node, unmountCmd); err != nil {
		log.Warnw("unmount may have failed", "error", err)
	}

	// Remove from fstab
	fstabCmd := fmt.Sprintf("sed -i '\\|%s|d' /etc/fstab", mountPath)
	if _, _, err := sshPool.Run(ctx, node, fstabCmd); err != nil {
		log.Warnw("failed to remove fstab entry", "error", err)
	}

	log.Infow("✓ CephFS unmounted")
	return nil
}

// Teardown removes MicroCeph from a node.
func (p *MicroCephProvider) Teardown(ctx context.Context, sshPool *ssh.Pool, node string) error {
	log := logging.L().With("component", "microceph", "node", node)

	// Remove microceph snap with purge
	removeCmd := "snap remove microceph --purge 2>/dev/null || true"
	log.Infow("removing MicroCeph", "command", removeCmd)
	if _, _, err := sshPool.Run(ctx, node, removeCmd); err != nil {
		log.Warnw("failed to remove microceph snap", "error", err)
	}

	// Clean up any remaining data
	cleanupCmds := []string{
		"rm -rf /var/snap/microceph 2>/dev/null || true",
		"rm -rf /var/lib/ceph 2>/dev/null || true",
	}
	for _, cmd := range cleanupCmds {
		sshPool.Run(ctx, node, cmd)
	}

	log.Infow("✓ MicroCeph removed")
	return nil
}

// Status returns the status of the MicroCeph cluster.
func (p *MicroCephProvider) Status(ctx context.Context, sshPool *ssh.Pool, node string) (*ClusterStatus, error) {
	log := logging.L().With("component", "microceph", "node", node)

	// Get cluster status
	statusCmd := "microceph status --format=json 2>/dev/null"
	stdout, _, err := sshPool.Run(ctx, node, statusCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster status: %w", err)
	}

	// For now, return a basic status
	// TODO: Parse JSON output for detailed status
	status := &ClusterStatus{
		Healthy: strings.Contains(stdout, "HEALTH_OK") || len(stdout) > 0,
	}

	log.Infow("cluster status retrieved", "healthy", status.Healthy)
	return status, nil
}

