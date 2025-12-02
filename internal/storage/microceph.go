package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
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
	mcCfg := ds.Providers.MicroCeph
	channel := mcCfg.SnapChannel
	if channel == "" {
		channel = "squid/stable"
	}

	// Install microceph snap
	installCmd := fmt.Sprintf("snap install microceph --channel=%s", channel)
	log.Infow("installing MicroCeph", "command", installCmd, "channel", channel)
	if _, stderr, err := sshPool.Run(ctx, node, installCmd); err != nil {
		return fmt.Errorf("failed to install microceph: %w (stderr: %s)", err, stderr)
	}

	// Hold snap updates if EnableUpdates is false (default)
	if !mcCfg.EnableUpdates {
		holdCmd := "snap refresh --hold microceph"
		log.Infow("holding MicroCeph updates", "command", holdCmd)
		if _, stderr, err := sshPool.Run(ctx, node, holdCmd); err != nil {
			log.Warnw("failed to hold snap updates (non-fatal)", "error", err, "stderr", stderr)
		}
	}

	// Wait for snap to be ready
	time.Sleep(2 * time.Second)

	log.Infow("✓ MicroCeph installed", "channel", channel, "updatesEnabled", mcCfg.EnableUpdates)
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
		} else {
			return fmt.Errorf("failed to bootstrap cluster: %w (stderr: %s)", err, stderr)
		}
	}

	// Configure Ceph network CIDR using overlay/private network detection
	// Priority: RFC 6598 (100.64.0.0/10) > RFC 1918 (10/8, 172.16/12, 192.168/16) > don't set
	if cidr := p.detectNetworkCIDR(ctx, sshPool, primaryNode); cidr != "" {
		log.Infow("configuring Ceph cluster network", "cidr", cidr)
		// Set both public and cluster network to the same CIDR
		// public_network: for client traffic (MON, MDS, RGW)
		// cluster_network: for OSD replication traffic
		setCmds := []string{
			fmt.Sprintf("ceph config set global cluster_network %s", cidr),
			fmt.Sprintf("ceph config set global public_network %s", cidr),
		}
		for _, cmd := range setCmds {
			log.Infow("setting Ceph network config", "command", cmd)
			if _, stderr, err := sshPool.Run(ctx, primaryNode, cmd); err != nil {
				log.Warnw("failed to set network config (non-fatal)", "command", cmd, "error", err, "stderr", stderr)
			}
		}
	} else {
		log.Infow("no overlay/private network detected, skipping network CIDR configuration")
	}

	log.Infow("✓ MicroCeph cluster bootstrapped")
	return nil
}

// detectNetworkCIDR detects the appropriate network CIDR for Ceph cluster communication.
// Priority: RFC 6598 overlay (100.64.0.0/10) > RFC 1918 private > none
func (p *MicroCephProvider) detectNetworkCIDR(ctx context.Context, sshPool *ssh.Pool, node string) string {
	log := logging.L().With("component", "microceph", "node", node)

	// Get all IPv4 addresses with their CIDR notation
	// Using 'ip -4 addr show' to get addresses in CIDR format
	cmd := "ip -4 -o addr show | awk '{print $4}' | grep -v '^127\\.'"
	stdout, _, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		log.Warnw("failed to detect network addresses", "error", err)
		return ""
	}

	var cgnatCIDR, rfc1918CIDR string
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr == "" {
			continue
		}

		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// Check RFC 6598 (CGNAT - overlay networks like Netbird/Tailscale)
		// 100.64.0.0/10
		if ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127 {
			cgnatCIDR = cidr
			log.Debugw("found RFC 6598 overlay network", "cidr", cidr)
			continue
		}

		// Check RFC 1918 private networks
		// Priority: 10.0.0.0/8 (Class A) > 172.16.0.0/12 (Class B) > 192.168.0.0/16 (Class C)
		if ip[0] == 10 {
			if rfc1918CIDR == "" || !strings.HasPrefix(rfc1918CIDR, "10.") {
				rfc1918CIDR = cidr
				log.Debugw("found RFC 1918 Class A network", "cidr", cidr)
			}
		} else if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
			if rfc1918CIDR == "" || strings.HasPrefix(rfc1918CIDR, "192.168.") {
				rfc1918CIDR = cidr
				log.Debugw("found RFC 1918 Class B network", "cidr", cidr)
			}
		} else if ip[0] == 192 && ip[1] == 168 {
			if rfc1918CIDR == "" {
				rfc1918CIDR = cidr
				log.Debugw("found RFC 1918 Class C network", "cidr", cidr)
			}
		}
	}

	// Priority: RFC 6598 (overlay) > RFC 1918 (private)
	if cgnatCIDR != "" {
		log.Infow("using RFC 6598 overlay network for Ceph", "cidr", cgnatCIDR)
		return cgnatCIDR
	}
	if rfc1918CIDR != "" {
		log.Infow("using RFC 1918 private network for Ceph", "cidr", rfc1918CIDR)
		return rfc1918CIDR
	}

	return ""
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

	// Get eligible disks using inclusion/exclusion patterns
	eligibleDisks, err := p.getEligibleDisks(ctx, sshPool, node)
	if err != nil {
		log.Warnw("failed to get eligible disks", "error", err)
	}

	// Add physical disks first
	addedDisks := 0
	for _, disk := range eligibleDisks {
		addCmd := fmt.Sprintf("microceph disk add %s --wipe", disk)
		log.Infow("adding disk", "disk", disk, "command", addCmd)
		if _, stderr, err := sshPool.Run(ctx, node, addCmd); err != nil {
			log.Warnw("failed to add disk (may already be in use)", "disk", disk, "error", err, "stderr", stderr)
		} else {
			addedDisks++
		}
	}

	// If no physical disks were added and loop devices are allowed, add a loop device
	if addedDisks == 0 && mcCfg.AllowLoopDevices {
		log.Infow("no physical disks added, creating loop device",
			"directory", mcCfg.LoopDeviceDirectory,
			"sizeGB", mcCfg.LoopDeviceSizeGB,
			"thinProvision", mcCfg.LoopDeviceThinProvision)

		// Ensure loop device directory exists
		mkdirCmd := fmt.Sprintf("mkdir -p %s", mcCfg.LoopDeviceDirectory)
		log.Infow("ensuring loop device directory exists", "command", mkdirCmd)
		if _, stderr, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
			return fmt.Errorf("failed to create loop device directory: %w (stderr: %s)", err, stderr)
		}

		// MicroCeph loop device format: loop,<size>G,<count>
		// The --data-dir flag specifies where to store the loop file
		loopSpec := fmt.Sprintf("loop,%dG,1", mcCfg.LoopDeviceSizeGB)
		addCmd := fmt.Sprintf("microceph disk add %s --data-dir %s", loopSpec, mcCfg.LoopDeviceDirectory)
		log.Infow("adding loop device", "command", addCmd)
		if _, stderr, err := sshPool.Run(ctx, node, addCmd); err != nil {
			return fmt.Errorf("failed to add loop device: %w (stderr: %s)", err, stderr)
		}
		log.Infow("✓ loop device added", "directory", mcCfg.LoopDeviceDirectory, "sizeGB", mcCfg.LoopDeviceSizeGB)
	} else if addedDisks > 0 {
		log.Infow("✓ physical disks added", "count", addedDisks)
	} else {
		log.Warnw("no storage added - no eligible disks and loop devices not allowed")
	}

	return nil
}

// getEligibleDisks returns disks that match inclusion patterns and don't match exclusion patterns.
func (p *MicroCephProvider) getEligibleDisks(ctx context.Context, sshPool *ssh.Pool, node string) ([]string, error) {
	log := logging.L().With("component", "microceph", "node", node)
	ds := p.cfg.GetDistributedStorage()

	// List all available disks
	listCmd := "lsblk -dpno NAME,TYPE | grep disk | awk '{print $1}'"
	stdout, _, err := sshPool.Run(ctx, node, listCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list disks: %w", err)
	}

	allDisks := strings.Split(strings.TrimSpace(stdout), "\n")
	inclusions := ds.EligibleDisks.InclusionExpression
	exclusions := ds.EligibleDisks.ExclusionExpression

	log.Infow("filtering disks", "totalDisks", len(allDisks), "inclusionPatterns", inclusions, "exclusionPatterns", exclusions)

	// Step 1: Apply inclusion filter (OR logic - "can match this OR this")
	var includedDisks []string
	for _, disk := range allDisks {
		disk = strings.TrimSpace(disk)
		if disk == "" {
			continue
		}

		// If no inclusions specified, include all disks
		if len(inclusions) == 0 {
			includedDisks = append(includedDisks, disk)
			continue
		}

		// Check if disk matches ANY inclusion pattern
		for _, pattern := range inclusions {
			matched, err := regexp.MatchString(pattern, disk)
			if err != nil {
				log.Warnw("invalid inclusion regex", "pattern", pattern, "error", err)
				continue
			}
			if matched {
				includedDisks = append(includedDisks, disk)
				log.Debugw("disk passed inclusion filter", "disk", disk, "pattern", pattern)
				break
			}
		}
	}

	log.Infow("after inclusion filter", "includedCount", len(includedDisks), "disks", includedDisks)

	// Step 2: Apply exclusion filter to included disks (OR logic - "must NOT match this OR this")
	var eligibleDisks []string
	for _, disk := range includedDisks {
		excluded := false
		for _, pattern := range exclusions {
			matched, err := regexp.MatchString(pattern, disk)
			if err != nil {
				log.Warnw("invalid exclusion regex", "pattern", pattern, "error", err)
				continue
			}
			if matched {
				excluded = true
				log.Debugw("disk dropped by exclusion filter", "disk", disk, "pattern", pattern)
				break
			}
		}
		if !excluded {
			eligibleDisks = append(eligibleDisks, disk)
		}
	}

	log.Infow("after exclusion filter (final eligible)", "eligibleCount", len(eligibleDisks), "disks", eligibleDisks)
	return eligibleDisks, nil
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

// EnableRadosGateway enables RADOS Gateway (S3-compatible) on the specified OSD nodes.
// RGW is enabled on workers (OSD nodes) only, with placement for HA across multiple nodes.
func (p *MicroCephProvider) EnableRadosGateway(ctx context.Context, sshPool *ssh.Pool, osdNodes []string, port int) (*RadosGatewayInfo, error) {
	log := logging.L().With("component", "microceph-rgw", "port", port, "nodes", len(osdNodes))

	if len(osdNodes) == 0 {
		return nil, fmt.Errorf("no OSD nodes provided for RGW")
	}
	if port == 0 {
		port = 7480 // Default RGW port
	}

	// Use first OSD node as primary for commands
	primaryOSD := osdNodes[0]

	// Build placement string with all OSD hostnames for HA
	// Format: --target node1 --target node2 --target node3
	var placementArgs []string
	for _, node := range osdNodes {
		placementArgs = append(placementArgs, "--target", node)
	}

	// Enable RGW with placement on all OSD nodes
	// microceph enable rgw --target node1 --target node2 ...
	enableCmd := fmt.Sprintf("microceph enable rgw --port %d %s", port, strings.Join(placementArgs, " "))
	log.Infow("enabling RADOS Gateway on OSD nodes", "command", enableCmd)
	if _, stderr, err := sshPool.Run(ctx, primaryOSD, enableCmd); err != nil {
		// Check if already enabled
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "enabled") {
			log.Infow("RGW already enabled, continuing")
		} else {
			return nil, fmt.Errorf("failed to enable RGW: %w (stderr: %s)", err, stderr)
		}
	}

	// Wait for RGW to start
	time.Sleep(5 * time.Second)

	// Create S3 user for cluster access
	userID := "clusterctl-s3-user"
	displayName := "Clusterctl S3 User"
	createUserCmd := fmt.Sprintf("radosgw-admin user create --uid=%s --display-name=\"%s\" 2>/dev/null || radosgw-admin user info --uid=%s", userID, displayName, userID)
	log.Infow("creating/retrieving S3 user", "userId", userID)
	stdout, stderr, err := sshPool.Run(ctx, primaryOSD, createUserCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to create/get S3 user: %w (stderr: %s)", err, stderr)
	}

	// Parse the user info JSON to extract access_key and secret_key
	accessKey, secretKey, err := parseRadosGWUserKeys(stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse S3 user credentials: %w", err)
	}

	// Build endpoint list using hostnames (with precedence)
	var endpoints []string
	for _, node := range osdNodes {
		endpoint := fmt.Sprintf("http://%s:%d", node, port)
		endpoints = append(endpoints, endpoint)
	}

	log.Infow("✓ RADOS Gateway enabled",
		"endpoints", endpoints,
		"userId", userID,
		"accessKey", accessKey)

	return &RadosGatewayInfo{
		Endpoints: endpoints,
		AccessKey: accessKey,
		SecretKey: secretKey,
		UserID:    userID,
	}, nil
}

// parseRadosGWUserKeys extracts access_key and secret_key from radosgw-admin user JSON output.
func parseRadosGWUserKeys(jsonOutput string) (accessKey, secretKey string, err error) {
	// Simple JSON parsing for keys array
	// Expected format: { "keys": [ { "access_key": "...", "secret_key": "..." } ] }
	type rgwKey struct {
		AccessKey string `json:"access_key"`
		SecretKey string `json:"secret_key"`
	}
	type rgwUser struct {
		Keys []rgwKey `json:"keys"`
	}

	var user rgwUser
	if err := json.Unmarshal([]byte(jsonOutput), &user); err != nil {
		return "", "", fmt.Errorf("failed to parse user JSON: %w", err)
	}

	if len(user.Keys) == 0 {
		return "", "", fmt.Errorf("no keys found in user info")
	}

	return user.Keys[0].AccessKey, user.Keys[0].SecretKey, nil
}
