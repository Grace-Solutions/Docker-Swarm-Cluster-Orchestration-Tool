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
		channel = "reef/stable"
	}

	// Install microceph snap
	installCmd := fmt.Sprintf("snap install microceph --channel=%s", channel)
	log.Infow("installing MicroCeph", "command", installCmd, "channel", channel)
	if _, stderr, err := sshPool.Run(ctx, node, installCmd); err != nil {
		// Check if already installed
		if strings.Contains(stderr, "already installed") {
			log.Infow("MicroCeph already installed, continuing")
		} else {
			return fmt.Errorf("failed to install microceph: %w (stderr: %s)", err, stderr)
		}
	}

	// Hold snap updates if EnableUpdates is false (default)
	if !mcCfg.EnableUpdates {
		holdCmd := "snap refresh --hold microceph"
		if _, stderr, err := sshPool.Run(ctx, node, holdCmd); err != nil {
			log.Warnw("failed to hold snap updates (non-fatal)", "error", err, "stderr", stderr)
		}
	}

	log.Infow("✓ MicroCeph installed", "channel", channel)
	return nil
}

// Bootstrap initializes the MicroCeph cluster on the primary node.
func (p *MicroCephProvider) Bootstrap(ctx context.Context, sshPool *ssh.Pool, primaryNode string) error {
	log := logging.L().With("component", "microceph", "node", primaryNode)

	// Detect the best network for Ceph BEFORE bootstrap
	// Priority: RFC 6598 overlay (Netbird/Tailscale 100.x.x.x) > RFC 1918 private
	// This is critical - without --mon-ip, Ceph may bind to wrong interface causing TLS handshake failures
	netInfo := p.detectNetworkInfo(ctx, sshPool, primaryNode)

	// Build bootstrap command with network binding options
	bootstrapCmd := "microceph cluster bootstrap"
	if netInfo != nil {
		// --microceph-ip: Network address microceph daemon binds to (internal cluster communication)
		// --mon-ip: Public address for bootstrapping ceph mon service
		// --cluster-network: Cluster network CIDR for Ceph daemons (OSD replication)
		bootstrapCmd = fmt.Sprintf("microceph cluster bootstrap --microceph-ip %s --mon-ip %s --cluster-network %s",
			netInfo.IP, netInfo.IP, netInfo.CIDR)
	} else {
		log.Warnw("could not detect overlay/private network, bootstrap may bind to wrong interface")
	}

	// Log the full command for easy copy/paste debugging
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Infow("BOOTSTRAP COMMAND:", "cmd", bootstrapCmd)
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		stdout, stderr, err := sshPool.Run(ctx, primaryNode, bootstrapCmd)
		if err == nil {
			log.Infow("✓ MicroCeph cluster bootstrap succeeded")
			if stdout != "" {
				log.Infow("bootstrap output", "stdout", strings.TrimSpace(stdout))
			}
			lastErr = nil
			break
		}

		// Check if already bootstrapped
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "exists") || strings.Contains(stderr, "initialized") || strings.Contains(stderr, "This node is already part of a MicroCeph cluster") {
			log.Infow("cluster already bootstrapped, continuing")
			lastErr = nil
			break
		}

		log.Warnw("bootstrap failed", "attempt", attempt, "maxAttempts", 3, "stderr", strings.TrimSpace(stderr))
		lastErr = fmt.Errorf("failed to bootstrap cluster: %w (stderr: %s)", err, stderr)
		time.Sleep(5 * time.Second)
	}
	if lastErr != nil {
		return lastErr
	}

	// Verify cluster is bootstrapped by checking status
	stdout, stderr, err := sshPool.Run(ctx, primaryNode, "microceph status")
	if err != nil {
		return fmt.Errorf("cluster bootstrap succeeded but status check failed: %w (stderr: %s)", err, stderr)
	}
	log.Infow("cluster status", "status", strings.TrimSpace(stdout))

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

// NetworkInfo contains detected network information for Ceph binding
type NetworkInfo struct {
	IP   string // The best IP address (e.g., "100.76.132.128")
	CIDR string // The network CIDR (e.g., "100.76.132.128/16")
}

// detectNetworkInfo detects the appropriate network IP and CIDR for Ceph cluster communication.
// Priority: RFC 6598 overlay (100.64.0.0/10) > RFC 1918 private > none
// Returns both the IP (for --mon-ip) and CIDR (for --cluster-network)
func (p *MicroCephProvider) detectNetworkInfo(ctx context.Context, sshPool *ssh.Pool, node string) *NetworkInfo {
	log := logging.L().With("component", "microceph", "node", node)

	// Get all IPv4 addresses with their CIDR notation
	// Using 'ip -4 addr show' to get addresses in CIDR format
	cmd := "ip -4 -o addr show | awk '{print $4}' | grep -v '^127\\.'"
	stdout, stderr, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		log.Warnw("failed to detect network addresses", "error", err, "stderr", stderr)
		return nil
	}

	log.Infow("detected network addresses", "raw", strings.TrimSpace(stdout))

	var cgnatInfo, rfc1918Info *NetworkInfo
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		cidr := strings.TrimSpace(line)
		if cidr == "" {
			continue
		}

		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Warnw("failed to parse CIDR", "cidr", cidr, "error", err)
			continue
		}

		// Convert to 4-byte IPv4 representation (net.IP can be 4 or 16 bytes)
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}

		log.Debugw("checking IP", "ip", ip4.String(), "cidr", cidr, "byte0", ip4[0], "byte1", ip4[1])

		// Check RFC 6598 (CGNAT - overlay networks like Netbird/Tailscale)
		// 100.64.0.0/10 means first byte = 100, second byte 64-127
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			cgnatInfo = &NetworkInfo{IP: ip4.String(), CIDR: cidr}
			log.Infow("found RFC 6598 overlay network", "ip", ip4.String(), "cidr", cidr)
			continue
		}

		// Check RFC 1918 private networks
		// Priority: 10.0.0.0/8 (Class A) > 172.16.0.0/12 (Class B) > 192.168.0.0/16 (Class C)
		if ip4[0] == 10 {
			if rfc1918Info == nil || !strings.HasPrefix(rfc1918Info.CIDR, "10.") {
				rfc1918Info = &NetworkInfo{IP: ip4.String(), CIDR: cidr}
				log.Infow("found RFC 1918 Class A network", "ip", ip4.String(), "cidr", cidr)
			}
		} else if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			if rfc1918Info == nil || strings.HasPrefix(rfc1918Info.CIDR, "192.168.") {
				rfc1918Info = &NetworkInfo{IP: ip4.String(), CIDR: cidr}
				log.Infow("found RFC 1918 Class B network", "ip", ip4.String(), "cidr", cidr)
			}
		} else if ip4[0] == 192 && ip4[1] == 168 {
			if rfc1918Info == nil {
				rfc1918Info = &NetworkInfo{IP: ip4.String(), CIDR: cidr}
				log.Infow("found RFC 1918 Class C network", "ip", ip4.String(), "cidr", cidr)
			}
		}
	}

	// Priority: RFC 6598 (overlay) > RFC 1918 (private)
	if cgnatInfo != nil {
		log.Infow("selected RFC 6598 overlay network for Ceph", "ip", cgnatInfo.IP, "cidr", cgnatInfo.CIDR)
		return cgnatInfo
	}
	if rfc1918Info != nil {
		log.Infow("selected RFC 1918 private network for Ceph", "ip", rfc1918Info.IP, "cidr", rfc1918Info.CIDR)
		return rfc1918Info
	}

	log.Warnw("no suitable network found for Ceph binding")
	return nil
}

// detectNetworkCIDR detects the appropriate network CIDR for Ceph cluster communication.
// Priority: RFC 6598 overlay (100.64.0.0/10) > RFC 1918 private > none
// Wrapper for backward compatibility
func (p *MicroCephProvider) detectNetworkCIDR(ctx context.Context, sshPool *ssh.Pool, node string) string {
	info := p.detectNetworkInfo(ctx, sshPool, node)
	if info != nil {
		return info.CIDR
	}
	return ""
}

// GenerateJoinToken adds a node to the cluster and returns a join token.
// For reef/stable MicroCeph, this uses 'microceph cluster add <hostname>'.
// The hostname is fetched from the joining node to ensure it matches.
func (p *MicroCephProvider) GenerateJoinToken(ctx context.Context, sshPool *ssh.Pool, primaryNode, joiningNode string) (string, error) {
	log := logging.L().With("component", "microceph", "primaryNode", primaryNode, "joiningNode", joiningNode)

	// Get the actual hostname from the joining node (microceph uses system hostname)
	hostnameCmd := "hostname"
	hostname, _, err := sshPool.Run(ctx, joiningNode, hostnameCmd)
	if err != nil {
		return "", fmt.Errorf("failed to get hostname from joining node: %w", err)
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", fmt.Errorf("empty hostname returned from joining node")
	}
	log.Infow("resolved joining node hostname", "sshHost", joiningNode, "hostname", hostname)

	// Add node to cluster using 'microceph cluster add' (reef/stable channel)
	// This returns a join token that must be used on the joining node
	addCmd := fmt.Sprintf("microceph cluster add %s", hostname)
	log.Infow("generating join token for node", "command", addCmd, "hostname", hostname)
	stdout, stderr, err := sshPool.Run(ctx, primaryNode, addCmd)
	if err != nil {
		// Check if node already exists
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "exists") || strings.Contains(stderr, "is already a cluster member") {
			log.Infow("node already added to cluster, continuing", "hostname", hostname)
			// Return empty token - join will be skipped
			return "", nil
		}
		return "", fmt.Errorf("failed to add node to cluster: %w (stderr: %s)", err, stderr)
	}

	token := strings.TrimSpace(stdout)
	if token == "" {
		return "", fmt.Errorf("no join token returned from 'microceph cluster add'")
	}

	// Log the token for visibility
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Infow("JOIN TOKEN GENERATED", "hostname", hostname, "token", token)
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	return token, nil
}

// Join joins a node to an existing MicroCeph cluster using a join token.
func (p *MicroCephProvider) Join(ctx context.Context, sshPool *ssh.Pool, node, token string) error {
	log := logging.L().With("component", "microceph", "node", node)

	// If no token provided, check if node is already in cluster
	if token == "" {
		log.Infow("no join token provided, checking if node already in cluster")
		if _, _, err := sshPool.Run(ctx, node, "microceph status"); err == nil {
			log.Infow("node already in cluster")
			return nil
		}
		return fmt.Errorf("no join token and node not in cluster")
	}

	// Verify MicroCeph daemon service is running on joining node
	statusCmd := `systemctl status snap.microceph.daemon.service --no-pager 2>/dev/null | grep -q "active (running)" && echo "running" || echo "not running"`
	stdout, _, _ := sshPool.Run(ctx, node, statusCmd)
	if !strings.Contains(stdout, "running") || strings.Contains(stdout, "not running") {
		log.Warnw("MicroCeph daemon service not running on joining node")
	}

	// Verify MicroCeph database is ready on joining node
	dbCheckCmd := "microceph status >/dev/null 2>&1 && echo 'ready' || echo 'not ready'"
	stdout, _, _ = sshPool.Run(ctx, node, dbCheckCmd)
	if strings.Contains(stdout, "not ready") {
		// Wait for database to be ready
		log.Infow("waiting for MicroCeph database to initialize on joining node")
		waitDbCmd := `for i in $(seq 1 15); do microceph status >/dev/null 2>&1 && exit 0; sleep 2; done; exit 1`
		if _, _, err := sshPool.Run(ctx, node, waitDbCmd); err != nil {
			log.Warnw("MicroCeph database may not be ready on joining node, attempting join anyway")
		}
	}

	// Join the cluster using the token
	joinCmd := fmt.Sprintf("microceph cluster join %s", token)
	log.Infow("joining MicroCeph cluster", "command", "microceph cluster join <token>")
	if _, stderr, err := sshPool.Run(ctx, node, joinCmd); err != nil {
		// Check if already joined
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "member") {
			log.Infow("node already joined to cluster")
			return nil
		}
		return fmt.Errorf("failed to join cluster: %w (stderr: %s)", err, stderr)
	}

	// Verify join succeeded with microceph status
	log.Infow("verifying node joined cluster")
	if _, stderr, err := sshPool.Run(ctx, node, "microceph status"); err != nil {
		return fmt.Errorf("join succeeded but status check failed: %w (stderr: %s)", err, stderr)
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

// GetClusterCredentials retrieves the admin key and monitor addresses from the primary node.
// Uses overlay hostname precedence for MON addresses: overlay hostname > overlay IP > private.
// monNodes is the list of MON node SSH hostnames (for resolving overlay addresses).
func (p *MicroCephProvider) GetClusterCredentials(ctx context.Context, sshPool *ssh.Pool, primaryNode string, monNodes []string, overlayProvider string) (*ClusterCredentials, error) {
	log := logging.L().With("component", "microceph", "node", primaryNode)

	// Get admin key
	keyCmd := "ceph auth get-key client.admin 2>/dev/null"
	adminKey, stderr, err := sshPool.Run(ctx, primaryNode, keyCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin key: %w (stderr: %s)", err, stderr)
	}
	adminKey = strings.TrimSpace(adminKey)
	if adminKey == "" {
		return nil, fmt.Errorf("empty admin key returned")
	}

	// Build monitor addresses using overlay hostname precedence
	// Format: hostname1:6789,hostname2:6789,hostname3:6789
	const monPort = 6789
	var monAddrList []string

	for _, monNode := range monNodes {
		// Resolve overlay hostname/IP for each MON node
		addr := resolveNodeAddress(ctx, sshPool, monNode, overlayProvider)
		monAddrList = append(monAddrList, fmt.Sprintf("%s:%d", addr, monPort))
		log.Debugw("resolved MON address", "node", monNode, "addr", addr, "port", monPort)
	}

	monAddrs := strings.Join(monAddrList, ",")
	if monAddrs == "" {
		return nil, fmt.Errorf("no MON addresses resolved")
	}

	log.Infow("retrieved cluster credentials", "monAddrs", monAddrs, "adminKeyLen", len(adminKey), "monCount", len(monAddrList))
	return &ClusterCredentials{
		AdminKey: adminKey,
		MonAddrs: monAddrs,
	}, nil
}

// MountWithCredentials mounts CephFS on a node using pre-fetched credentials.
// This is more efficient than Mount() when mounting multiple nodes.
func (p *MicroCephProvider) MountWithCredentials(ctx context.Context, sshPool *ssh.Pool, node, poolName string, creds *ClusterCredentials) error {
	mountPath := p.GetMountPath()
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	if creds == nil {
		return fmt.Errorf("cluster credentials required")
	}

	// Create mount directory
	mkdirCmd := fmt.Sprintf("mkdir -p %s", mountPath)
	if _, _, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create mount directory: %w", err)
	}

	// Mount CephFS using provided credentials
	mountCmd := fmt.Sprintf("mount -t ceph %s:/ %s -o name=admin,secret=%s,fs=%s",
		creds.MonAddrs, mountPath, creds.AdminKey, poolName)
	log.Infow("mounting CephFS", "monAddrs", creds.MonAddrs, "fs", poolName)
	if _, stderr, err := sshPool.Run(ctx, node, mountCmd); err != nil {
		return fmt.Errorf("failed to mount CephFS: %w (stderr: %s)", err, stderr)
	}

	// Add to fstab for persistence
	fstabEntry := fmt.Sprintf("%s:/ %s ceph name=admin,secret=%s,fs=%s,_netdev 0 0",
		creds.MonAddrs, mountPath, creds.AdminKey, poolName)
	fstabCmd := fmt.Sprintf("grep -q '%s' /etc/fstab || echo '%s' >> /etc/fstab", mountPath, fstabEntry)
	if _, _, err := sshPool.Run(ctx, node, fstabCmd); err != nil {
		log.Warnw("failed to add fstab entry", "error", err)
	}

	// Reload systemd to pick up fstab changes
	if _, _, err := sshPool.Run(ctx, node, "systemctl daemon-reload"); err != nil {
		log.Warnw("failed to reload systemd daemon", "error", err)
	}

	log.Infow("✓ CephFS mounted", "mountPath", mountPath)
	return nil
}

// Mount mounts the CephFS filesystem on a node (fetches credentials from node itself).
// Prefer MountWithCredentials when mounting multiple nodes.
// Note: This falls back to using the node's own address without overlay precedence.
func (p *MicroCephProvider) Mount(ctx context.Context, sshPool *ssh.Pool, node, poolName string) error {
	// Get credentials from this node - uses the node as its own MON with no overlay provider
	// This is a fallback; prefer MountWithCredentials with proper overlay resolution
	creds, err := p.GetClusterCredentials(ctx, sshPool, node, []string{node}, "")
	if err != nil {
		return fmt.Errorf("failed to get cluster credentials: %w", err)
	}
	return p.MountWithCredentials(ctx, sshPool, node, poolName, creds)
}

// Unmount unmounts the CephFS filesystem from a node.
func (p *MicroCephProvider) Unmount(ctx context.Context, sshPool *ssh.Pool, node string) error {
	mountPath := p.GetMountPath()
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	// Check if mount path is actually mounted
	checkCmd := fmt.Sprintf("mountpoint -q %s 2>/dev/null && echo 'mounted' || echo 'not mounted'", mountPath)
	stdout, _, _ := sshPool.Run(ctx, node, checkCmd)
	if strings.Contains(stdout, "not mounted") {
		log.Infow("CephFS not mounted, skipping unmount")
		return nil
	}

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

	// Check if MicroCeph is installed
	checkCmd := "snap list microceph 2>/dev/null"
	stdout, _, _ := sshPool.Run(ctx, node, checkCmd)
	if !strings.Contains(stdout, "microceph") {
		log.Infow("MicroCeph not installed, skipping removal")
		return nil
	}

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

	// Get microceph status
	mcStatusCmd := "microceph status"
	mcStdout, _, err := sshPool.Run(ctx, node, mcStatusCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get microceph status: %w", err)
	}
	log.Infow("MicroCeph cluster status", "output", strings.TrimSpace(mcStdout))

	// Get ceph status for health info
	cephStatusCmd := "ceph status"
	cephStdout, _, err := sshPool.Run(ctx, node, cephStatusCmd)
	if err != nil {
		log.Warnw("failed to get ceph status", "error", err)
	} else {
		log.Infow("Ceph cluster status", "output", strings.TrimSpace(cephStdout))
	}

	// Determine health from ceph status output
	healthy := strings.Contains(cephStdout, "HEALTH_OK")
	if !healthy && strings.Contains(cephStdout, "HEALTH_WARN") {
		// HEALTH_WARN is acceptable for newly created clusters
		healthy = true
		log.Infow("cluster health is HEALTH_WARN (acceptable for new clusters)")
	}

	// Count OSDs from status
	osdCount := 0
	if strings.Contains(cephStdout, "osd:") {
		// Parse "osd: N osds: N up, N in" pattern
		lines := strings.Split(cephStdout, "\n")
		for _, line := range lines {
			if strings.Contains(line, "osd:") && strings.Contains(line, "osds:") {
				// Extract first number after "osd:"
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "osd:" && i+1 < len(parts) {
						fmt.Sscanf(parts[i+1], "%d", &osdCount)
						break
					}
				}
			}
		}
	}

	status := &ClusterStatus{
		Healthy:   healthy,
		NodeCount: osdCount,
	}

	log.Infow("✓ cluster status verified", "healthy", status.Healthy, "osdCount", osdCount)
	return status, nil
}

// EnableRadosGateway enables RADOS Gateway (S3-compatible) on the specified OSD nodes.
// RGW is enabled on workers (OSD nodes) only, with placement for HA across multiple nodes.
// Hostname precedence: overlay hostname > overlay IP > private hostname > private IP.
func (p *MicroCephProvider) EnableRadosGateway(ctx context.Context, sshPool *ssh.Pool, osdNodes []string, port int, overlayProvider string) (*RadosGatewayInfo, error) {
	log := logging.L().With("component", "microceph-rgw", "port", port, "nodes", len(osdNodes), "overlayProvider", overlayProvider)

	if len(osdNodes) == 0 {
		return nil, fmt.Errorf("no OSD nodes provided for RGW")
	}
	if port == 0 {
		port = 7480 // Default RGW port
	}

	// Use first OSD node to run the enable command (only needs to run once)
	primaryOSD := osdNodes[0]

	// Build placement string with comma-separated hostnames for HA
	// Format: --placement=node1,node2,node3
	placement := strings.Join(osdNodes, ",")

	// Enable RGW with placement on all OSD nodes (run from one node only)
	// microceph enable rgw --port 7480 --placement=node1,node2,node3
	enableCmd := fmt.Sprintf("microceph enable rgw --port %d --placement=%s", port, placement)
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

	// Build endpoint list using hostname precedence:
	// overlay hostname > overlay IP > private hostname > private IP
	var endpoints []string
	for _, node := range osdNodes {
		addr := resolveNodeAddress(ctx, sshPool, node, overlayProvider)
		endpoint := fmt.Sprintf("http://%s:%d", addr, port)
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

// resolveNodeAddress resolves the best address for a node with precedence:
// 1. Overlay hostname (netbird FQDN / tailscale DNSName)
// 2. Overlay IP (100.x.x.x)
// 3. Private hostname (system hostname)
// 4. Private IP (RFC 1918)
func resolveNodeAddress(ctx context.Context, sshPool *ssh.Pool, node, overlayProvider string) string {
	log := logging.L().With("component", "resolve-address", "node", node)
	overlayProvider = strings.ToLower(strings.TrimSpace(overlayProvider))

	// Try overlay hostname first
	if overlayProvider == "netbird" {
		stdout, _, err := sshPool.Run(ctx, node, "netbird status --json")
		if err == nil {
			var status struct {
				FQDN      string `json:"fqdn"`
				NetbirdIP string `json:"netbirdIp"`
			}
			if json.Unmarshal([]byte(stdout), &status) == nil {
				// 1. Overlay hostname
				if status.FQDN != "" {
					log.Debugw("using overlay hostname", "node", node, "fqdn", status.FQDN)
					return status.FQDN
				}
				// 2. Overlay IP
				if status.NetbirdIP != "" {
					ip := strings.Split(status.NetbirdIP, "/")[0]
					log.Debugw("using overlay IP", "node", node, "ip", ip)
					return ip
				}
			}
		}
	} else if overlayProvider == "tailscale" {
		stdout, _, err := sshPool.Run(ctx, node, "tailscale status --json")
		if err == nil {
			var status struct {
				Self struct {
					DNSName      string   `json:"DNSName"`
					TailscaleIPs []string `json:"TailscaleIPs"`
				} `json:"Self"`
			}
			if json.Unmarshal([]byte(stdout), &status) == nil {
				// 1. Overlay hostname
				if status.Self.DNSName != "" {
					log.Debugw("using overlay hostname", "node", node, "dnsName", status.Self.DNSName)
					return status.Self.DNSName
				}
				// 2. Overlay IP
				if len(status.Self.TailscaleIPs) > 0 {
					log.Debugw("using overlay IP", "node", node, "ip", status.Self.TailscaleIPs[0])
					return status.Self.TailscaleIPs[0]
				}
			}
		}
	}

	// 3. Private hostname
	stdout, _, err := sshPool.Run(ctx, node, "hostname -f 2>/dev/null || hostname")
	if err == nil {
		hostname := strings.TrimSpace(stdout)
		if hostname != "" {
			log.Debugw("using private hostname", "node", node, "hostname", hostname)
			return hostname
		}
	}

	// 4. Private IP (fallback to node as-is, which is typically SSH hostname/IP)
	log.Debugw("using SSH node address as fallback", "node", node)
	return node
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

// CreateS3Bucket creates an S3 bucket using radosgw-admin.
func (p *MicroCephProvider) CreateS3Bucket(ctx context.Context, sshPool *ssh.Pool, primaryOSD string, bucketName string) error {
	log := logging.L().With("component", "microceph-s3", "node", primaryOSD, "bucket", bucketName)

	if bucketName == "" {
		return fmt.Errorf("bucket name is required")
	}

	// Get the S3 user credentials first
	userID := "clusterctl-s3-user"
	getUserCmd := fmt.Sprintf("radosgw-admin user info --uid=%s", userID)
	stdout, stderr, err := sshPool.Run(ctx, primaryOSD, getUserCmd)
	if err != nil {
		return fmt.Errorf("failed to get S3 user info: %w (stderr: %s)", err, stderr)
	}

	accessKey, secretKey, err := parseRadosGWUserKeys(stdout)
	if err != nil {
		return fmt.Errorf("failed to parse S3 credentials: %w", err)
	}

	// Check if bucket already exists
	listBucketsCmd := fmt.Sprintf("radosgw-admin bucket list --uid=%s", userID)
	stdout, _, _ = sshPool.Run(ctx, primaryOSD, listBucketsCmd)
	if strings.Contains(stdout, bucketName) {
		log.Infow("bucket already exists, skipping creation")
		return nil
	}

	// Create the bucket using s3cmd or aws cli
	// First, try to install s3cmd if not present
	installCmd := "which s3cmd || apt-get update -qq && apt-get install -y -qq s3cmd"
	if _, stderr, err := sshPool.Run(ctx, primaryOSD, installCmd); err != nil {
		log.Warnw("failed to install s3cmd, trying with radosgw-admin", "stderr", stderr)
	}

	// Configure s3cmd with credentials
	s3cfgContent := fmt.Sprintf(`[default]
access_key = %s
secret_key = %s
host_base = 127.0.0.1:7480
host_bucket = 127.0.0.1:7480/%%(bucket)s
use_https = False
signature_v2 = True
`, accessKey, secretKey)

	configureCmd := fmt.Sprintf("cat > /tmp/.s3cfg << 'EOF'\n%sEOF", s3cfgContent)
	if _, stderr, err := sshPool.Run(ctx, primaryOSD, configureCmd); err != nil {
		return fmt.Errorf("failed to configure s3cmd: %w (stderr: %s)", err, stderr)
	}

	// Create the bucket using s3cmd
	createBucketCmd := fmt.Sprintf("s3cmd -c /tmp/.s3cfg mb s3://%s 2>&1 || true", bucketName)
	log.Infow("creating S3 bucket", "command", fmt.Sprintf("s3cmd mb s3://%s", bucketName))
	stdout, stderr, err = sshPool.Run(ctx, primaryOSD, createBucketCmd)
	if err != nil && !strings.Contains(stdout, "already") && !strings.Contains(stderr, "already") {
		// Try alternative method using radosgw-admin
		log.Warnw("s3cmd failed, trying radosgw-admin bucket link", "error", err)
		// Create bucket via radosgw-admin (requires bucket to be touched first)
		touchCmd := fmt.Sprintf("radosgw-admin bucket link --bucket=%s --uid=%s 2>/dev/null || true", bucketName, userID)
		sshPool.Run(ctx, primaryOSD, touchCmd)
	}

	// Verify bucket was created
	verifyCmd := fmt.Sprintf("s3cmd -c /tmp/.s3cfg ls s3://%s 2>&1 || radosgw-admin bucket stats --bucket=%s 2>&1", bucketName, bucketName)
	stdout, stderr, err = sshPool.Run(ctx, primaryOSD, verifyCmd)
	if err != nil && !strings.Contains(stdout, bucketName) {
		return fmt.Errorf("failed to verify bucket creation: %w (stdout: %s, stderr: %s)", err, stdout, stderr)
	}

	// Clean up temp config
	sshPool.Run(ctx, primaryOSD, "rm -f /tmp/.s3cfg")

	log.Infow("✓ S3 bucket created successfully")
	return nil
}
