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

	// Show current disk state after bootstrap so operators can see what
	// MicroCeph thinks is configured/available. Use JSON output so we can
	// reliably parse and log it.
	p.logDiskListJSON(ctx, sshPool, primaryNode, "post-bootstrap")
	return nil
}

// NetworkInfo contains detected network information for Ceph binding
type NetworkInfo struct {
	IP   string // The best IP address (e.g., "100.76.132.128")
	CIDR string // The network CIDR (e.g., "100.76.132.128/16")
}

// getDockerSubnets retrieves all Docker network subnets from the node.
// Returns a slice of *net.IPNet representing Docker-managed network ranges.
// These should be excluded from IP selection since Docker IPs are not routable.
func (p *MicroCephProvider) getDockerSubnets(ctx context.Context, sshPool *ssh.Pool, node string) []*net.IPNet {
	log := logging.L().With("component", "microceph", "node", node)

	// Get all Docker network subnets using docker network inspect
	// This handles bridge, overlay, and custom networks dynamically
	cmd := `docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -v '^$' || true`
	stdout, _, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		// Docker may not be installed or running - that's fine
		return nil
	}

	var subnets []*net.IPNet
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		cidr := strings.TrimSpace(line)
		if cidr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		subnets = append(subnets, ipnet)
	}

	if len(subnets) > 0 {
		subnetStrs := make([]string, len(subnets))
		for i, s := range subnets {
			subnetStrs[i] = s.String()
		}
		log.Debugw("detected Docker subnets to exclude", "subnets", subnetStrs)
	}

	return subnets
}

// isIPInDockerSubnet checks if an IP address falls within any Docker network subnet.
func isIPInDockerSubnet(ip net.IP, dockerSubnets []*net.IPNet) bool {
	for _, subnet := range dockerSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// detectNetworkInfo detects the appropriate network IP and CIDR for Ceph cluster communication.
// Priority: RFC 6598 overlay (100.64.0.0/10) > RFC 1918 private > none
// Docker network subnets are excluded since they are not routable across hosts.
// Returns both the IP (for --mon-ip) and CIDR (for --cluster-network)
func (p *MicroCephProvider) detectNetworkInfo(ctx context.Context, sshPool *ssh.Pool, node string) *NetworkInfo {
	log := logging.L().With("component", "microceph", "node", node)

	// First, get Docker network subnets to exclude
	dockerSubnets := p.getDockerSubnets(ctx, sshPool, node)

	// Get all IPv4 addresses with their CIDR notation
	// Using 'ip -4 addr show' to get addresses in CIDR format
	cmd := "ip -4 -o addr show | awk '{print $4}' | grep -v '^127\\.'"
	stdout, stderr, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		log.Warnw("failed to detect network addresses", "error", err, "stderr", stderr)
		return nil
	}

	log.Debugw("detected network addresses", "raw", strings.TrimSpace(stdout))

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

		// Skip IPs that fall within Docker network subnets
		if isIPInDockerSubnet(ip4, dockerSubnets) {
			log.Debugw("skipping IP in Docker subnet", "ip", ip4.String(), "cidr", cidr)
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
// Uses 'microceph cluster add <host>' where <host> is resolved using hostname
// precedence: overlay hostname > overlay IP > private hostname > private IP.
func (p *MicroCephProvider) GenerateJoinToken(ctx context.Context, sshPool *ssh.Pool, primaryNode, joiningNode string) (string, error) {
	log := logging.L().With("component", "microceph", "primaryNode", primaryNode, "joiningNode", joiningNode)

	// Fast path: if the joining node already appears to be part of a MicroCeph
	// cluster, do not generate a new token. This keeps the operation idempotent
	// when rerunning against an existing cluster.
	if stdout, stderr, err := sshPool.Run(ctx, joiningNode, "microceph status"); err == nil {
		log.Infow("joining node already in MicroCeph cluster; skipping cluster add/join",
			"joiningNode", joiningNode,
			"status", strings.TrimSpace(stdout))
		return "", nil
	} else {
		// On fresh nodes this is expected; log at debug level only so we do not
		// spam logs while still having enough detail for troubleshooting.
		log.Debugw("microceph status on joining node failed (proceeding with join)",
			"joiningNode", joiningNode,
			"error", err,
			"stderr", strings.TrimSpace(stderr))
	}

	// Determine the join address using the configured overlay provider (if any).
	overlayProvider := ""
	if p.cfg != nil {
		overlayProvider = p.cfg.GlobalSettings.OverlayProvider
	}
	joinAddress := resolveNodeAddress(ctx, sshPool, joiningNode, overlayProvider)
	joinAddress = strings.TrimSpace(joinAddress)
	if joinAddress == "" {
		return "", fmt.Errorf("failed to resolve join address for joining node %s", joiningNode)
	}

	log.Infow("resolved joining node address", "primaryNode", primaryNode, "joiningNode", joiningNode, "sshHost", joiningNode, "joinAddress", joinAddress)

	// Add node to cluster using 'microceph cluster add <joinAddress>'
	// This returns a join token that must be used on the joining node
	addCmd := fmt.Sprintf("microceph cluster add %s", joinAddress)
	log.Infow("generating join token for node", "primaryNode", primaryNode, "joiningNode", joiningNode, "command", addCmd, "joinAddress", joinAddress)
	stdout, stderr, err := sshPool.Run(ctx, primaryNode, addCmd)
	if err != nil {
		// Check if node already exists
		if strings.Contains(stderr, "already") || strings.Contains(stderr, "exists") || strings.Contains(stderr, "is already a cluster member") {
			log.Infow("node already added to cluster, continuing", "joinAddress", joinAddress)
			// Return empty token - join will be skipped
			return "", nil
		}
		return "", fmt.Errorf("failed to add node to cluster: %w (stderr: %s)", err, stderr)
	}

	token := strings.TrimSpace(stdout)
	if token == "" {
		return "", fmt.Errorf("no join token returned from 'microceph cluster add'")
	}

	// Log that a token was generated for this node without echoing it twice.
	// The full token is already visible once in the subsequent join command log.
	log.Infow("join token generated", "primaryNode", primaryNode, "joiningNode", joiningNode, "joinAddress", joinAddress)

	return token, nil
}

// Join joins a node to an existing MicroCeph cluster using a join token.
func (p *MicroCephProvider) Join(ctx context.Context, sshPool *ssh.Pool, node, token string) error {
	log := logging.L().With("component", "microceph", "node", node)

	// First, check if this node already appears to be part of a MicroCeph
	// cluster. If `microceph status` succeeds, we treat the node as joined and
	// skip the join operation entirely.
	statusStdout, statusStderr, statusErr := sshPool.Run(ctx, node, "microceph status")
	if statusErr == nil {
		log.Infow("node already appears to be in MicroCeph cluster; skipping join",
			"status", strings.TrimSpace(statusStdout))
		return nil
	}

	// If we do not have a token and `microceph status` failed, there is no safe
	// way to join this node.
	if token == "" {
		return fmt.Errorf("no join token and node not in cluster: %w (stderr: %s)", statusErr, strings.TrimSpace(statusStderr))
	}

	// Verify MicroCeph daemon service is running on joining node
	statusCmd := `systemctl status snap.microceph.daemon.service --no-pager 2>/dev/null | grep -q "active (running)" && echo "running" || echo "not running"`
	svcStatus, _, _ := sshPool.Run(ctx, node, statusCmd)
	if !strings.Contains(svcStatus, "running") || strings.Contains(svcStatus, "not running") {
		log.Warnw("MicroCeph daemon service not running on joining node")
	}

	// Determine the preferred hostname/IP for this node using the same overlay
	// precedence as the rest of the system. We keep this primarily for
	// logging and for future cases where MicroCeph may support hostnames
	// directly for its control-plane address.
	overlayProvider := ""
	if p.cfg != nil {
		overlayProvider = p.cfg.GlobalSettings.OverlayProvider
	}
	preferredAddr := strings.TrimSpace(resolveNodeAddress(ctx, sshPool, node, overlayProvider))

	// For --microceph-ip specifically, MicroCeph currently expects an IP
	// address (ParseAddr fails on hostnames). Select an IP with precedence:
	//   1) Overlay/private IP from detectNetworkInfo (CGNAT 100.64/10 first,
	//      then RFC1918)
	//   2) If preferredAddr parses as an IP, use it
	//   3) Otherwise, omit --microceph-ip and let MicroCeph auto-detect
	joinIP := ""
	if netInfo := p.detectNetworkInfo(ctx, sshPool, node); netInfo != nil {
		joinIP = netInfo.IP
		log.Infow("selected MicroCeph IP for join", "ip", joinIP, "cidr", netInfo.CIDR)
	} else if preferredAddr != "" {
		if ip := net.ParseIP(preferredAddr); ip != nil {
			joinIP = ip.String()
			log.Infow("using preferred address as MicroCeph join IP", "ip", joinIP)
		} else {
			log.Warnw("preferred address for MicroCeph join is not an IP; will join without explicit --microceph-ip", "preferredAddr", preferredAddr)
		}
	}

	// Join the cluster using the token and, when available, an explicit
	// --microceph-ip argument. The hostname/FQDN (preferredAddr) is kept for
	// logging so we can switch to hostname-based control-plane addresses in
	// the future if/when MicroCeph supports it end-to-end.
	joinCmd := fmt.Sprintf("microceph cluster join %s", token)
	if joinIP != "" {
		joinCmd = fmt.Sprintf("microceph cluster join %s --microceph-ip '%s'", token, joinIP)
	}
	log.Infow("joining MicroCeph cluster", "node", node, "joinAddress", preferredAddr, "joinIP", joinIP, "command", joinCmd)
	if _, stderr, err := sshPool.Run(ctx, node, joinCmd); err != nil {
		// Check if this is an idempotent "already joined" style error. MicroCeph
		// may report conditions such as "Remote with address ... exists" when a
		// node has already joined previously. Treat these as success so reruns do
		// not fail the whole deployment.
		lower := strings.ToLower(stderr)
		if strings.Contains(lower, "already") || strings.Contains(lower, "member") ||
			strings.Contains(lower, "remote with address") || strings.Contains(lower, "already exists") {
			log.Infow("node already appears to be joined to cluster; ignoring join error",
				"stderr", strings.TrimSpace(stderr))
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
		// Best-effort preparation: ensure the disk is not mounted/in-use and is read-write
		// before asking MicroCeph/Ceph to claim it. This helps avoid bluestore
		// "Device or resource busy" / malformed label errors on re-runs.
		p.prepareDiskForMicroCeph(ctx, sshPool, node, disk)

		// Give udev a chance to settle after destructive operations so that
		// subsequent ceph-osd mkfs does not immediately hit a busy device.
		settleCmd := "command -v udevadm >/dev/null 2>&1 && udevadm settle || true"
		if _, stderr, err := sshPool.Run(ctx, node, settleCmd); err != nil {
			log.Warnw("udevadm settle failed before disk add (continuing)", "disk", disk, "error", err, "stderr", strings.TrimSpace(stderr))
		}

		// After unmounting/wiping a disk we've seen that immediately calling
		// `microceph disk add --wipe` can still race with the kernel/udev and
		// Ceph tearing down previous OSD state. Mirror the successful manual
		// procedure (unmount, then wait ~15s, then add) with an explicit
		// settle delay before the first add attempt.
		const diskSettleDelay = 15 * time.Second
		log.Infow("waiting for disk to settle before MicroCeph disk add",
			"disk", disk, "delaySeconds", int(diskSettleDelay/time.Second))
		time.Sleep(diskSettleDelay)

		// Add the disk with a bounded retry/backoff window. In practice we've
		// seen that unmounting and immediately adding can still race with the
		// kernel or Ceph releasing prior state; a short retry window makes this
		// robust without requiring manual intervention between commands.
		const maxAttempts = 3
		const retryDelay = 10 * time.Second
		var lastErr error
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			addCmd := fmt.Sprintf("microceph disk add %s --wipe", disk)
			log.Infow("adding disk", "disk", disk, "command", addCmd, "attempt", attempt, "maxAttempts", maxAttempts)
			if _, stderr, err := sshPool.Run(ctx, node, addCmd); err != nil {
				lastErr = err

				// Only retry on errors that are very likely to be transient after
				// a wipe/unmount sequence. This mirrors the errors observed when
				// reusing GlusterFS bricks too quickly.
				trimmed := strings.TrimSpace(stderr)
				transient := strings.Contains(trimmed, "Device or resource busy") ||
					strings.Contains(trimmed, "unable to decode label") ||
					strings.Contains(trimmed, "Malformed input") ||
					strings.Contains(trimmed, "End of buffer")

				if attempt < maxAttempts && transient {
					log.Warnw("disk add failed with transient error, will retry after delay",
						"disk", disk, "attempt", attempt, "maxAttempts", maxAttempts, "stderr", trimmed,
						"retryDelaySeconds", int(retryDelay/time.Second))
					time.Sleep(retryDelay)
					continue
				}

				log.Warnw("failed to add disk (not retrying)", "disk", disk, "error", err, "stderr", trimmed)
				break
			}

			// Success
			lastErr = nil
			addedDisks++
			break
		}

		if lastErr != nil {
			log.Warnw("failed to add disk after retries", "disk", disk, "error", lastErr)
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

	// Always show the current disk state after attempting to add storage so
	// operators can see which OSDs were actually configured and which disks
	// remain available.
	p.logDiskListJSON(ctx, sshPool, node, "post-add-storage")

	return nil
}

// prepareDiskForMicroCeph performs best-effort OS-level cleanup on a disk
// before running `microceph disk add` against it. The goal is to get the
// device back to a raw, read-write state by:
//   - refusing to touch the root filesystem disk
//   - disabling swap on the disk/its partitions
//   - unmounting any mountpoints on the disk/its partitions
//   - forcing the block device back to read-write
//   - zapping Ceph/LVM metadata when ceph-volume is available
//   - wiping filesystem signatures and partition tables (wipefs/sgdisk)
//   - zeroing the beginning of the device to clear any remaining labels
//
// This function is intentionally forgiving and destructive for the selected
// disk: failures in the preparation script are logged but do not abort the
// storage add flow. It assumes that inclusion/exclusion filtering has already
// restricted the disk set to dedicated OSD devices.
func (p *MicroCephProvider) prepareDiskForMicroCeph(ctx context.Context, sshPool *ssh.Pool, node, disk string) {
	log := logging.L().With("component", "microceph", "node", node)

	script := fmt.Sprintf(`DISK="%s"

		# Do not operate on the root filesystem disk even if misconfigured
		ROOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || echo "")
		case "${ROOT_DEV}" in
		  "${DISK}"|${DISK}[0-9]*)
			exit 0
			;;
		esac

		# Disable swap on this disk or its partitions (if any)
		if [ -f /proc/swaps ]; then
		  awk 'NR>1 {print $1}' /proc/swaps | while read SWAPDEV; do
		    case "${SWAPDEV}" in
		      "${DISK}"|${DISK}[0-9]*)
			swapoff "${SWAPDEV}" 2>/dev/null || true
			;;
		    esac
		  done
		fi

		# Unmount any mountpoints on this disk or its partitions (avoids "device busy").
		# This is fully dynamic and does not rely on hard-coded mount paths (e.g. GlusterFS bricks).
		lsblk -lnpo NAME,MOUNTPOINT "${DISK}" "${DISK}"?* 2>/dev/null \
		  | awk '$2 != "" {print $1 " " $2}' \
		  | while read DEV MNT; do
		    if [ "${MNT}" != "/" ]; then
		      # Try device and mountpoint, with lazy-unmount fallback.
		      umount -f "${DEV}" 2>/dev/null || \
		      umount -f "${MNT}" 2>/dev/null || \
		      umount -fl "${DEV}" 2>/dev/null || \
		      umount -fl "${MNT}" 2>/dev/null || true
		    fi
		  done

		# As an extra safety net, use findmnt (if available) to detach any remaining mounts
		# that still reference this block device.
		if command -v findmnt >/dev/null 2>&1; then
		  findmnt -Rn -S "${DISK}" 2>/dev/null | awk '{print $1}' | while read MNT; do
		    if [ "${MNT}" != "/" ]; then
		      umount -f "${MNT}" 2>/dev/null || umount -fl "${MNT}" 2>/dev/null || true
		    fi
		  done
		fi

		# Ensure the block device is marked read-write
		blockdev --setrw "${DISK}" 2>/dev/null || true

		# If ceph-volume is available, try to zap any existing Ceph/LVM metadata.
		if command -v ceph-volume >/dev/null 2>&1; then
		  ceph-volume lvm zap --destroy "${DISK}" 2>/dev/null || \
		  ceph-volume raw zap --destroy "${DISK}" 2>/dev/null || true
		fi

		# Wipe filesystem signatures and RAID superblocks
		if command -v wipefs >/dev/null 2>&1; then
		  wipefs -af "${DISK}" 2>/dev/null || true
		fi

		# Zap partition table / GPT if sgdisk is available
		if command -v sgdisk >/dev/null 2>&1; then
		  sgdisk --zap-all "${DISK}" 2>/dev/null || true
		fi

		# Finally, zero the beginning of the device to clear any remaining labels
		dd if=/dev/zero of="${DISK}" bs=1M count=10 conv=fsync,notrunc oflag=direct 2>/dev/null || true
		sync || true
		`, disk)

	cmd := fmt.Sprintf("sh -s << 'EOF'\n%s\nEOF", script)
	log.Infow("preparing disk before MicroCeph disk add", "disk", disk)
	if _, stderr, err := sshPool.Run(ctx, node, cmd); err != nil {
		log.Warnw("disk preparation encountered errors (continuing to microceph disk add)", "disk", disk, "error", err, "stderr", stderr)
	}
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

	// Derive explicit data and metadata pool names from the configured pool
	// name while still respecting the variable base name, e.g.:
	//   docker-swarm-0001-data
	//   docker-swarm-0001-metadata
	dataPool := fmt.Sprintf("%s-data", poolName)
	metadataPool := fmt.Sprintf("%s-metadata", poolName)

	// Create the data and metadata pools explicitly with 64 PGs as requested.
	// Treat "already exists" style errors as success so this stays idempotent.
	for _, pool := range []string{dataPool, metadataPool} {
		createPoolCmd := fmt.Sprintf("ceph osd pool create %s 64", pool)
		log.Infow("creating Ceph pool if needed", "pool", pool, "command", createPoolCmd)
		if _, stderr, err := sshPool.Run(ctx, primaryNode, createPoolCmd); err != nil {
			combined := strings.TrimSpace(stderr)
			if combined == "" {
				combined = err.Error()
			}
			if strings.Contains(combined, "already exists") || strings.Contains(combined, "EEXIST") {
				log.Infow("Ceph pool already exists", "pool", pool, "detail", combined)
				continue
			}
			return fmt.Errorf("failed to create Ceph pool %s: %w (stderr: %s)", pool, err, stderr)
		}
	}

	// Create the CephFS filesystem bound to the explicit data/metadata pools.
	// We use poolName as the filesystem name so mounts can continue to use
	// fs=<poolName> when invoking mount(8).
	fsName := poolName
	createFsCmd := fmt.Sprintf("ceph fs new %s %s %s", fsName, metadataPool, dataPool)
	log.Infow("creating CephFS filesystem with explicit pools", "command", createFsCmd,
		"fsName", fsName, "metadataPool", metadataPool, "dataPool", dataPool)
	if _, stderr, err := sshPool.Run(ctx, primaryNode, createFsCmd); err != nil {
		combined := strings.TrimSpace(stderr)
		if combined == "" {
			combined = err.Error()
		}
		if strings.Contains(combined, "already exists") {
			log.Infow("CephFS filesystem already exists", "fsName", fsName, "detail", combined)
		} else {
			return fmt.Errorf("failed to create CephFS filesystem %s: %w (stderr: %s)", fsName, err, stderr)
		}
	}

	// Wait for filesystem to be reported by `ceph fs ls -f json` before
	// proceeding to mount; this avoids the "No such process" race.
	if err := p.waitForCephFS(ctx, sshPool, primaryNode, fsName, 60*time.Second); err != nil {
		return fmt.Errorf("CephFS filesystem %s did not become ready: %w", fsName, err)
	}

	log.Infow("✓ CephFS filesystem created", "poolName", poolName)
	return nil
}

// waitForCephFS waits until the given CephFS filesystem is reported by
// `ceph fs ls -f json` or the timeout elapses.
func (p *MicroCephProvider) waitForCephFS(ctx context.Context, sshPool *ssh.Pool, primaryNode, fsName string, timeout time.Duration) error {
	log := logging.L().With("component", "microceph", "node", primaryNode, "fsName", fsName)
	deadline := time.Now().Add(timeout)

	type cephFSInfo struct {
		Name string `json:"name"`
	}

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for CephFS %s to become ready after %s", fsName, timeout)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for CephFS %s to become ready: %w", fsName, ctx.Err())
		default:
		}

		// Use `ceph fs ls -f json` rather than text parsing to detect the
		// presence of the filesystem.
		cmd := "ceph fs ls -f json"
		stdout, stderr, err := sshPool.Run(ctx, primaryNode, cmd)
		if err != nil {
			log.Warnw("failed to list CephFS filesystems while waiting for readiness (continuing)", "error", err, "stderr", strings.TrimSpace(stderr))
		} else {
			var fsList []cephFSInfo
			if err := json.Unmarshal([]byte(stdout), &fsList); err != nil {
				log.Warnw("failed to parse CephFS list JSON (continuing)", "error", err, "raw", strings.TrimSpace(stdout))
			} else {
				for _, fs := range fsList {
					if fs.Name == fsName {
						log.Infow("CephFS filesystem is now reported by Ceph", "fsName", fsName)
						return nil
					}
				}
			}
		}

		// Small backoff between checks to avoid spamming Ceph.
		time.Sleep(5 * time.Second)
	}
}

// CephFS mount timeout tuning. These values are used both for the direct
// kernel client mount and the persisted /etc/fstab entry so that CephFS
// does not block boot or `mount -a` indefinitely when the cluster or MONs
// are slow or unreachable.
//
// NOTE: `mon_timeout` is NOT a valid kernel CephFS mount option. The kernel
// driver only supports `mount_timeout` for bounding the mount operation.
// See: https://docs.ceph.com/en/latest/man/8/mount.ceph/#options
const (
	// cephMountTimeoutSeconds bounds the overall mount operation from the
	// Ceph client's perspective via the `mount_timeout` option.
	// This is the ONLY timeout option supported by the kernel CephFS driver.
	cephMountTimeoutSeconds = 30

	// systemdMountTimeout and systemdDeviceTimeout are passed via
	// x-systemd.* options in /etc/fstab so that systemd refuses to wait
	// indefinitely when CephFS cannot be mounted.
	systemdMountTimeout  = "45s"
	systemdDeviceTimeout = "45s"
)

// GetClusterCredentials retrieves the admin key and monitor addresses from the primary node.
// For CephFS mounts we now prefer IP-based MON addresses because hostname-based
// mounts were failing in some environments. The precedence for MON addresses is:
//  1. Overlay IP (Netbird / Tailscale)
//  2. Private IP (first non-loopback address)
//  3. SSH node string as a final fallback
//
// monNodes is the list of MON node SSH hostnames (for resolving overlay
// addresses/IPs).
func (p *MicroCephProvider) GetClusterCredentials(ctx context.Context, sshPool *ssh.Pool, primaryNode string, monNodes []string, overlayProvider string) (*ClusterCredentials, error) {
	log := logging.L().With("component", "microceph", "node", primaryNode)

	// Get admin key using JSON first so we can log and validate the value reliably.
	var adminKey string

	jsonCmd := "ceph auth get client.admin -f json 2>/dev/null"
	stdout, stderr, err := sshPool.Run(ctx, primaryNode, jsonCmd)
	if err != nil {
		log.Warnw("failed to get admin key via JSON, falling back to legacy text command",
			"error", err, "stderr", strings.TrimSpace(stderr))
	} else {
		output := strings.TrimSpace(stdout)
		if output != "" {
			// Try single-object format: { "key": "..." }.
			var single struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal([]byte(output), &single); err == nil && single.Key != "" {
				adminKey = single.Key
			} else {
				// Some Ceph versions may return a list of entities.
				var list []struct {
					Key string `json:"key"`
				}
				if err := json.Unmarshal([]byte(output), &list); err == nil && len(list) > 0 && list[0].Key != "" {
					adminKey = list[0].Key
				} else {
					log.Warnw("failed to parse admin key from JSON output, falling back to legacy command",
						"error", err, "raw", output)
				}
			}
		} else {
			log.Warnw("empty JSON output when retrieving admin key, falling back to legacy command")
		}
	}

	if adminKey == "" {
		// Fallback: legacy text command used previously.
		keyCmd := "ceph auth get-key client.admin 2>/dev/null"
		stdout, stderr, err = sshPool.Run(ctx, primaryNode, keyCmd)
		if err != nil {
			return nil, fmt.Errorf("failed to get admin key: %w (stderr: %s)", err, stderr)
		}
		adminKey = strings.TrimSpace(stdout)
	}

	if adminKey == "" {
		return nil, fmt.Errorf("empty admin key returned")
	}

	// Build monitor addresses using IP precedence (overlay IP > private IP).
	// Format: ip1:6789,ip2:6789,ip3:6789
	const monPort = 6789
	var monAddrList []string

	for _, monNode := range monNodes {
		// Resolve the best IP address for each MON node (overlay IP preferred).
		addr := resolveNodeIP(ctx, sshPool, monNode, overlayProvider)
		monAddrList = append(monAddrList, fmt.Sprintf("%s:%d", addr, monPort))
		log.Debugw("resolved MON address for CephFS", "node", monNode, "addr", addr, "port", monPort)
	}

	monAddrs := strings.Join(monAddrList, ",")
	if monAddrs == "" {
		return nil, fmt.Errorf("no MON addresses resolved")
	}

	// Log the full admin key so we can see exactly what was retrieved on the node.
	log.Infow("retrieved cluster credentials", "monAddrs", monAddrs, "adminKey", adminKey,
		"adminKeyLen", len(adminKey), "monCount", len(monAddrList))

	return &ClusterCredentials{
		AdminKey: adminKey,
		MonAddrs: monAddrs,
	}, nil
}

// MountWithCredentials mounts CephFS on a node using pre-fetched credentials.
// This is more efficient than Mount() when mounting multiple nodes and is
// intended to be idempotent so it can be safely re-run.
func (p *MicroCephProvider) MountWithCredentials(ctx context.Context, sshPool *ssh.Pool, node, poolName string, creds *ClusterCredentials) error {
	mountPath := p.GetMountPath()
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	if creds == nil {
		return fmt.Errorf("cluster credentials required")
	}

	// Always attempt to ensure /etc/fstab is updated and the system has applied
	// the mount configuration once this function completes. We log any errors
	// here instead of failing the whole operation to keep behaviour consistent
	// with earlier versions, while still surfacing issues for troubleshooting.
	defer func() {
		if err := p.ensureFstabAndReload(ctx, sshPool, node, mountPath, poolName, creds); err != nil {
			log.Warnw("ensureFstabAndReload reported an error", "error", err)
			return
		}

		// Optionally log df output for verification without being overly noisy.
		dfCmd := fmt.Sprintf("df -h %s || true", mountPath)
		if stdout, _, err := sshPool.Run(ctx, node, dfCmd); err == nil {
			log.Debugw("filesystem usage after CephFS mount", "mountPath", mountPath, "df", strings.TrimSpace(stdout))
		}
	}()

	// Create mount directory
	mkdirCmd := fmt.Sprintf("mkdir -p %s", mountPath)
	if _, _, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create mount directory: %w", err)
	}

	// If the mount is already present, skip the mount command but still ensure
	// /etc/fstab is correct so the mount persists across reboots.
	mountCheckCmd := fmt.Sprintf("mountpoint -q %s", mountPath)
	if _, _, err := sshPool.Run(ctx, node, mountCheckCmd); err == nil {
		log.Infow("CephFS already mounted on node, ensuring fstab entry exists", "mountPath", mountPath)
		if err := p.ensureFstabAndReload(ctx, sshPool, node, mountPath, poolName, creds); err != nil {
			return err
		}
		return nil
	}

	// Mount CephFS using provided credentials. Follow the user-specified
	// recipe closely and rely on Ceph's default filesystem selection (when a
	// single filesystem exists) instead of passing an explicit fs=<name>
	// option. To avoid hanging indefinitely when MONs are unreachable, we
	// pass `mount_timeout` (the ONLY timeout option supported by the kernel
	// CephFS driver). Note: `mon_timeout` is NOT a valid kernel mount option.
	mountCmd := fmt.Sprintf(
		"sudo mount -t ceph %s:/ %s -o name=admin,secret=%s,_netdev,mount_timeout=%d",
		creds.MonAddrs, mountPath, creds.AdminKey, cephMountTimeoutSeconds,
	)
	log.Infow("mounting CephFS", "monAddrs", creds.MonAddrs, "mountPath", mountPath, "mount_timeout", cephMountTimeoutSeconds)
	if _, stderr, err := sshPool.Run(ctx, node, mountCmd); err != nil {
		// Capture only ceph-related kernel messages to aid in diagnosing mount
		// failures without flooding the log with unrelated dmesg output.
		dmesgCmd := "dmesg | grep -i ceph | tail -n 10 || true"
		if dmesgOut, _, dmesgErr := sshPool.Run(ctx, node, dmesgCmd); dmesgErr == nil && strings.TrimSpace(dmesgOut) != "" {
			log.Warnw("ceph-related dmesg after mount failure", "dmesg", strings.TrimSpace(dmesgOut))
		}

		return fmt.Errorf("failed to mount CephFS: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✓ CephFS mounted", "mountPath", mountPath)
	return nil
}

// ensureFstabAndReload ensures that the correct CephFS entry is present in
// /etc/fstab, logs the exact line, runs `mount -a` and reloads systemd so the
// changes take effect. It is safe to call repeatedly; if the line already
// exists it will not be duplicated.
func (p *MicroCephProvider) ensureFstabAndReload(
	ctx context.Context,
	sshPool *ssh.Pool,
	node, mountPath, poolName string,
	creds *ClusterCredentials,
) error {
	log := logging.L().With("component", "microceph", "node", node, "mountPath", mountPath)

	// Build the fstab line using MON IPs and the admin key, following the
	// documented format and relying on Ceph's default filesystem selection
	// when only a single filesystem exists. To prevent `mount -a` and boot
	// from hanging indefinitely when Ceph is unavailable, we include:
	//   - mount_timeout: the ONLY timeout option supported by kernel CephFS driver
	//   - x-systemd.mount-timeout / x-systemd.device-timeout: systemd timeouts
	// NOTE: mon_timeout is NOT a valid kernel CephFS option and will cause mount failures.
	fstabEntry := fmt.Sprintf("%s:/ %s ceph name=admin,secret=%s,_netdev,mount_timeout=%d,x-systemd.mount-timeout=%s,x-systemd.device-timeout=%s 0 0",
		creds.MonAddrs, mountPath, creds.AdminKey, cephMountTimeoutSeconds, systemdMountTimeout, systemdDeviceTimeout)

	// Ensure idempotency by removing any existing fstab lines that reference
	// this mount path before appending the new, timeout-aware entry.
	cleanupCmd := fmt.Sprintf("sudo sed -i '\\|%s|d' /etc/fstab", mountPath)
	sshPool.Run(ctx, node, cleanupCmd)

	appendCmd := fmt.Sprintf("echo '%s' | sudo tee -a /etc/fstab >/dev/null", fstabEntry)
	log.Infow("adding/updating CephFS entry in fstab", "entry", fstabEntry)
	if _, stderr, err := sshPool.Run(ctx, node, appendCmd); err != nil {
		log.Warnw("failed to add fstab entry", "error", err, "stderr", strings.TrimSpace(stderr))
		return fmt.Errorf("failed to add fstab entry: %w (stderr: %s)", err, stderr)
	}

	// Apply the fstab changes. `mount -a` is safe to call repeatedly; if the
	// filesystem is already mounted it should either succeed or emit a benign
	// "already mounted" message. The fstab entry includes Ceph and systemd
	// timeouts so this call will no longer hang indefinitely on boot or when
	// the cluster is unavailable.
	if _, stderr, err := sshPool.Run(ctx, node, "sudo mount -a"); err != nil {
		combined := strings.TrimSpace(stderr)
		if !strings.Contains(combined, "already mounted") {
			log.Warnw("mount -a reported an error", "error", err, "stderr", combined)
			// Capture recent kernel messages to make debugging mount issues easier
			// without requiring a separate manual dmesg collection step.
			dmesgCmd := "dmesg | tail -n 50 || true"
			if dmesgOut, _, dmesgErr := sshPool.Run(ctx, node, dmesgCmd); dmesgErr == nil {
				log.Warnw("dmesg output after mount -a failure", "dmesgTail", strings.TrimSpace(dmesgOut))
			} else {
				log.Warnw("failed to collect dmesg after mount -a failure", "error", dmesgErr)
			}
			return fmt.Errorf("mount -a failed: %w (stderr: %s)", err, stderr)
		}
		log.Infow("mount -a reported filesystem already mounted", "stderr", combined)
	}

	// Reload systemd to pick up any updated mount units.
	if _, stderr, err := sshPool.Run(ctx, node, "sudo systemctl daemon-reload"); err != nil {
		log.Warnw("failed to reload systemd daemon", "error", err, "stderr", strings.TrimSpace(stderr))
		return fmt.Errorf("failed to reload systemd daemon: %w (stderr: %s)", err, stderr)
	}

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

// microcephDiskList models the JSON output from `microceph disk list --json`.
type microcephDiskList struct {
	ConfiguredDisks []microcephConfiguredDisk `json:"ConfiguredDisks"`
	AvailableDisks  []microcephAvailableDisk  `json:"AvailableDisks"`
}

type microcephConfiguredDisk struct {
	OSD      int    `json:"OSD"`
	Location string `json:"Location"`
	Path     string `json:"Path"`
}

type microcephAvailableDisk struct {
	Model string `json:"Model"`
	Size  string `json:"Size"`
	Type  string `json:"Type"`
	Path  string `json:"Path"`
}

// cephStatusJSON models the subset of `ceph status --format json` we care
// about for health and OSD counts. The structure matches Ceph's nested
// osdmap layout while remaining tolerant of minor version differences.
type cephStatusJSON struct {
	Health struct {
		Status        string `json:"status"`
		OverallStatus string `json:"overall_status"`
	} `json:"health"`
	OSDMap struct {
		// Some versions nest the actual map under "osdmap".
		Nested struct {
			NumOSDs   int `json:"num_osds"`
			NumUpOSDs int `json:"num_up_osds"`
			NumInOSDs int `json:"num_in_osds"`
		} `json:"osdmap"`

		// Other versions expose the counts directly at this level.
		NumOSDs   int `json:"num_osds"`
		NumUpOSDs int `json:"num_up_osds"`
		NumInOSDs int `json:"num_in_osds"`
	} `json:"osdmap"`
}

// cephOSDTreeJSON models the output of `ceph osd tree --format json`.
// Used to verify OSDs are up after disk enrollment.
type cephOSDTreeJSON struct {
	Nodes []cephOSDTreeNode `json:"nodes"`
}

type cephOSDTreeNode struct {
	ID       int     `json:"id"`       // OSD ID (e.g., 0, 1) or bucket ID (negative for hosts/roots)
	Name     string  `json:"name"`     // OSD name (e.g., "osd.0") or bucket name (hostname)
	Type     string  `json:"type"`     // "osd", "host", "root"
	Status   string  `json:"status"`   // "up" or "down" (only for OSDs)
	Children []int   `json:"children"` // Child node IDs (for hosts/roots)
	Exists   int     `json:"exists"`   // 1 if exists, 0 if removed
	Reweight float64 `json:"reweight"` // Reweight factor (0 = out, 1 = in)
}

// OSD verification timeout and polling constants
const (
	osdVerifyTimeout          = 60 * time.Second // Max time to wait for single OSD to come up
	osdVerifyPollInterval     = 5 * time.Second  // How often to check OSD status
	clusterHealthTimeout      = 5 * time.Minute  // Max time to wait for cluster to become healthy
	clusterHealthPollInterval = 10 * time.Second // How often to check cluster health
)

// logDiskListJSON fetches and logs the MicroCeph disk list in JSON form so
// we have a consistent, machine-readable view of configured and available
// disks at important points in the lifecycle (post-bootstrap, post-add, etc).
func (p *MicroCephProvider) logDiskListJSON(ctx context.Context, sshPool *ssh.Pool, node, phase string) {
	log := logging.L().With("component", "microceph", "node", node)

	cmd := "microceph disk list --json"
	stdout, stderr, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		log.Warnw("failed to get microceph disk list", "phase", phase, "error", err, "stderr", strings.TrimSpace(stderr))
		return
	}

	output := strings.TrimSpace(stdout)
	if output == "" {
		log.Warnw("microceph disk list returned empty JSON", "phase", phase)
		return
	}

	var dl microcephDiskList
	if err := json.Unmarshal([]byte(output), &dl); err != nil {
		log.Warnw("failed to parse microceph disk list JSON", "phase", phase, "error", err, "raw", output)
		return
	}

	log.Infow("MicroCeph disk list",
		"phase", phase,
		"configuredCount", len(dl.ConfiguredDisks),
		"availableCount", len(dl.AvailableDisks),
		"configured", dl.ConfiguredDisks,
		"available", dl.AvailableDisks,
	)
}

// VerifyOSDsUpForHost verifies that at least one OSD on the given host is in "up" state.
// This is called after adding a disk to confirm the OSD actually started.
// monNode is a MON node to query the cluster from; osdSSHNode is the SSH target; osdHostname is the node's hostname.
func (p *MicroCephProvider) VerifyOSDsUpForHost(ctx context.Context, sshPool *ssh.Pool, monNode, osdSSHNode, osdHostname string) error {
	log := logging.L().With("component", "microceph", "monNode", monNode, "osdSSHNode", osdSSHNode, "osdHostname", osdHostname)

	deadline := time.Now().Add(osdVerifyTimeout)
	var lastOSDCount, lastUpCount int

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for OSD on host %s to come up (found %d OSDs, %d up) after %s",
				osdHostname, lastOSDCount, lastUpCount, osdVerifyTimeout)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for OSD on host %s: %w", osdHostname, ctx.Err())
		default:
		}

		// Query OSD tree from MON node
		cmd := "ceph osd tree --format json"
		stdout, stderr, err := sshPool.Run(ctx, monNode, cmd)
		if err != nil {
			log.Warnw("failed to get OSD tree (retrying)", "error", err, "stderr", strings.TrimSpace(stderr))
			time.Sleep(osdVerifyPollInterval)
			continue
		}

		var tree cephOSDTreeJSON
		if err := json.Unmarshal([]byte(stdout), &tree); err != nil {
			log.Warnw("failed to parse OSD tree JSON (retrying)", "error", err)
			time.Sleep(osdVerifyPollInterval)
			continue
		}

		// Find the host node and its child OSDs
		hostFound, osdCount, upCount := p.countOSDsForHost(tree, osdHostname)
		lastOSDCount = osdCount
		lastUpCount = upCount

		if !hostFound {
			log.Debugw("host not found in OSD tree yet (retrying)", "osdHost", osdHostname)
			time.Sleep(osdVerifyPollInterval)
			continue
		}

		if osdCount == 0 {
			log.Debugw("no OSDs registered for host yet (retrying)", "osdHost", osdHostname)
			time.Sleep(osdVerifyPollInterval)
			continue
		}

		if upCount > 0 {
			log.Infow("✓ OSD verified up for host", "osdHost", osdHostname, "osdCount", osdCount, "upCount", upCount)
			return nil
		}

		log.Debugw("OSDs found but not up yet (retrying)", "osdHost", osdHostname, "osdCount", osdCount, "upCount", upCount)
		time.Sleep(osdVerifyPollInterval)
	}
}

// countOSDsForHost parses the OSD tree and returns (hostFound, totalOSDs, upOSDs) for the given hostname.
func (p *MicroCephProvider) countOSDsForHost(tree cephOSDTreeJSON, hostname string) (bool, int, int) {
	// Build a map of node ID -> node for quick lookup
	nodeMap := make(map[int]cephOSDTreeNode)
	for _, n := range tree.Nodes {
		nodeMap[n.ID] = n
	}

	// Find the host node (type=host, name matches hostname)
	var hostNode *cephOSDTreeNode
	for i, n := range tree.Nodes {
		if n.Type == "host" {
			// Match against full hostname, short hostname, or case-insensitive
			if strings.EqualFold(n.Name, hostname) {
				hostNode = &tree.Nodes[i]
				break
			}
			// Also try matching short hostname
			shortHost := hostname
			if idx := strings.Index(hostname, "."); idx > 0 {
				shortHost = hostname[:idx]
			}
			if strings.EqualFold(n.Name, shortHost) {
				hostNode = &tree.Nodes[i]
				break
			}
		}
	}

	if hostNode == nil {
		return false, 0, 0
	}

	// Count OSDs under this host
	var osdCount, upCount int
	for _, childID := range hostNode.Children {
		child, ok := nodeMap[childID]
		if !ok {
			continue
		}
		if child.Type != "osd" {
			continue
		}
		if child.Exists == 0 {
			continue // OSD was removed
		}
		osdCount++
		if child.Status == "up" {
			upCount++
		}
	}

	return true, osdCount, upCount
}

// WaitForClusterHealth waits for the cluster to reach a healthy state with at least
// the majority of expected OSDs up. This should be called after all disks are enrolled.
func (p *MicroCephProvider) WaitForClusterHealth(ctx context.Context, sshPool *ssh.Pool, monNode string, expectedOSDs int) error {
	log := logging.L().With("component", "microceph", "monNode", monNode, "expectedOSDs", expectedOSDs)

	// Calculate majority threshold (at least ceil(n/2) + 1 for odd, n/2 + 1 for even)
	majorityThreshold := (expectedOSDs / 2) + 1
	if majorityThreshold < 1 {
		majorityThreshold = 1
	}

	log.Infow("waiting for cluster health", "majorityThreshold", majorityThreshold, "timeout", clusterHealthTimeout)

	deadline := time.Now().Add(clusterHealthTimeout)
	var lastStatus string
	var lastOSDs, lastUp int

	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for cluster health after %s (last: %s, OSDs: %d/%d up)",
				clusterHealthTimeout, lastStatus, lastUp, lastOSDs)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for cluster health: %w", ctx.Err())
		default:
		}

		// Get cluster status
		cmd := "ceph status --format json"
		stdout, stderr, err := sshPool.Run(ctx, monNode, cmd)
		if err != nil {
			log.Warnw("failed to get cluster status (retrying)", "error", err, "stderr", strings.TrimSpace(stderr))
			time.Sleep(clusterHealthPollInterval)
			continue
		}

		var cs cephStatusJSON
		if err := json.Unmarshal([]byte(stdout), &cs); err != nil {
			log.Warnw("failed to parse cluster status JSON (retrying)", "error", err)
			time.Sleep(clusterHealthPollInterval)
			continue
		}

		// Extract status values
		healthStatus := cs.Health.Status
		if healthStatus == "" {
			healthStatus = cs.Health.OverallStatus
		}
		lastStatus = healthStatus

		// Get OSD counts (handle both nested and flat formats)
		numOSDs := cs.OSDMap.NumOSDs
		numUp := cs.OSDMap.NumUpOSDs
		if cs.OSDMap.Nested.NumOSDs > 0 {
			numOSDs = cs.OSDMap.Nested.NumOSDs
			numUp = cs.OSDMap.Nested.NumUpOSDs
		}
		lastOSDs = numOSDs
		lastUp = numUp

		log.Infow("cluster health check",
			"health", healthStatus,
			"osdsTotal", numOSDs,
			"osdsUp", numUp,
			"majorityThreshold", majorityThreshold)

		// Check if we meet the health criteria:
		// 1. At least majority of OSDs are up
		// 2. Health is OK or WARN (WARN is acceptable for fresh clusters)
		if numUp >= majorityThreshold && (healthStatus == "HEALTH_OK" || healthStatus == "HEALTH_WARN") {
			log.Infow("✓ cluster health verified",
				"health", healthStatus,
				"osdsUp", numUp,
				"osdsTotal", numOSDs,
				"majorityThreshold", majorityThreshold)
			return nil
		}

		// Not healthy yet
		if numUp < majorityThreshold {
			log.Infow("waiting for more OSDs to come up",
				"osdsUp", numUp,
				"needed", majorityThreshold,
				"polling", clusterHealthPollInterval)
		} else if healthStatus != "HEALTH_OK" && healthStatus != "HEALTH_WARN" {
			log.Infow("waiting for cluster health to improve",
				"currentHealth", healthStatus,
				"polling", clusterHealthPollInterval)
		}

		time.Sleep(clusterHealthPollInterval)
	}
}

// VerifyClusterHealthForMount verifies the cluster is healthy enough for CephFS mounts.
// This is a pre-mount gate to fail fast with a clear message if the cluster is degraded.
func (p *MicroCephProvider) VerifyClusterHealthForMount(ctx context.Context, sshPool *ssh.Pool, monNode string) error {
	log := logging.L().With("component", "microceph", "monNode", monNode)

	cmd := "ceph status --format json"
	stdout, stderr, err := sshPool.Run(ctx, monNode, cmd)
	if err != nil {
		return fmt.Errorf("failed to get cluster status: %w (stderr: %s)", err, strings.TrimSpace(stderr))
	}

	var cs cephStatusJSON
	if err := json.Unmarshal([]byte(stdout), &cs); err != nil {
		return fmt.Errorf("failed to parse cluster status: %w", err)
	}

	healthStatus := cs.Health.Status
	if healthStatus == "" {
		healthStatus = cs.Health.OverallStatus
	}

	numOSDs := cs.OSDMap.NumOSDs
	numUp := cs.OSDMap.NumUpOSDs
	if cs.OSDMap.Nested.NumOSDs > 0 {
		numOSDs = cs.OSDMap.Nested.NumOSDs
		numUp = cs.OSDMap.Nested.NumUpOSDs
	}

	// Calculate majority
	majorityThreshold := (numOSDs / 2) + 1
	if majorityThreshold < 1 {
		majorityThreshold = 1
	}

	// Check for critical failures
	if numUp == 0 {
		return fmt.Errorf("cannot mount CephFS: no OSDs are up (0/%d OSDs available)", numOSDs)
	}

	if numUp < majorityThreshold {
		return fmt.Errorf("cannot mount CephFS: cluster degraded (%d/%d OSDs up, need %d for majority)",
			numUp, numOSDs, majorityThreshold)
	}

	if healthStatus != "HEALTH_OK" && healthStatus != "HEALTH_WARN" {
		log.Warnw("cluster health is not optimal but proceeding with mount",
			"health", healthStatus,
			"osdsUp", numUp,
			"osdsTotal", numOSDs)
	}

	log.Infow("✓ cluster health verified for mount",
		"health", healthStatus,
		"osdsUp", numUp,
		"osdsTotal", numOSDs)

	return nil
}

// removeOSDsForNode removes any configured OSDs whose LOCATION matches this
// node. This is used during teardown so that OSDs are cleanly removed from
// the MicroCeph cluster before the snap and data directories are purged.
func (p *MicroCephProvider) removeOSDsForNode(ctx context.Context, sshPool *ssh.Pool, node string) {
	log := logging.L().With("component", "microceph", "node", node)

	// Determine the node's hostname as MicroCeph sees it in the LOCATION
	// column. We match against both the FQDN and the short hostname.
	hostnameCmd := "hostname -f 2>/dev/null || hostname"
	hostnameOut, _, err := sshPool.Run(ctx, node, hostnameCmd)
	if err != nil {
		log.Warnw("failed to determine hostname for OSD removal (will fall back to SSH node name)", "error", err)
	}
	fullHostname := strings.TrimSpace(hostnameOut)
	shortHostname := fullHostname
	if idx := strings.Index(fullHostname, "."); idx > 0 {
		shortHostname = fullHostname[:idx]
	}

	cmd := "microceph disk list --json"
	stdout, stderr, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		log.Warnw("failed to get microceph disk list before OSD removal", "error", err, "stderr", strings.TrimSpace(stderr))
		return
	}

	var dl microcephDiskList
	if err := json.Unmarshal([]byte(stdout), &dl); err != nil {
		log.Warnw("failed to parse microceph disk list JSON before OSD removal", "error", err)
		return
	}

	if len(dl.ConfiguredDisks) == 0 {
		log.Infow("no configured OSD disks found for removal")
		return
	}

	var osdsForNode []microcephConfiguredDisk
	for _, d := range dl.ConfiguredDisks {
		if d.Location == "" {
			continue
		}

		if fullHostname != "" && d.Location == fullHostname {
			osdsForNode = append(osdsForNode, d)
			continue
		}
		if shortHostname != "" && d.Location == shortHostname {
			osdsForNode = append(osdsForNode, d)
			continue
		}
		if d.Location == node {
			osdsForNode = append(osdsForNode, d)
		}
	}

	if len(osdsForNode) == 0 {
		log.Infow("no configured OSDs associated with this node", "fullHostname", fullHostname, "shortHostname", shortHostname)
		return
	}

	for _, d := range osdsForNode {
		// Use a 30-second timeout to avoid waiting 5 minutes when cluster is unresponsive.
		// If the cluster is healthy, disk remove should complete quickly.
		// If it times out, we'll fall back to just purging the snap.
		removeCmd := fmt.Sprintf("timeout 30 microceph disk remove %d --bypass-safety-checks 2>&1 || echo 'TIMEOUT_OR_ERROR'", d.OSD)
		log.Infow("removing MicroCeph OSD disk", "osd", d.OSD, "location", d.Location, "path", d.Path, "timeout", "30s")
		stdout, stderr, err := sshPool.Run(ctx, node, removeCmd)
		if err != nil || strings.Contains(stdout, "TIMEOUT_OR_ERROR") || strings.Contains(stdout, "timed out") {
			// If the OSD removal times out or fails (cluster unhealthy), skip graceful removal.
			// The snap purge will clean up everything anyway.
			log.Warnw("graceful OSD removal failed or timed out (will purge snap instead)", "osd", d.OSD, "error", err, "stdout", strings.TrimSpace(stdout), "stderr", strings.TrimSpace(stderr))
		} else {
			log.Infow("✓ OSD disk removed gracefully", "osd", d.OSD)
		}
	}
}

// Teardown removes MicroCeph from a node.
// The teardown is designed to work even when the cluster is unhealthy:
// 1. Stop local MicroCeph services first (no cluster communication needed)
// 2. Attempt graceful OSD removal with a short timeout (30s)
// 3. If graceful removal fails, fall back to snap purge which cleans everything
func (p *MicroCephProvider) Teardown(ctx context.Context, sshPool *ssh.Pool, node string) error {
	log := logging.L().With("component", "microceph", "node", node)

	// Check if MicroCeph is installed
	checkCmd := "snap list microceph 2>/dev/null"
	stdout, _, _ := sshPool.Run(ctx, node, checkCmd)
	if !strings.Contains(stdout, "microceph") {
		log.Infow("MicroCeph not installed, skipping removal")
		return nil
	}

	// Step 1: Stop MicroCeph services first. This doesn't require cluster
	// communication and ensures no local processes are running before cleanup.
	stopCmd := "snap stop microceph 2>/dev/null || true"
	log.Infow("stopping MicroCeph services")
	sshPool.Run(ctx, node, stopCmd)

	// Step 2: Attempt graceful OSD removal with a short timeout.
	// If the cluster is healthy, this updates the CRUSH map properly.
	// If the cluster is unhealthy, the timeout prevents long waits.
	p.removeOSDsForNode(ctx, sshPool, node)

	// Step 3: Remove microceph snap with purge (cleans up everything)
	removeCmd := "snap remove microceph --purge 2>/dev/null || true"
	log.Infow("removing MicroCeph snap")
	if _, _, err := sshPool.Run(ctx, node, removeCmd); err != nil {
		log.Warnw("failed to remove microceph snap", "error", err)
	}

	// Step 4: Clean up any remaining data directories
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

	// Always log the human-readable MicroCeph status for operators.
	mcStatusCmd := "microceph status"
	mcStdout, mcStderr, err := sshPool.Run(ctx, node, mcStatusCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get microceph status: %w (stderr: %s)", err, strings.TrimSpace(mcStderr))
	}
	log.Infow("MicroCeph cluster status", "output", strings.TrimSpace(mcStdout))

	// Prefer structured JSON from Ceph wherever possible so we do not rely on
	// brittle text parsing. We fall back to the old text-based approach only if
	// JSON is unavailable or cannot be parsed.
	var (
		healthy  bool
		osdCount int
	)

	cephStatusJSONCmd := "ceph status --format json"
	cephJSONOut, cephJSONErr, err := sshPool.Run(ctx, node, cephStatusJSONCmd)
	if err == nil && strings.TrimSpace(cephJSONOut) != "" {
		var cs cephStatusJSON
		if jsonErr := json.Unmarshal([]byte(cephJSONOut), &cs); jsonErr == nil {
			// Determine health from JSON
			healthStatus := strings.TrimSpace(cs.Health.Status)
			if healthStatus == "" {
				healthStatus = strings.TrimSpace(cs.Health.OverallStatus)
			}

			// HEALTH_OK is obviously fine; we also continue to treat HEALTH_WARN as
			// acceptable for freshly created clusters, matching previous behaviour.
			switch healthStatus {
			case "HEALTH_OK":
				healthy = true
			case "HEALTH_WARN":
				healthy = true
				log.Infow("cluster health is HEALTH_WARN (acceptable for new clusters)")
			default:
				healthy = false
			}

			// Prefer nested OSD map counts when available, fall back to the top
			// level otherwise.
			if cs.OSDMap.Nested.NumOSDs > 0 {
				osdCount = cs.OSDMap.Nested.NumOSDs
			} else {
				osdCount = cs.OSDMap.NumOSDs
			}

			log.Infow("Ceph cluster status (json)",
				"health", healthStatus,
				"osdCount", osdCount,
				"osdsUp", cs.OSDMap.Nested.NumUpOSDs+cs.OSDMap.NumUpOSDs,
				"osdsIn", cs.OSDMap.Nested.NumInOSDs+cs.OSDMap.NumInOSDs,
			)
		} else {
			log.Warnw("failed to parse ceph status JSON; falling back to text status",
				"error", jsonErr,
			)
		}
	} else {
		if err != nil {
			log.Warnw("failed to get ceph status JSON; falling back to text status",
				"error", err, "stderr", strings.TrimSpace(cephJSONErr))
		} else {
			log.Warnw("empty ceph status JSON output; falling back to text status")
		}
	}

	// If JSON-based parsing did not yield anything (older Ceph or unexpected
	// output), fall back to the existing text-based approach so we still return
	// a useful status.
	if !healthy && osdCount == 0 {
		cephStatusCmd := "ceph status"
		cephStdout, cephStderr, err := sshPool.Run(ctx, node, cephStatusCmd)
		if err != nil {
			log.Warnw("failed to get ceph status (text)", "error", err, "stderr", strings.TrimSpace(cephStderr))
		} else {
			log.Infow("Ceph cluster status (text)", "output", strings.TrimSpace(cephStdout))

			// Determine health from ceph status output
			if strings.Contains(cephStdout, "HEALTH_OK") {
				healthy = true
			} else if strings.Contains(cephStdout, "HEALTH_WARN") {
				// HEALTH_WARN is acceptable for newly created clusters
				healthy = true
				log.Infow("cluster health is HEALTH_WARN (acceptable for new clusters)")
			}

			// Count OSDs from status: parse "osd: N osds: N up, N in" pattern
			if strings.Contains(cephStdout, "osd:") {
				lines := strings.Split(cephStdout, "\n")
				for _, line := range lines {
					if strings.Contains(line, "osd:") && strings.Contains(line, "osds:") {
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

// getDockerSubnetsStandalone retrieves Docker network subnets (standalone version for use outside MicroCephProvider).
func getDockerSubnetsStandalone(ctx context.Context, sshPool *ssh.Pool, node string) []*net.IPNet {
	cmd := `docker network ls -q 2>/dev/null | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -v '^$' || true`
	stdout, _, err := sshPool.Run(ctx, node, cmd)
	if err != nil {
		return nil
	}

	var subnets []*net.IPNet
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		cidr := strings.TrimSpace(line)
		if cidr == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		subnets = append(subnets, ipnet)
	}
	return subnets
}

// resolveNodeIP resolves the best IP address for a node with precedence:
// 1. Overlay IP (Netbird / Tailscale)
// 2. Private IP (first non-loopback, non-Docker address)
// 3. SSH node string as a final fallback
// Docker network subnets are excluded since they are not routable across hosts.
func resolveNodeIP(ctx context.Context, sshPool *ssh.Pool, node, overlayProvider string) string {
	log := logging.L().With("component", "resolve-ip", "node", node)
	overlayProvider = strings.ToLower(strings.TrimSpace(overlayProvider))

	// 1. Overlay IP from Netbird
	if overlayProvider == "netbird" {
		stdout, _, err := sshPool.Run(ctx, node, "netbird status --json")
		if err == nil {
			var status struct {
				NetbirdIP string `json:"netbirdIp"`
			}
			if json.Unmarshal([]byte(stdout), &status) == nil {
				if status.NetbirdIP != "" {
					ip := strings.Split(status.NetbirdIP, "/")[0]
					log.Debugw("using overlay IP (netbird)", "ip", ip)
					return ip
				}
			}
		}
	} else if overlayProvider == "tailscale" {
		// 1. Overlay IP from Tailscale
		stdout, _, err := sshPool.Run(ctx, node, "tailscale status --json")
		if err == nil {
			var status struct {
				Self struct {
					TailscaleIPs []string `json:"TailscaleIPs"`
				} `json:"Self"`
			}
			if json.Unmarshal([]byte(stdout), &status) == nil {
				if len(status.Self.TailscaleIPs) > 0 {
					ip := status.Self.TailscaleIPs[0]
					log.Debugw("using overlay IP (tailscale)", "ip", ip)
					return ip
				}
			}
		}
	}

	// Get Docker subnets to exclude
	dockerSubnets := getDockerSubnetsStandalone(ctx, sshPool, node)

	// 2. Private IP (first non-loopback, non-Docker address)
	// Use hostname -I on Linux which returns a space-separated list of addresses.
	stdout, _, err := sshPool.Run(ctx, node, "hostname -I 2>/dev/null || hostname -i 2>/dev/null || echo ''")
	if err == nil {
		fields := strings.Fields(strings.TrimSpace(stdout))
		for _, f := range fields {
			if f == "127.0.0.1" || f == "::1" {
				continue
			}
			ip := net.ParseIP(f)
			if ip == nil {
				continue
			}
			// Skip IPs in Docker subnets
			if isIPInDockerSubnet(ip, dockerSubnets) {
				log.Debugw("skipping IP in Docker subnet", "ip", f)
				continue
			}
			log.Debugw("using private IP", "ip", f)
			return f
		}
	}

	// 3. Fallback to SSH node string, which is typically a hostname or IP.
	log.Debugw("using SSH node as fallback for IP", "node", node)
	return node
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
