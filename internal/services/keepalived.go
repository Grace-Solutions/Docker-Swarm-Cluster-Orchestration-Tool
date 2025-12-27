package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"clusterctl/internal/config"
	"clusterctl/internal/defaults"
	"clusterctl/internal/ipdetect"
	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// KeepalivedNodeConfig holds the resolved configuration for a single node.
type KeepalivedNodeConfig struct {
	Hostname  string // SSH hostname for this node
	Priority  int    // VRRP priority (1-254)
	State     string // "MASTER" or "BACKUP"
	Interface string // Network interface for VRRP
	VIP       string // Virtual IP address with CIDR
}

// KeepalivedDeployment holds the complete Keepalived deployment configuration.
type KeepalivedDeployment struct {
	Enabled   bool                    // Whether Keepalived is enabled
	VIP       string                  // Virtual IP address (without CIDR)
	VIPCIDR   string                  // Virtual IP address with CIDR (e.g., 192.168.1.250/24)
	Interface string                  // Network interface for VRRP
	RouterID  int                     // VRRP router ID
	AuthPass  string                  // VRRP authentication password
	Nodes     []*KeepalivedNodeConfig // Per-node configurations
}

// PrepareKeepalivedDeployment prepares the Keepalived configuration for all nodes.
// This must be called after Swarm setup and before service deployment.
// Only nodes with an RFC1918 IP in the same subnet as the first node are included,
// since VRRP is Layer 2 and requires all nodes to be on the same broadcast domain.
func PrepareKeepalivedDeployment(ctx context.Context, sshPool *ssh.Pool, cfg *config.Config) (*KeepalivedDeployment, error) {
	log := logging.L().With("component", "keepalived")

	if !cfg.IsKeepalivedEnabled() {
		log.Infow("Keepalived is not enabled globally, skipping")
		return &KeepalivedDeployment{Enabled: false}, nil
	}

	keepalivedNodes := cfg.GetKeepalivedNodes()
	if len(keepalivedNodes) == 0 {
		log.Infow("no nodes have Keepalived enabled, skipping")
		return &KeepalivedDeployment{Enabled: false}, nil
	}

	log.Infow("preparing Keepalived deployment", "candidateNodeCount", len(keepalivedNodes))

	globalKA := cfg.GetKeepalived()

	// Use first enabled node to detect interface and establish reference subnet
	firstNode := keepalivedNodes[0].SSHFQDNorIP

	// Detect or use configured interface
	iface := globalKA.Interface
	if config.IsAutoValue(iface) || iface == "" {
		detected, err := detectRFC1918Interface(ctx, sshPool, firstNode)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect RFC1918 interface: %w", err)
		}
		iface = detected
		log.Infow("auto-detected RFC1918 interface", "interface", iface, "node", firstNode)
	}

	// Get interface details (IP and netmask) from first node - this is the reference subnet
	ifaceIP, ifaceCIDR, err := getInterfaceDetails(ctx, sshPool, firstNode, iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface details: %w", err)
	}
	log.Infow("reference subnet from first node", "interface", iface, "ip", ifaceIP, "cidr", ifaceCIDR)

	// Parse the reference network for subnet filtering
	referenceNetwork, err := parseNetwork(ifaceIP, ifaceCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse reference network: %w", err)
	}

	// Filter nodes to only include those in the same subnet (VRRP is Layer 2)
	var eligibleNodes []config.NodeConfig
	for _, node := range keepalivedNodes {
		nodeIP, err := getNodeRFC1918IP(ctx, sshPool, node.SSHFQDNorIP, iface)
		if err != nil {
			log.Warnw("failed to get RFC1918 IP for node, excluding from VRRP",
				"node", node.SSHFQDNorIP, "error", err)
			continue
		}

		parsedIP := net.ParseIP(nodeIP)
		if parsedIP == nil {
			log.Warnw("invalid IP for node, excluding from VRRP",
				"node", node.SSHFQDNorIP, "ip", nodeIP)
			continue
		}

		if !referenceNetwork.Contains(parsedIP) {
			log.Warnw("node not in same subnet as reference, excluding from VRRP (Layer 2 requirement)",
				"node", node.SSHFQDNorIP, "nodeIP", nodeIP, "referenceNetwork", referenceNetwork.String())
			continue
		}

		log.Infow("node eligible for VRRP", "node", node.SSHFQDNorIP, "ip", nodeIP)
		eligibleNodes = append(eligibleNodes, node)
	}

	if len(eligibleNodes) == 0 {
		log.Warnw("no nodes in same subnet eligible for Keepalived, skipping")
		return &KeepalivedDeployment{Enabled: false}, nil
	}

	log.Infow("filtered nodes for same-subnet VRRP",
		"eligible", len(eligibleNodes), "excluded", len(keepalivedNodes)-len(eligibleNodes))

	// Get VIP scan timeout
	vipScanTimeout := globalKA.VIPScanTimeout
	if vipScanTimeout <= 0 {
		vipScanTimeout = defaults.KeepalivedVIPScanTimeout
	}

	// Detect or use configured VIP
	vip := globalKA.VIP
	if config.IsAutoValue(vip) || vip == "" {
		detected, err := findUnusedVIP(ctx, sshPool, firstNode, ifaceIP, ifaceCIDR, vipScanTimeout)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-detect unused VIP: %w", err)
		}
		vip = detected
		log.Infow("auto-detected unused VIP", "vip", vip)
	}

	// Generate or use configured auth password
	authPass := globalKA.AuthPass
	if config.IsAutoValue(authPass) || authPass == "" {
		authPass = generateAuthPassword()
		log.Infow("generated Keepalived auth password", "password", authPass)
	}

	// Resolve router ID - if auto, use last octet of VIP
	routerID := 0
	if config.IsAutoValue(globalKA.RouterID) || globalKA.RouterID == "" {
		// Parse VIP to get last octet
		vipIP := net.ParseIP(vip)
		if vipIP != nil {
			vip4 := vipIP.To4()
			if vip4 != nil {
				routerID = int(vip4[3])
			}
		}
		if routerID == 0 {
			routerID = 51 // Fallback default
		}
		log.Infow("auto-generated router ID from VIP last octet", "routerId", routerID)
	} else {
		// Try to parse as integer
		if id, err := strconv.Atoi(globalKA.RouterID); err == nil {
			routerID = id
		} else {
			routerID = 51 // Fallback default
		}
	}

	// Build per-node configurations (using filtered eligible nodes with reindexed priorities)
	deployment := &KeepalivedDeployment{
		Enabled:   true,
		VIP:       vip,
		VIPCIDR:   fmt.Sprintf("%s/%s", vip, ifaceCIDR),
		Interface: iface,
		RouterID:  routerID,
		AuthPass:  authPass,
		Nodes:     make([]*KeepalivedNodeConfig, 0, len(eligibleNodes)),
	}

	for i, node := range eligibleNodes {
		nodeConfig := resolveNodeConfig(node, i, iface, deployment.VIPCIDR)
		deployment.Nodes = append(deployment.Nodes, nodeConfig)
		log.Infow("resolved node configuration",
			"hostname", nodeConfig.Hostname,
			"priority", nodeConfig.Priority,
			"state", nodeConfig.State,
		)
	}

	// Log complete configuration
	log.Infow("Keepalived deployment prepared",
		"vip", deployment.VIPCIDR,
		"interface", deployment.Interface,
		"routerId", deployment.RouterID,
		"authPass", deployment.AuthPass,
		"nodeCount", len(deployment.Nodes),
	)

	return deployment, nil
}

// parseNetwork parses an IP and CIDR prefix into a net.IPNet for subnet checking.
func parseNetwork(ip string, cidrPrefix string) (*net.IPNet, error) {
	cidr := fmt.Sprintf("%s/%s", ip, cidrPrefix)
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return network, nil
}

// getNodeRFC1918IP gets the RFC1918 IP address for a node on the specified interface.
func getNodeRFC1918IP(ctx context.Context, sshPool *ssh.Pool, host, iface string) (string, error) {
	ip, _, err := getInterfaceDetails(ctx, sshPool, host, iface)
	if err != nil {
		return "", err
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP: %s", ip)
	}
	if !ipdetect.IsRFC1918(parsedIP) {
		return "", fmt.Errorf("IP %s is not RFC1918", ip)
	}
	return ip, nil
}

// resolveNodeConfig resolves the per-node configuration with auto-values.
func resolveNodeConfig(node config.NodeConfig, nodeIndex int, iface, vipCIDR string) *KeepalivedNodeConfig {
	// Resolve priority
	priority := defaults.KeepalivedBasePriority - nodeIndex
	if !config.IsAutoValue(node.Keepalived.Priority) && node.Keepalived.Priority != "" {
		if p, err := strconv.Atoi(node.Keepalived.Priority); err == nil {
			priority = p
		}
	}

	// Resolve state
	state := "BACKUP"
	if nodeIndex == 0 {
		state = "MASTER"
	}
	if !config.IsAutoValue(node.Keepalived.State) && node.Keepalived.State != "" {
		state = strings.ToUpper(node.Keepalived.State)
	}

	return &KeepalivedNodeConfig{
		Hostname:  node.SSHFQDNorIP,
		Priority:  priority,
		State:     state,
		Interface: iface,
		VIP:       vipCIDR,
	}
}

// detectRFC1918Interface finds the first network interface with an RFC1918 IP address.
// Uses ipdetect.IsRFC1918 for consistent RFC1918 detection across the codebase.
func detectRFC1918Interface(ctx context.Context, sshPool *ssh.Pool, host string) (string, error) {
	// Get all interfaces with their IPs
	cmd := `ip -o -4 addr show | awk '{print $2, $4}' | grep -v '^lo '`
	stdout, stderr, err := sshPool.Run(ctx, host, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %w (stderr: %s)", err, stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		iface := parts[0]
		ipCIDR := parts[1]

		// Skip Docker and overlay interfaces
		if strings.HasPrefix(iface, "docker") || strings.HasPrefix(iface, "br-") ||
			strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "wg") {
			continue
		}

		// Check if IP is RFC1918 using centralized ipdetect package
		ip, _, err := net.ParseCIDR(ipCIDR)
		if err != nil {
			continue
		}

		if ipdetect.IsRFC1918(ip) {
			return iface, nil
		}
	}

	return "", fmt.Errorf("no RFC1918 interface found")
}

// getInterfaceDetails returns the IP address and CIDR prefix for an interface.
func getInterfaceDetails(ctx context.Context, sshPool *ssh.Pool, host, iface string) (string, string, error) {
	cmd := fmt.Sprintf(`ip -o -4 addr show %s | awk '{print $4}'`, iface)
	stdout, stderr, err := sshPool.Run(ctx, host, cmd)
	if err != nil {
		return "", "", fmt.Errorf("failed to get interface details: %w (stderr: %s)", err, stderr)
	}

	ipCIDR := strings.TrimSpace(stdout)
	if ipCIDR == "" {
		return "", "", fmt.Errorf("no IP address found on interface %s", iface)
	}

	ip, ipNet, err := net.ParseCIDR(ipCIDR)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse IP/CIDR %s: %w", ipCIDR, err)
	}

	ones, _ := ipNet.Mask.Size()
	return ip.String(), fmt.Sprintf("%d", ones), nil
}

// findUnusedVIP finds an unused IP address in the subnet using ARP scanning.
// It dynamically calculates the full usable address range and scans until timeout.
func findUnusedVIP(ctx context.Context, sshPool *ssh.Pool, host, ifaceIP, cidrPrefix string, timeoutSeconds int) (string, error) {
	log := logging.L().With("component", "keepalived")

	// Parse the interface IP to get the network
	ip := net.ParseIP(ifaceIP)
	if ip == nil {
		return "", fmt.Errorf("invalid interface IP: %s", ifaceIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 address: %s", ifaceIP)
	}

	prefix, _ := strconv.Atoi(cidrPrefix)
	mask := net.CIDRMask(prefix, 32)

	// Calculate network and broadcast addresses
	networkAddr := make(net.IP, 4)
	broadcastAddr := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		networkAddr[i] = ip4[i] & mask[i]
		broadcastAddr[i] = ip4[i] | ^mask[i]
	}

	// Calculate total usable hosts (excluding network and broadcast)
	hostBits := 32 - prefix
	totalHosts := (1 << hostBits) - 2 // Subtract network and broadcast
	if totalHosts <= 0 {
		return "", fmt.Errorf("subnet /%d has no usable hosts", prefix)
	}

	log.Infow("scanning for unused VIP",
		"network", networkAddr.String(),
		"broadcast", broadcastAddr.String(),
		"usableHosts", totalHosts,
		"timeout", timeoutSeconds,
	)

	// Ensure arping is installed (iputils-arping on Debian/Ubuntu, arping on RHEL/CentOS)
	installCmd := `command -v arping >/dev/null 2>&1 || {
		if command -v apt-get >/dev/null 2>&1; then
			apt-get update -qq && apt-get install -y -qq iputils-arping 2>/dev/null
		elif command -v dnf >/dev/null 2>&1; then
			dnf install -y -q arping 2>/dev/null
		elif command -v yum >/dev/null 2>&1; then
			yum install -y -q arping 2>/dev/null
		fi
	}`
	if stdout, stderr, err := sshPool.Run(ctx, host, installCmd); err != nil {
		log.Warnw("arping install may have failed", "stdout", stdout, "stderr", stderr, "error", err)
	}

	// Verify arping is available
	verifyCmd := "command -v arping && arping -V 2>&1 | head -1"
	if stdout, _, err := sshPool.Run(ctx, host, verifyCmd); err != nil {
		return "", fmt.Errorf("arping not available after install attempt: %w", err)
	} else {
		log.Infow("arping verified", "output", strings.TrimSpace(stdout))
	}

	// Detect the network interface for the reference IP
	detectIfaceCmd := fmt.Sprintf("ip route get %s 2>/dev/null | grep -oP 'dev \\K\\S+' | head -1", ifaceIP)
	ifaceOut, _, err := sshPool.Run(ctx, host, detectIfaceCmd)
	if err != nil || strings.TrimSpace(ifaceOut) == "" {
		return "", fmt.Errorf("failed to detect interface for IP %s", ifaceIP)
	}
	detectedIface := strings.TrimSpace(ifaceOut)
	log.Infow("using interface for ARP scan", "interface", detectedIface)

	// Start from broadcast-1 and work down (prefer high IPs for VIPs)
	startTime := time.Now()
	timeout := time.Duration(timeoutSeconds) * time.Second

	// Convert network address to uint32 for iteration
	netInt := ipToUint32(networkAddr)
	broadInt := ipToUint32(broadcastAddr)

	scannedCount := 0

	// Iterate from broadcast-1 down to network+1
	for hostInt := broadInt - 1; hostInt > netInt; hostInt-- {
		// Check timeout
		if time.Since(startTime) > timeout {
			return "", fmt.Errorf("VIP scan timeout (%ds) exceeded after testing %d IPs", timeoutSeconds, scannedCount)
		}

		candidate := uint32ToIP(hostInt)

		// Skip if it matches the interface IP
		if candidate.String() == ifaceIP {
			continue
		}

		scannedCount++

		// arping -D (DAD mode) with iputils-arping:
		// Exit codes: 0 = no reply (IP available), 1 = reply received (IP in use), 2 = error
		// -c 1 = send 1 probe, -w 1 = wait 1 second total
		arpCmd := fmt.Sprintf("arping -D -c 1 -w 1 -I %s %s", detectedIface, candidate.String())
		stdout, _, err := sshPool.Run(ctx, host, arpCmd)

		// Log every IP being tested at INFO level for visibility
		log.Infow("testing IP",
			"ip", candidate.String(),
			"scanned", scannedCount,
			"exitError", err != nil,
			"output", strings.TrimSpace(stdout),
		)

		if err == nil {
			// Exit code 0 = no ARP reply = IP is available
			log.Infow("found unused VIP", "ip", candidate.String(), "scannedCount", scannedCount)
			return candidate.String(), nil
		}
		// err != nil means exit code 1 (in use) or 2 (error) - continue scanning
	}

	return "", fmt.Errorf("no unused IP found in subnet %s/%s after scanning %d hosts", networkAddr.String(), cidrPrefix, scannedCount)
}

// ipToUint32 converts an IPv4 address to uint32.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

// uint32ToIP converts a uint32 to an IPv4 address.
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// generateAuthPassword generates a random password for VRRP authentication.
func generateAuthPassword() string {
	bytes := make([]byte, defaults.KeepalivedAuthPassLength/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// InstallAndConfigureKeepalived installs and configures Keepalived on all enabled nodes.
func InstallAndConfigureKeepalived(ctx context.Context, sshPool *ssh.Pool, deployment *KeepalivedDeployment) error {
	if !deployment.Enabled || len(deployment.Nodes) == 0 {
		return nil
	}

	log := logging.L().With("component", "keepalived")

	for _, nodeConfig := range deployment.Nodes {
		log.Infow("installing and configuring Keepalived",
			"node", nodeConfig.Hostname,
			"state", nodeConfig.State,
			"priority", nodeConfig.Priority,
		)

		if err := installKeepalivedOnNode(ctx, sshPool, nodeConfig, deployment); err != nil {
			return fmt.Errorf("failed to configure Keepalived on %s: %w", nodeConfig.Hostname, err)
		}

		log.Infow("✅ Keepalived configured", "node", nodeConfig.Hostname)
	}

	return nil
}

// installKeepalivedOnNode installs and configures Keepalived on a single node.
func installKeepalivedOnNode(ctx context.Context, sshPool *ssh.Pool, nodeConfig *KeepalivedNodeConfig, deployment *KeepalivedDeployment) error {
	host := nodeConfig.Hostname

	// Install keepalived idempotently
	installCmd := `
if ! command -v keepalived &> /dev/null; then
    echo "Installing keepalived..."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y keepalived
    elif command -v yum &> /dev/null; then
        yum install -y keepalived
    elif command -v dnf &> /dev/null; then
        dnf install -y keepalived
    else
        echo "ERROR: No supported package manager found"
        exit 1
    fi
else
    echo "keepalived already installed"
fi
`
	stdout, stderr, err := sshPool.Run(ctx, host, installCmd)
	if err != nil {
		return fmt.Errorf("failed to install keepalived: %w (stderr: %s)", err, stderr)
	}
	logging.L().Infow("keepalived install output", "stdout", strings.TrimSpace(stdout))

	// Generate keepalived.conf
	keepalivedConf := generateKeepalivedConf(nodeConfig, deployment)

	// Write configuration
	writeCmd := fmt.Sprintf(`cat > /etc/keepalived/keepalived.conf << 'KEEPALIVED_EOF'
%s
KEEPALIVED_EOF`, keepalivedConf)

	if _, stderr, err := sshPool.Run(ctx, host, writeCmd); err != nil {
		return fmt.Errorf("failed to write keepalived.conf: %w (stderr: %s)", err, stderr)
	}

	// Write health check script
	if err := WriteHealthCheckScript(ctx, sshPool, host); err != nil {
		return fmt.Errorf("failed to write health check script: %w", err)
	}

	// Enable and restart keepalived
	restartCmd := `systemctl enable keepalived && systemctl restart keepalived`
	if _, stderr, err := sshPool.Run(ctx, host, restartCmd); err != nil {
		return fmt.Errorf("failed to restart keepalived: %w (stderr: %s)", err, stderr)
	}

	return nil
}

// generateKeepalivedConf generates the keepalived.conf content for a node.
func generateKeepalivedConf(nodeConfig *KeepalivedNodeConfig, deployment *KeepalivedDeployment) string {
	healthCheckPath := "/etc/keepalived/" + defaults.KeepalivedHealthCheckScript

	conf := fmt.Sprintf(`# Keepalived configuration - Generated by dscotctl
# VIP: %s | Interface: %s | Node State: %s

global_defs {
    router_id %s_%d
    script_user root
    enable_script_security
}

vrrp_script chk_health {
    script "%s"
    interval 5
    weight -20
    fall 2
    rise 2
}

vrrp_instance %s {
    state %s
    interface %s
    virtual_router_id %d
    priority %d
    advert_int %d

    authentication {
        auth_type PASS
        auth_pass %s
    }

    virtual_ipaddress {
        %s
    }

    track_script {
        chk_health
    }
}
`,
		deployment.VIPCIDR,
		nodeConfig.Interface,
		nodeConfig.State,
		defaults.KeepalivedVRRPInstance,
		deployment.RouterID,
		healthCheckPath,
		defaults.KeepalivedVRRPInstance,
		nodeConfig.State,
		nodeConfig.Interface,
		deployment.RouterID,
		nodeConfig.Priority,
		defaults.KeepalivedAdvertInterval,
		deployment.AuthPass,
		deployment.VIPCIDR,
	)

	return conf
}

// WriteHealthCheckScript writes the Docker Swarm health check script to a node.
func WriteHealthCheckScript(ctx context.Context, sshPool *ssh.Pool, host string) error {
	scriptPath := "/etc/keepalived/" + defaults.KeepalivedHealthCheckScript
	script := `#!/bin/bash
# Health check for Keepalived - Docker Swarm node status
# Returns 0 if node is healthy in swarm, 1 otherwise

if ! command -v docker &> /dev/null; then
    exit 1
fi

if docker node ls &>/dev/null; then
    exit 0
else
    exit 1
fi
`
	cmd := fmt.Sprintf(`cat > %s << 'SCRIPT_EOF'
%s
SCRIPT_EOF
chmod +x %s`, scriptPath, script, scriptPath)

	_, stderr, err := sshPool.Run(ctx, host, cmd)
	if err != nil {
		return fmt.Errorf("failed to write health check script: %w (stderr: %s)", err, stderr)
	}

	return nil
}

