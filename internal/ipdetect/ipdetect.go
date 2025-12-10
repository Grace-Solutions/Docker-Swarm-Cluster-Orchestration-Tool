package ipdetect

import (
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// DetectPrimary returns the preferred primary IPv4 address for this node.
//
// Preference order:
//   1. CGNAT 100.64.0.0/10
//   2. RFC1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
//   3. Other non-loopback addresses
//   4. Loopback as a last resort
//
// Docker network subnets are excluded since they are not routable across hosts.
func DetectPrimary() (net.IP, error) {
	// Get Docker subnets to exclude
	dockerSubnets := getDockerSubnetsLocal()

	var cgnat, rfc1918, other, loopback []net.IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.To4() == nil {
				continue
			}

			if ip.IsLoopback() {
				loopback = append(loopback, ip)
				continue
			}

			// Skip IPs in Docker subnets
			if isIPInDockerSubnet(ip, dockerSubnets) {
				continue
			}

			switch classify(ip) {
			case classCGNAT:
				cgnat = append(cgnat, ip)
			case classRFC1918:
				rfc1918 = append(rfc1918, ip)
			default:
				other = append(other, ip)
			}
		}
	}

	if len(cgnat) > 0 {
		return cgnat[0], nil
	}
	if len(rfc1918) > 0 {
		return rfc1918[0], nil
	}
	if len(other) > 0 {
		return other[0], nil
	}
	if len(loopback) > 0 {
		return loopback[0], nil
	}

	return nil, errors.New("ipdetect: no IPv4 address found")
}

// getDockerSubnetsLocal retrieves Docker network subnets from the local system.
// Returns a slice of *net.IPNet representing Docker-managed network ranges.
func getDockerSubnetsLocal() []*net.IPNet {
	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	// Get list of Docker network IDs
	listCmd := exec.Command("docker", "network", "ls", "--format", "{{.ID}}")
	listOut, err := listCmd.Output()
	if err != nil {
		return nil
	}

	var subnets []*net.IPNet
	networkIDs := strings.Split(strings.TrimSpace(string(listOut)), "\n")

	for _, netID := range networkIDs {
		netID = strings.TrimSpace(netID)
		if netID == "" {
			continue
		}

		// Inspect each network for its subnet
		inspectCmd := exec.Command("docker", "network", "inspect", netID, "--format", "{{range .IPAM.Config}}{{.Subnet}}\n{{end}}")
		inspectOut, err := inspectCmd.Output()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(strings.TrimSpace(string(inspectOut)), "\n") {
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

type ipClass int

const (
	classOther ipClass = iota
	classCGNAT
	classRFC1918
)

func classify(ip net.IP) ipClass {
	if inCIDR(ip, "100.64.0.0", 10) {
		return classCGNAT
	}
	if inCIDR(ip, "10.0.0.0", 8) || inCIDR(ip, "172.16.0.0", 12) || inCIDR(ip, "192.168.0.0", 16) {
		return classRFC1918
	}
	return classOther
}

func inCIDR(ip net.IP, base string, prefix int) bool {
	_, network, err := net.ParseCIDR(base + "/" + strconv.Itoa(prefix))
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

