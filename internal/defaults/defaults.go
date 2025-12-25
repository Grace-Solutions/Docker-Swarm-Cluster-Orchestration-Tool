// Package defaults provides centralized default values and constants used across the codebase.
// This ensures consistency and makes maintenance easier - change once, apply everywhere.
package defaults

// =============================================================================
// Docker Swarm Overlay Networks
// =============================================================================

// Network names for Docker Swarm overlay networks
const (
	// InternalNetworkName is the name of the internal overlay network for inter-service communication.
	InternalNetworkName = "DOCKER-SWARM-CLUSTER-INTERNAL-COMMUNICATION"

	// DefaultIngressNetworkName is Docker's default ingress network name.
	// We use the default ingress network instead of creating a custom one.
	DefaultIngressNetworkName = "ingress"
)

// NetworkConfig holds the configuration for a Docker overlay network.
type NetworkConfig struct {
	Name     string
	Subnet   string
	Gateway  string
	Internal bool // If true, network is internal-only (no external access)
}

// InternalNetwork returns the default configuration for the internal overlay network.
// Uses 10.10.0.0/20 to avoid conflicts with Docker's default bridge (172.17.0.0/16).
func InternalNetwork() NetworkConfig {
	return NetworkConfig{
		Name:     InternalNetworkName,
		Subnet:   "10.10.0.0/20",
		Gateway:  "10.10.0.1",
		Internal: true,
	}
}

// AllNetworks returns all default overlay network configurations that we create.
// Note: This does NOT include the default Docker ingress network which is managed by Docker.
func AllNetworks() []NetworkConfig {
	return []NetworkConfig{
		InternalNetwork(),
	}
}

// =============================================================================
// MicroCeph / CephFS Defaults
// =============================================================================

const (
	// MicroCephSnapChannel is the default snap channel for MicroCeph installation.
	MicroCephSnapChannel = "reef/stable"

	// CephFSMountPath is the default mount path for CephFS.
	CephFSMountPath = "/mnt/cephfs"

	// ServiceDataSubdir is the subdirectory under the storage mount for service data.
	ServiceDataSubdir = "data"

	// CephLoopDeviceDirectory is the default directory for loop device image files.
	CephLoopDeviceDirectory = "/var/snap/microceph/common"

	// CephLoopDeviceSizeGB is the default size for loop device OSDs in GB.
	CephLoopDeviceSizeGB = 4

	// CephPoolName is the default name for the Ceph storage pool.
	CephPoolName = "docker-swarm"
)

// =============================================================================
// RADOS Gateway (S3) Defaults
// =============================================================================

const (
	// RadosGatewayPort is the default port for the RADOS Gateway (S3) service.
	RadosGatewayPort = 7480

	// S3AdminUser is the default username for S3 admin user.
	S3AdminUser = "dscotctl-s3-admin"

	// S3AdminDisplayName is the display name for S3 admin user.
	S3AdminDisplayName = "DSCOTCTL S3 Admin"
)

// =============================================================================
// SSH Defaults
// =============================================================================

const (
	// SSHPort is the default SSH port.
	SSHPort = 22

	// SSHUsername is the default SSH username.
	SSHUsername = "root"

	// SSHKeyType is the default SSH key type for auto-generation.
	SSHKeyType = "ed25519"
)

// =============================================================================
// Overlay Provider Defaults
// =============================================================================

const (
	// OverlayProviderNone is the default overlay provider (none).
	OverlayProviderNone = "none"
)

