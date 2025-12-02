// Package storage provides a framework for distributed storage providers.
package storage

import (
	"context"
	"fmt"

	"clusterctl/internal/config"
	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// Provider defines the interface for distributed storage backends.
// Storage providers map Docker Swarm roles to storage roles:
// - Managers → MON nodes (cluster brain/quorum)
// - Workers → OSD nodes (data storage)
type Provider interface {
	// Name returns the provider name (e.g., "microceph").
	Name() string

	// GetMountPath returns the mount path for the storage filesystem.
	GetMountPath() string

	// Install installs the storage software on a node.
	Install(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Bootstrap initializes the storage cluster on the primary manager node.
	Bootstrap(ctx context.Context, sshPool *ssh.Pool, primaryNode string) error

	// GenerateJoinToken generates a token for a node to join the cluster.
	GenerateJoinToken(ctx context.Context, sshPool *ssh.Pool, primaryNode, joiningNode string) (string, error)

	// Join joins a node to an existing storage cluster.
	Join(ctx context.Context, sshPool *ssh.Pool, node, token string) error

	// AddStorage adds storage (disks or loop devices) to an OSD node (worker).
	// This should only be called on worker nodes.
	AddStorage(ctx context.Context, sshPool *ssh.Pool, node string) error

	// CreatePool creates a storage pool/filesystem for use by containers.
	CreatePool(ctx context.Context, sshPool *ssh.Pool, primaryNode, poolName string) error

	// Mount mounts the storage filesystem on a node.
	Mount(ctx context.Context, sshPool *ssh.Pool, node, poolName string) error

	// Unmount unmounts the storage filesystem from a node.
	Unmount(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Teardown removes the storage cluster from a node.
	Teardown(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Status returns the status of the storage cluster.
	Status(ctx context.Context, sshPool *ssh.Pool, node string) (*ClusterStatus, error)

	// EnableRadosGateway enables the RADOS Gateway (S3-compatible) on specified OSD nodes.
	// Returns the S3 endpoint URL and credentials.
	EnableRadosGateway(ctx context.Context, sshPool *ssh.Pool, osdNodes []string, port int) (*RadosGatewayInfo, error)
}

// RadosGatewayInfo contains the S3 endpoint and credentials for RADOS Gateway.
type RadosGatewayInfo struct {
	Endpoints  []string // List of S3 endpoint URLs (one per RGW node)
	AccessKey  string
	SecretKey  string
	UserID     string
}

// ClusterStatus represents the status of a storage cluster.
type ClusterStatus struct {
	Healthy     bool
	NodeCount   int
	StorageUsed int64
	StorageTotal int64
	Nodes       []NodeStatus
}

// NodeStatus represents the status of a storage node.
type NodeStatus struct {
	Name    string
	Healthy bool
	Role    string
}

// NewProvider creates a new storage provider based on the configuration.
func NewProvider(cfg *config.Config) (Provider, error) {
	ds := cfg.GetDistributedStorage()
	log := logging.L().With("component", "storage-provider")

	switch ds.Provider {
	case config.StorageProviderMicroCeph:
		log.Infow("creating MicroCeph storage provider",
			"snapChannel", ds.Providers.MicroCeph.SnapChannel,
			"mountPath", ds.Providers.MicroCeph.MountPath,
			"allowLoopDevices", ds.Providers.MicroCeph.AllowLoopDevices)
		return NewMicroCephProvider(cfg), nil
	case config.StorageProviderNone:
		return nil, fmt.Errorf("storage provider 'none' does not require a provider")
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", ds.Provider)
	}
}

// SetupCluster orchestrates the complete storage cluster setup.
// managers are MON nodes (cluster brain/quorum), workers are OSD nodes (data storage).
// All nodes participate in the cluster, but only workers get OSDs added.
func SetupCluster(ctx context.Context, sshPool *ssh.Pool, provider Provider, managers []string, workers []string, cfg *config.Config) error {
	log := logging.L().With("component", "storage-setup", "provider", provider.Name())
	ds := cfg.GetDistributedStorage()
	mountPath := provider.GetMountPath()

	allNodes := append(managers, workers...)
	if len(allNodes) == 0 {
		return fmt.Errorf("no storage nodes provided")
	}

	if len(managers) == 0 {
		return fmt.Errorf("at least one manager (MON) node is required")
	}

	log.Infow("setting up distributed storage cluster",
		"managers", len(managers),
		"workers", len(workers),
		"totalNodes", len(allNodes),
		"poolName", ds.PoolName,
		"mountPath", mountPath)

	primaryNode := managers[0]

	// Step 1: Install storage software on all nodes
	log.Infow("→ Step 1: Installing storage software on all nodes")
	for _, node := range allNodes {
		log.Infow("→ installing on node", "node", node)
		if err := provider.Install(ctx, sshPool, node); err != nil {
			return fmt.Errorf("failed to install storage on %s: %w", node, err)
		}
		log.Infow("✓ storage software installed", "node", node)
	}

	// Step 2: Bootstrap the primary manager node (first MON)
	log.Infow("→ Step 2: Bootstrapping primary MON node", "node", primaryNode)
	if err := provider.Bootstrap(ctx, sshPool, primaryNode); err != nil {
		return fmt.Errorf("failed to bootstrap primary node %s: %w", primaryNode, err)
	}
	log.Infow("✓ primary MON node bootstrapped", "node", primaryNode)

	// Step 3: Join additional manager nodes (MONs for quorum)
	if len(managers) > 1 {
		log.Infow("→ Step 3: Joining additional MON nodes", "count", len(managers)-1)
		for i := 1; i < len(managers); i++ {
			node := managers[i]
			log.Infow("→ joining MON node to cluster", "node", node, "index", i+1, "total", len(managers))

			token, err := provider.GenerateJoinToken(ctx, sshPool, primaryNode, node)
			if err != nil {
				return fmt.Errorf("failed to generate join token for %s: %w", node, err)
			}

			if err := provider.Join(ctx, sshPool, node, token); err != nil {
				return fmt.Errorf("failed to join MON node %s to cluster: %w", node, err)
			}
			log.Infow("✓ MON node joined cluster", "node", node)
		}
	}

	// Step 4: Join worker nodes (OSDs)
	if len(workers) > 0 {
		log.Infow("→ Step 4: Joining OSD nodes", "count", len(workers))
		for i, node := range workers {
			log.Infow("→ joining OSD node to cluster", "node", node, "index", i+1, "total", len(workers))

			token, err := provider.GenerateJoinToken(ctx, sshPool, primaryNode, node)
			if err != nil {
				return fmt.Errorf("failed to generate join token for %s: %w", node, err)
			}

			if err := provider.Join(ctx, sshPool, node, token); err != nil {
				return fmt.Errorf("failed to join OSD node %s to cluster: %w", node, err)
			}
			log.Infow("✓ OSD node joined cluster", "node", node)
		}
	}

	// Step 5: Add storage (OSDs) only on worker nodes
	if len(workers) > 0 {
		log.Infow("→ Step 5: Adding storage to OSD nodes", "count", len(workers))
		for _, node := range workers {
			log.Infow("→ adding storage to OSD node", "node", node)
			if err := provider.AddStorage(ctx, sshPool, node); err != nil {
				return fmt.Errorf("failed to add storage on %s: %w", node, err)
			}
			log.Infow("✓ storage added", "node", node)
		}
	} else {
		log.Warnw("no worker nodes configured for OSD storage")
	}

	// Step 6: Create storage pool/filesystem
	log.Infow("→ Step 6: Creating storage pool/filesystem", "poolName", ds.PoolName)
	if err := provider.CreatePool(ctx, sshPool, primaryNode, ds.PoolName); err != nil {
		return fmt.Errorf("failed to create storage pool: %w", err)
	}
	log.Infow("✓ storage pool created", "poolName", ds.PoolName)

	// Step 7: Mount storage on all nodes
	log.Infow("→ Step 7: Mounting storage on all nodes", "mountPath", mountPath)
	for _, node := range allNodes {
		log.Infow("→ mounting storage on node", "node", node)
		if err := provider.Mount(ctx, sshPool, node, ds.PoolName); err != nil {
			return fmt.Errorf("failed to mount storage on %s: %w", node, err)
		}
		log.Infow("✓ storage mounted", "node", node)
	}

	// Step 8: Enable RADOS Gateway (S3) on OSD nodes if configured
	mcCfg := ds.Providers.MicroCeph
	if mcCfg.EnableRadosGateway && len(workers) > 0 {
		log.Infow("→ Step 8: Enabling RADOS Gateway (S3) on OSD nodes", "port", mcCfg.RadosGatewayPort, "nodes", len(workers))
		rgwInfo, err := provider.EnableRadosGateway(ctx, sshPool, workers, mcCfg.RadosGatewayPort)
		if err != nil {
			return fmt.Errorf("failed to enable RADOS Gateway: %w", err)
		}
		log.Infow("✓ RADOS Gateway (S3) enabled",
			"endpoints", rgwInfo.Endpoints,
			"userId", rgwInfo.UserID,
			"accessKey", rgwInfo.AccessKey)
	} else if mcCfg.EnableRadosGateway && len(workers) == 0 {
		log.Warnw("RADOS Gateway enabled but no OSD workers available - skipping")
	}

	log.Infow("✅ distributed storage cluster setup complete",
		"managers", len(managers),
		"workers", len(workers),
		"mountPath", mountPath)
	return nil
}

