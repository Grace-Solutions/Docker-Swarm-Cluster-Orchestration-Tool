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
type Provider interface {
	// Name returns the provider name (e.g., "microceph").
	Name() string

	// Install installs the storage software on a node.
	Install(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Bootstrap initializes the storage cluster on the primary node.
	Bootstrap(ctx context.Context, sshPool *ssh.Pool, primaryNode string) error

	// GenerateJoinToken generates a token for a node to join the cluster.
	GenerateJoinToken(ctx context.Context, sshPool *ssh.Pool, primaryNode, joiningNode string) (string, error)

	// Join joins a node to an existing storage cluster.
	Join(ctx context.Context, sshPool *ssh.Pool, node, token string) error

	// AddStorage adds storage (disks or loop devices) to a node.
	AddStorage(ctx context.Context, sshPool *ssh.Pool, node string) error

	// CreatePool creates a storage pool for use by containers.
	CreatePool(ctx context.Context, sshPool *ssh.Pool, primaryNode, poolName string, poolSize int) error

	// Mount mounts the storage pool on a node.
	Mount(ctx context.Context, sshPool *ssh.Pool, node, poolName, mountPath string) error

	// Unmount unmounts the storage pool from a node.
	Unmount(ctx context.Context, sshPool *ssh.Pool, node, mountPath string) error

	// Teardown removes the storage cluster from a node.
	Teardown(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Status returns the status of the storage cluster.
	Status(ctx context.Context, sshPool *ssh.Pool, node string) (*ClusterStatus, error)
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

	switch ds.Type {
	case config.StorageTypeMicroCeph:
		log.Infow("creating MicroCeph storage provider",
			"snapChannel", ds.Providers.MicroCeph.SnapChannel,
			"useLoopDevices", ds.Providers.MicroCeph.UseLoopDevices)
		return NewMicroCephProvider(cfg), nil
	case config.StorageTypeNone:
		return nil, fmt.Errorf("storage type 'none' does not require a provider")
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", ds.Type)
	}
}

// SetupCluster orchestrates the complete storage cluster setup.
func SetupCluster(ctx context.Context, sshPool *ssh.Pool, provider Provider, nodes []string, addresses []string, cfg *config.Config) error {
	log := logging.L().With("component", "storage-setup", "provider", provider.Name())
	ds := cfg.GetDistributedStorage()

	if len(nodes) == 0 {
		return fmt.Errorf("no storage nodes provided")
	}

	log.Infow("setting up distributed storage cluster",
		"nodes", len(nodes),
		"poolName", ds.PoolName,
		"mountPath", ds.MountPath)

	primaryNode := nodes[0]

	// Step 1: Install storage software on all nodes
	log.Infow("→ installing storage software on all nodes")
	for _, node := range nodes {
		log.Infow("→ installing on node", "node", node)
		if err := provider.Install(ctx, sshPool, node); err != nil {
			return fmt.Errorf("failed to install storage on %s: %w", node, err)
		}
		log.Infow("✓ storage software installed", "node", node)
	}

	// Step 2: Bootstrap the primary node
	log.Infow("→ bootstrapping primary node", "node", primaryNode)
	if err := provider.Bootstrap(ctx, sshPool, primaryNode); err != nil {
		return fmt.Errorf("failed to bootstrap primary node %s: %w", primaryNode, err)
	}
	log.Infow("✓ primary node bootstrapped", "node", primaryNode)

	// Step 3: Join additional nodes
	for i := 1; i < len(nodes); i++ {
		node := nodes[i]
		log.Infow("→ joining node to cluster", "node", node, "index", i+1, "total", len(nodes))

		// Generate join token
		token, err := provider.GenerateJoinToken(ctx, sshPool, primaryNode, node)
		if err != nil {
			return fmt.Errorf("failed to generate join token for %s: %w", node, err)
		}

		// Join the cluster
		if err := provider.Join(ctx, sshPool, node, token); err != nil {
			return fmt.Errorf("failed to join node %s to cluster: %w", node, err)
		}
		log.Infow("✓ node joined cluster", "node", node)
	}

	// Step 4: Add storage to all nodes
	for _, node := range nodes {
		log.Infow("→ adding storage to node", "node", node)
		if err := provider.AddStorage(ctx, sshPool, node); err != nil {
			return fmt.Errorf("failed to add storage on %s: %w", node, err)
		}
		log.Infow("✓ storage added", "node", node)
	}

	// Step 5: Create storage pool
	log.Infow("→ creating storage pool", "poolName", ds.PoolName, "poolSize", ds.PoolSize)
	if err := provider.CreatePool(ctx, sshPool, primaryNode, ds.PoolName, ds.PoolSize); err != nil {
		return fmt.Errorf("failed to create storage pool: %w", err)
	}
	log.Infow("✓ storage pool created", "poolName", ds.PoolName)

	// Step 6: Mount storage on all nodes
	for _, node := range nodes {
		log.Infow("→ mounting storage on node", "node", node, "mountPath", ds.MountPath)
		if err := provider.Mount(ctx, sshPool, node, ds.PoolName, ds.MountPath); err != nil {
			return fmt.Errorf("failed to mount storage on %s: %w", node, err)
		}
		log.Infow("✓ storage mounted", "node", node)
	}

	log.Infow("✅ distributed storage cluster setup complete", "nodes", len(nodes))
	return nil
}

