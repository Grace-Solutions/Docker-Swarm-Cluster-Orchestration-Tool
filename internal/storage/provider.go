// Package storage provides a framework for distributed storage providers.
package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

	// VerifyOSDsUpForHost verifies that OSDs on the given host are up.
	// Called after AddStorage to confirm the OSD(s) actually started.
	// monNode is a MON node to query; osdSSHNode is the SSH target; osdHostname is the node's hostname.
	VerifyOSDsUpForHost(ctx context.Context, sshPool *ssh.Pool, monNode, osdSSHNode, osdHostname string) error

	// WaitForClusterHealth waits for the cluster to reach a healthy state with
	// at least a majority of the expected OSDs up. Called after all disks are enrolled.
	WaitForClusterHealth(ctx context.Context, sshPool *ssh.Pool, monNode string, expectedOSDs int) error

	// VerifyClusterHealthForMount verifies the cluster is healthy enough for mounts.
	// This is a pre-mount gate to fail fast with a clear message if the cluster is degraded.
	VerifyClusterHealthForMount(ctx context.Context, sshPool *ssh.Pool, monNode string) error

	// CreatePool creates a storage pool/filesystem for use by containers.
	CreatePool(ctx context.Context, sshPool *ssh.Pool, primaryNode, poolName string) error

	// GetClusterCredentials retrieves cluster credentials (admin key, mon addresses) from the primary node.
	// Uses overlay hostname precedence: overlay hostname > overlay IP > private hostname > private IP.
	// monNodes is the list of MON node SSH hostnames (for resolving overlay addresses).
	// overlayProvider is "netbird", "tailscale", or empty.
	GetClusterCredentials(ctx context.Context, sshPool *ssh.Pool, primaryNode string, monNodes []string, overlayProvider string) (*ClusterCredentials, error)

	// Mount mounts the storage filesystem on a node (fetches credentials from node itself).
	Mount(ctx context.Context, sshPool *ssh.Pool, node, poolName string) error

	// MountWithCredentials mounts the storage filesystem using pre-fetched credentials.
	// This is more efficient when mounting multiple nodes as credentials are fetched once.
	MountWithCredentials(ctx context.Context, sshPool *ssh.Pool, node, poolName string, creds *ClusterCredentials) error

	// Unmount unmounts the storage filesystem from a node.
	Unmount(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Teardown removes the storage cluster from a node.
	Teardown(ctx context.Context, sshPool *ssh.Pool, node string) error

	// Status returns the status of the storage cluster.
	Status(ctx context.Context, sshPool *ssh.Pool, node string) (*ClusterStatus, error)

	// EnableRadosGateway enables the RADOS Gateway (S3-compatible) on specified OSD nodes.
	// overlayProvider is used for hostname precedence: overlay hostname > overlay IP > private hostname > private IP.
	// Returns the S3 endpoint URL and credentials.
	EnableRadosGateway(ctx context.Context, sshPool *ssh.Pool, osdNodes []string, port int, overlayProvider string) (*RadosGatewayInfo, error)

	// CreateS3Bucket creates an S3 bucket using the RADOS Gateway.
	// Returns nil if bucket already exists.
	CreateS3Bucket(ctx context.Context, sshPool *ssh.Pool, primaryOSD string, bucketName string) error
}

// RadosGatewayInfo contains the S3 endpoint and credentials for RADOS Gateway.
type RadosGatewayInfo struct {
	Endpoints  []string // List of S3 endpoint URLs (one per RGW node)
	AccessKey  string
	SecretKey  string
	UserID     string
	BucketName string // Name of the created bucket (if any)
}

// ClusterCredentials contains the credentials needed to mount the storage filesystem.
// These are retrieved once from the primary node and distributed to all nodes.
type ClusterCredentials struct {
	AdminKey   string // Ceph admin key for authentication
	MonAddrs   string // Slash-separated list of monitor addresses for mon_addr option (IP:6789/IP:6789/IP:6789)
	FSID       string // Ceph cluster FSID (from `ceph fsid`)
	FSName     string // CephFS filesystem name (e.g., "docker-swarm-0001")
	MonAddrOpt string // Pre-formatted mon_addr option value (IP:6789/IP:6789/IP:6789)
}

// ClusterStatus represents the status of a storage cluster.
type ClusterStatus struct {
	Healthy      bool
	NodeCount    int
	StorageUsed  int64
	StorageTotal int64
	Nodes        []NodeStatus
}

// NodeStatus represents the status of a storage node.
type NodeStatus struct {
	Name    string
	Healthy bool
	Role    string
}

// NodeInfo contains node metadata for formatted logging.
type NodeInfo struct {
	SSHFQDNorIP string // SSH connection hostname/IP (for display)
	NewHostname string // Friendly hostname (if set)
	Role        string // "manager" or "worker"
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
// nodeInfoMap provides node metadata for formatted logging (optional, can be nil).
func SetupCluster(ctx context.Context, sshPool *ssh.Pool, provider Provider, managers []string, workers []string, cfg *config.Config, nodeInfoMap map[string]NodeInfo) error {
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

	// Helper to format node messages
	fmtNode := func(prefix, node, message string) string {
		if nodeInfoMap != nil {
			if info, ok := nodeInfoMap[node]; ok {
				return logging.FormatNodeMessage(prefix, info.SSHFQDNorIP, info.NewHostname, info.Role, message)
			}
		}
		return logging.FormatNodeMessage(prefix, node, "", "", message)
	}

	log.Infow("setting up distributed storage cluster",
		"managers", len(managers),
		"workers", len(workers),
		"totalNodes", len(allNodes),
		"poolName", ds.PoolName,
		"mountPath", mountPath)

	primaryNode := managers[0]

	// Helper to check if a node should have OSD storage based on role
	// Managers (role=manager) = MON only, no disks
	// Workers (role=worker) = OSD, gets disks
	// Both/All/Empty = hybrid, gets both MON and OSD
	shouldAddStorage := func(node string) bool {
		if nodeInfoMap == nil {
			return false
		}
		info, ok := nodeInfoMap[node]
		if !ok {
			return false
		}
		role := strings.ToLower(strings.TrimSpace(info.Role))
		// Workers always get storage
		if role == "worker" {
			return true
		}
		// Managers with role "both", "all", or empty get storage too
		if role == "both" || role == "all" || role == "" {
			return true
		}
		// Pure managers (role=manager) don't get storage
		return false
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 1: Bootstrap primary manager (must complete before anything else)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Infow("PHASE 1: Bootstrap Primary Manager")
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Step 1a: Install on primary manager only
	log.Infow(fmtNode("→", primaryNode, "installing MicroCeph on primary"))
	if err := provider.Install(ctx, sshPool, primaryNode); err != nil {
		return fmt.Errorf("failed to install storage on primary %s: %w", primaryNode, err)
	}
	log.Infow(fmtNode("✓", primaryNode, "MicroCeph installed"))

	// Step 1b: Bootstrap the primary manager (first MON)
	log.Infow(fmtNode("→", primaryNode, "bootstrapping primary MON node"))
	if err := provider.Bootstrap(ctx, sshPool, primaryNode); err != nil {
		return fmt.Errorf("failed to bootstrap primary node %s: %w", primaryNode, err)
	}
	log.Infow(fmtNode("✓", primaryNode, "primary MON node bootstrapped"))

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 2: Join additional MON nodes (managers)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	if len(managers) > 1 {
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Infow("PHASE 2: Join Additional MON Nodes", "count", len(managers)-1)
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for i := 1; i < len(managers); i++ {
			node := managers[i]

			// Install MicroCeph on this node first
			log.Infow(fmtNode("→", node, fmt.Sprintf("installing MicroCeph (%d/%d)", i+1, len(managers))))
			if err := provider.Install(ctx, sshPool, node); err != nil {
				return fmt.Errorf("failed to install storage on %s: %w", node, err)
			}
			log.Infow(fmtNode("✓", node, "MicroCeph installed"))

			// Generate join token and join
			log.Infow(fmtNode("→", node, fmt.Sprintf("joining MON node to cluster (%d/%d)", i+1, len(managers))))
			token, err := provider.GenerateJoinToken(ctx, sshPool, primaryNode, node)
			if err != nil {
				return fmt.Errorf("failed to generate join token for %s: %w", node, err)
			}

			if err := provider.Join(ctx, sshPool, node, token); err != nil {
				return fmt.Errorf("failed to join MON node %s to cluster: %w", node, err)
			}
			log.Infow(fmtNode("✓", node, "MON node joined cluster"))
		}
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 3: Join OSD nodes (workers)
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	if len(workers) > 0 {
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Infow("PHASE 3: Join OSD Nodes", "count", len(workers))
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for i, node := range workers {
			// Install MicroCeph on this node first
			log.Infow(fmtNode("→", node, fmt.Sprintf("installing MicroCeph (%d/%d)", i+1, len(workers))))
			if err := provider.Install(ctx, sshPool, node); err != nil {
				return fmt.Errorf("failed to install storage on %s: %w", node, err)
			}
			log.Infow(fmtNode("✓", node, "MicroCeph installed"))

			// Generate join token and join
			log.Infow(fmtNode("→", node, fmt.Sprintf("joining OSD node to cluster (%d/%d)", i+1, len(workers))))
			token, err := provider.GenerateJoinToken(ctx, sshPool, primaryNode, node)
			if err != nil {
				return fmt.Errorf("failed to generate join token for %s: %w", node, err)
			}

			if err := provider.Join(ctx, sshPool, node, token); err != nil {
				return fmt.Errorf("failed to join OSD node %s to cluster: %w", node, err)
			}
			log.Infow(fmtNode("✓", node, "OSD node joined cluster"))
		}
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 4: Add Storage to OSD Nodes
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// - Workers always get storage (they are OSD nodes)
	// - Managers with role "both"/"all"/"" also get storage
	// - Pure managers (role=manager) do NOT get storage (MON only)
	storageNodes := []string{}
	for _, node := range allNodes {
		if shouldAddStorage(node) {
			storageNodes = append(storageNodes, node)
		}
	}

	if len(storageNodes) > 0 {
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Infow("PHASE 4: Add Storage to OSD Nodes", "count", len(storageNodes))
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		for i, node := range storageNodes {
			log.Infow(fmtNode("→", node, fmt.Sprintf("adding storage (%d/%d)", i+1, len(storageNodes))))
			if err := provider.AddStorage(ctx, sshPool, node); err != nil {
				return fmt.Errorf("failed to add storage on %s: %w", node, err)
			}
			log.Infow(fmtNode("✓", node, "storage added"))

			// Verify OSD came up for this host (best-effort, don't fail deployment)
			// Get the hostname for this node to match against OSD tree
			hostnameCmd := "hostname -f 2>/dev/null || hostname"
			hostnameOut, _, _ := sshPool.Run(ctx, node, hostnameCmd)
			osdHostname := strings.TrimSpace(hostnameOut)
			if osdHostname == "" {
				osdHostname = node // Fallback to SSH node name
			}

			log.Infow(fmtNode("→", node, "verifying OSD is up"), "osdHostname", osdHostname)
			if err := provider.VerifyOSDsUpForHost(ctx, sshPool, primaryNode, node, osdHostname); err != nil {
				// Best-effort: log warning but don't fail deployment
				log.Warnw(fmtNode("⚠", node, "OSD verification failed (continuing)"), "error", err)
			} else {
				log.Infow(fmtNode("✓", node, "OSD verified up"))
			}
		}

		// After all OSDs are added, wait for cluster health (best-effort)
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		log.Infow("PHASE 4a: Verify Cluster Health", "expectedOSDs", len(storageNodes))
		log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		if err := provider.WaitForClusterHealth(ctx, sshPool, primaryNode, len(storageNodes)); err != nil {
			log.Warnw("cluster health verification failed (continuing)", "error", err)
		} else {
			log.Infow("✓ cluster health verified")
		}
	} else {
		log.Warnw("no nodes configured for OSD storage - at least one node needs role=worker, both, all, or empty")
	}

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 5: Create Storage Pool and Get Cluster Credentials
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Infow("PHASE 5: Create Storage Pool", "poolName", ds.PoolName)
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if err := provider.CreatePool(ctx, sshPool, primaryNode, ds.PoolName); err != nil {
		return fmt.Errorf("failed to create storage pool: %w", err)
	}
	log.Infow("✓ storage pool created", "poolName", ds.PoolName)

	// Get cluster credentials from primary (admin key, mon addresses) for mounting
	// Uses overlay hostname precedence: overlay hostname > overlay IP > private
	overlayProvider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.OverlayProvider))
	clusterCreds, err := provider.GetClusterCredentials(ctx, sshPool, primaryNode, managers, overlayProvider)
	if err != nil {
		return fmt.Errorf("failed to get cluster credentials from primary: %w", err)
	}
	log.Infow("✓ cluster credentials retrieved from primary", "monAddrs", clusterCreds.MonAddrs)

	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// PHASE 6: Mount Storage on Worker Nodes Only
	// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
	// Managers (MON nodes) don't need storage mounted - services run on workers
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	log.Infow("PHASE 6: Mount Storage on Worker Nodes", "count", len(workers), "mountPath", mountPath)
	log.Infow("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Pre-mount health gate: verify cluster is healthy enough for CephFS mounts
	log.Infow("→ verifying cluster health before mounting")
	if err := provider.VerifyClusterHealthForMount(ctx, sshPool, primaryNode); err != nil {
		return fmt.Errorf("cluster health check failed before mount: %w", err)
	}
	log.Infow("✓ cluster health verified for mounting")

	for i, node := range workers {
		log.Infow(fmtNode("→", node, fmt.Sprintf("mounting storage (%d/%d)", i+1, len(workers))))
		if err := provider.MountWithCredentials(ctx, sshPool, node, ds.PoolName, clusterCreds); err != nil {
			return fmt.Errorf("failed to mount storage on %s: %w", node, err)
		}
		log.Infow(fmtNode("✓", node, "storage mounted"))
	}

	// Create scripts folder and mount helper script on shared storage
	if len(workers) > 0 {
		log.Infow("→ creating mount helper script on shared storage")
		if err := createMountHelperScript(ctx, sshPool, workers[0], mountPath, clusterCreds); err != nil {
			log.Warnw("failed to create mount helper script (non-fatal)", "error", err)
		} else {
			log.Infow("✓ mount helper script created", "path", mountPath+"/scripts/mount-cephfs.sh")
		}
	}

	// Step 8: Enable RADOS Gateway (S3) on OSD nodes if configured
	mcCfg := ds.Providers.MicroCeph
	if mcCfg.EnableRadosGateway && len(workers) > 0 {
		overlayProvider := strings.ToLower(strings.TrimSpace(cfg.GlobalSettings.OverlayProvider))
		log.Infow("→ Step 8: Enabling RADOS Gateway (S3) on OSD nodes", "port", mcCfg.RadosGatewayPort, "nodes", len(workers), "overlayProvider", overlayProvider)
		rgwInfo, err := provider.EnableRadosGateway(ctx, sshPool, workers, mcCfg.RadosGatewayPort, overlayProvider)
		if err != nil {
			return fmt.Errorf("failed to enable RADOS Gateway: %w", err)
		}

		// Step 8a: Create S3 bucket if configured
		if mcCfg.S3BucketName != "" {
			log.Infow("→ Step 8a: Creating S3 bucket", "bucket", mcCfg.S3BucketName)
			if err := provider.CreateS3Bucket(ctx, sshPool, workers[0], mcCfg.S3BucketName); err != nil {
				return fmt.Errorf("failed to create S3 bucket: %w", err)
			}
			rgwInfo.BucketName = mcCfg.S3BucketName
			log.Infow("✓ S3 bucket created", "bucket", mcCfg.S3BucketName)
		}

		// Step 8b: Write S3 credentials file if configured
		if mcCfg.S3CredentialsFile != "" {
			log.Infow("→ Step 8b: Writing S3 credentials file", "path", mcCfg.S3CredentialsFile)
			if err := writeS3CredentialsFile(mcCfg.S3CredentialsFile, rgwInfo); err != nil {
				return fmt.Errorf("failed to write S3 credentials file: %w", err)
			}
			log.Infow("✓ S3 credentials written", "path", mcCfg.S3CredentialsFile)
		}

		log.Infow("✓ RADOS Gateway (S3) enabled",
			"endpoints", rgwInfo.Endpoints,
			"userId", rgwInfo.UserID,
			"accessKey", rgwInfo.AccessKey,
			"bucket", rgwInfo.BucketName)
	} else if mcCfg.EnableRadosGateway && len(workers) == 0 {
		log.Warnw("RADOS Gateway enabled but no OSD workers available - skipping")
	}

	// Step 9: Final cluster health verification
	log.Infow("→ Step 9: Verifying cluster health")
	status, err := provider.Status(ctx, sshPool, primaryNode)
	if err != nil {
		log.Warnw("failed to get final cluster status (non-fatal)", "error", err)
	} else {
		log.Infow("✓ cluster health verified",
			"healthy", status.Healthy,
			"nodeCount", status.NodeCount,
			"storageUsed", status.StorageUsed,
			"storageTotal", status.StorageTotal)
	}

	log.Infow("✅ distributed storage cluster setup complete",
		"managers", len(managers),
		"workers", len(workers),
		"mountPath", mountPath)
	return nil
}

// S3Credentials represents the S3 credentials file format.
type S3Credentials struct {
	Endpoints  []string `json:"endpoints"`
	AccessKey  string   `json:"accessKey"`
	SecretKey  string   `json:"secretKey"`
	UserID     string   `json:"userId"`
	BucketName string   `json:"bucketName,omitempty"`
}

// writeS3CredentialsFile writes S3 credentials to a JSON file.
func writeS3CredentialsFile(path string, info *RadosGatewayInfo) error {
	creds := S3Credentials{
		Endpoints:  info.Endpoints,
		AccessKey:  info.AccessKey,
		SecretKey:  info.SecretKey,
		UserID:     info.UserID,
		BucketName: info.BucketName,
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	return nil
}

// createMountHelperScript creates a shell script on the shared storage that can be
// copied to any node to mount the CephFS filesystem via fstab. All values are expanded inline.
func createMountHelperScript(ctx context.Context, sshPool *ssh.Pool, node, mountPath string, creds *ClusterCredentials) error {
	scriptsDir := mountPath + "/scripts"
	scriptPath := scriptsDir + "/mount-cephfs.sh"

	// Create scripts directory
	mkdirCmd := fmt.Sprintf("mkdir -p %s", scriptsDir)
	if _, _, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create scripts directory: %w", err)
	}

	// Build the script content with fstab approach
	script := fmt.Sprintf(`#!/bin/bash
MOUNT_PATH="%s"
ADMIN_KEY="%s"
FSID="%s"
FSNAME="%s"
MON_ADDRS="%s"
FSTAB_ENTRY="admin@${FSID}.${FSNAME}=/ ${MOUNT_PATH} ceph mon_addr=${MON_ADDRS},secret=${ADMIN_KEY},_netdev,x-systemd.mount-timeout=45s,x-systemd.device-timeout=45s 0 0"
mkdir -p "$MOUNT_PATH"
grep -qF "$MOUNT_PATH" /etc/fstab || echo "$FSTAB_ENTRY" >> /etc/fstab
systemctl daemon-reload
mount -a
df -h "$MOUNT_PATH"
`, mountPath, creds.AdminKey, creds.FSID, creds.FSName, creds.MonAddrOpt)

	// Write the script via SSH
	writeCmd := fmt.Sprintf("cat > %s << 'SCRIPT_EOF'\n%sSCRIPT_EOF", scriptPath, script)
	if _, stderr, err := sshPool.Run(ctx, node, writeCmd); err != nil {
		return fmt.Errorf("failed to write script: %w (stderr: %s)", err, stderr)
	}

	// Make executable
	chmodCmd := fmt.Sprintf("chmod +x %s", scriptPath)
	if _, _, err := sshPool.Run(ctx, node, chmodCmd); err != nil {
		return fmt.Errorf("failed to chmod script: %w", err)
	}

	return nil
}
