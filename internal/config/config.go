package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"clusterctl/internal/defaults"
)

// Config represents the cluster configuration loaded from JSON.
type Config struct {
	GlobalSettings GlobalSettings `json:"globalSettings"`
	Nodes          []NodeConfig   `json:"nodes"`
	ConfigPath     string         `json:"-"` // Path to the config file (not serialized)
}

// StorageProviderType represents the type of distributed storage backend.
type StorageProviderType string

const (
	StorageProviderNone      StorageProviderType = "none"
	StorageProviderMicroCeph StorageProviderType = "microceph"
)

// MicroCephProviderConfig contains MicroCeph-specific configuration.
// MicroCeph uses Docker Swarm managers as MON nodes (cluster brain/quorum)
// and workers as OSD nodes (data storage).
type MicroCephProviderConfig struct {
	// SnapChannel is the snap channel to install MicroCeph from.
	// Available channels: "reef/stable" (default, recommended), "squid/stable", "quincy/stable", "latest/stable", "latest/edge"
	// Reef is 18.x (stable LTS), Squid is 19.x (newer), Quincy is 17.x (older)
	// Default: "reef/stable"
	SnapChannel string `json:"snapChannel"`

	// EnableUpdates enables automatic snap updates for MicroCeph.
	// When false, the snap is held at the installed version.
	// Default: false
	EnableUpdates bool `json:"enableUpdates"`

	// MountPath is where CephFS will be mounted on nodes.
	// Default: "/mnt/cephfs"
	MountPath string `json:"mountPath"`

	// AllowLoopDevices allows loop file-backed OSDs instead of physical disks.
	// Loop devices are ONLY created when no eligible physical disks are found (count=0).
	// Useful for testing and development environments.
	// Default: false (use physical disks only)
	AllowLoopDevices bool `json:"allowLoopDevices"`

	// LoopDeviceDirectory is the directory where loop device image files are stored.
	// This directory will be automatically created if it doesn't exist.
	// Default: "/var/snap/microceph/common"
	LoopDeviceDirectory string `json:"loopDeviceDirectory"`

	// LoopDeviceSizeGB is the size of the loop device in GB when AllowLoopDevices is true.
	// Default: 4
	LoopDeviceSizeGB int `json:"loopDeviceSizeGB"`

	// LoopDeviceThinProvision enables thin provisioning for loop devices.
	// When true, the loop file only uses disk space as data is written.
	// When false, the full size is allocated upfront.
	// Default: true
	LoopDeviceThinProvision bool `json:"loopDeviceThinProvision"`

	// EnableRadosGateway enables the Ceph Object Gateway (S3-compatible) service.
	// RADOS Gateway provides RESTful API compatible with Amazon S3 and OpenStack Swift.
	// Default: false
	EnableRadosGateway bool `json:"enableRadosGateway"`

	// RadosGatewayPort is the port for the RADOS Gateway service when EnableRadosGateway is true.
	// Default: 7480
	RadosGatewayPort int `json:"radosGatewayPort"`

	// RadosGatewayMultisite enables multisite replication for S3 objects.
	// When true, objects written via S3 protocol are replicated across RGW instances.
	// This configures realm, zonegroup, zone, and sync policies automatically.
	// Requires multiple OSD nodes for meaningful replication.
	// Default: true (replication enabled by default for HA)
	RadosGatewayMultisite bool `json:"radosGatewayMultisite"`

	// S3BucketName is the name of the S3 bucket to create when EnableRadosGateway is true.
	// If empty, no bucket is created.
	// Default: "" (no bucket created)
	S3BucketName string `json:"s3BucketName"`

	// S3CredentialsFile is the path to write S3 credentials after RGW is enabled.
	// The file will contain access_key, secret_key, endpoint, and bucket name.
	// If empty, credentials are only logged to console.
	// Default: "" (no file written)
	S3CredentialsFile string `json:"s3CredentialsFile"`
}

// StorageProviders contains provider-specific configurations.
type StorageProviders struct {
	MicroCeph MicroCephProviderConfig `json:"microceph"`
}

// EligibleDisks defines disk selection criteria using regex patterns.
// Inclusions are combined with OR (any match includes the disk).
// Exclusions are combined with AND (all must match to exclude the disk).
type EligibleDisks struct {
	// InclusionExpression is an array of regex patterns to match eligible disks.
	// Patterns are combined with OR logic (disk matches if ANY pattern matches).
	// Example: ["^/dev/sd[b-z]$", "^/dev/nvme[0-9]n1$"]
	InclusionExpression []string `json:"inclusionExpression"`

	// ExclusionExpression is an array of regex patterns to exclude disks.
	// Patterns are combined with AND logic (disk excluded if ALL patterns match).
	// Exclusions are applied after inclusions.
	// Example: ["^/dev/sda$", "^/dev/vda$"]
	ExclusionExpression []string `json:"exclusionExpression"`
}

// DistributedStorage contains distributed storage configuration.
// This is under GlobalSettings to keep all cluster-wide settings together.
type DistributedStorage struct {
	// Enabled controls whether distributed storage is configured.
	// Default: false
	Enabled bool `json:"enabled"`

	// Provider specifies the distributed storage backend: "none", "microceph"
	// The value must match a key under "providers" for provider-specific settings.
	// Default: "microceph"
	Provider StorageProviderType `json:"provider"`

	// ForceRecreation forces teardown and recreation of the storage cluster during deployment.
	// WARNING: This will delete all data in the storage cluster.
	// Default: false
	ForceRecreation bool `json:"forceRecreation"`

	// PoolName is the name of the storage pool to create.
	// Default: "docker-swarm"
	PoolName string `json:"poolName"`

	// EligibleDisks defines disk selection criteria using regex patterns.
	EligibleDisks EligibleDisks `json:"eligibleDisks"`

	// Providers contains provider-specific configurations.
	Providers StorageProviders `json:"providers"`
}

// ScriptConfig represents a script to execute on nodes.
type ScriptConfig struct {
	Enabled         bool              `json:"enabled"`         // Enable this script (must be true to execute)
	ContinueOnError bool              `json:"continueOnError"` // Continue deployment if this script fails (default: false)
	Name            string            `json:"name"`            // Script name/description
	Source          string            `json:"source"`          // Local path or http/https URL
	Parameters      string            `json:"parameters"`      // Script parameters/arguments
	Conditions      []ScriptCondition `json:"conditions"`      // Conditions for script execution (all must match, empty = run on all nodes)
}

// ScriptCondition represents a condition for script execution.
type ScriptCondition struct {
	Property string `json:"property"`       // Node property to check (e.g., "role", "hostname", "username", "newHostname", "storageEnabled")
	Operator string `json:"operator"`       // Comparison operator: "=", "!=", "regex", "!regex"
	Value    string `json:"value"`          // Value to compare against (case-insensitive for regex)
	Negate   bool   `json:"negate"`         // Negate the result of this condition (default: false)
}

// Decommissioning contains settings for cluster teardown/decommissioning.
type Decommissioning struct {
	// Enabled triggers cluster teardown instead of deployment.
	// When true, the cluster will be torn down according to the settings below.
	// Default: false
	Enabled bool `json:"enabled"`

	// DisconnectOverlays removes overlay network agents during teardown.
	// WARNING: This may break SSH connectivity if you're connected via the overlay.
	// Default: false
	DisconnectOverlays bool `json:"disconnectOverlays"`

	// RemoveStorage tears down the distributed storage cluster.
	// This is also controlled by distributedStorage.forceRecreation.
	// Default: uses distributedStorage.forceRecreation value
	RemoveStorage *bool `json:"removeStorage,omitempty"`

	// RemoveDockerSwarm removes Docker Swarm configuration from all nodes.
	// Default: true
	RemoveDockerSwarm *bool `json:"removeDockerSwarm,omitempty"`
}

// GlobalSettings contains cluster-wide configuration.
type GlobalSettings struct {
	ClusterName                    string             `json:"clusterName"`                    // Cluster name (required)
	OverlayProvider                string             `json:"overlayProvider"`                // "netbird", "tailscale", "wireguard", "none" (default: "none")
	OverlayConfig                  string             `json:"overlayConfig"`                  // Provider-specific config (e.g., Netbird setup key, Tailscale auth key)
	SetRootPassword                string             `json:"setRootPassword"`                // Set root password on all nodes (optional, empty = no change)
	SSHKeyType                     string             `json:"sshKeyType"`                     // SSH key type for auto-generation: "ed25519" (default) or "rsa"
	ServiceDefinitionDirectory     string             `json:"serviceDefinitionDirectory"`     // Directory containing service definition YAML files (default: "services" relative to binary)
	DistributedStorage             DistributedStorage `json:"distributedStorage"`             // Distributed storage configuration
	PreScripts                     []ScriptConfig     `json:"preScripts"`                     // Scripts to execute before deployment
	PostScripts                    []ScriptConfig     `json:"postScripts"`                    // Scripts to execute after deployment
	RemoveSSHPublicKeyOnCompletion bool               `json:"removeSSHPublicKeyOnCompletion"` // Remove SSH public key from nodes on completion (default: false)
	Decommissioning                Decommissioning    `json:"decommissioning"`                // Cluster teardown/decommissioning settings
}

// NodeConfig represents a single node's configuration.
type NodeConfig struct {
	// Node Control
	Enabled *bool `json:"enabled"` // Enable this node for deployment (default: true if nil)

	// SSH Connection Settings
	// SSHFQDNorIP is the hostname/IP used ONLY for SSH connections.
	// Infrastructure setup (Docker Swarm, MicroCeph, etc.) uses overlay hostname precedence:
	// overlay hostname > overlay IP > private hostname > private IP
	SSHFQDNorIP            string `json:"sshFQDNorIP"`            // SSH connection hostname or IP (required)
	Username               string `json:"username"`               // SSH username (required, default: "root")
	Password               string `json:"password"`               // SSH password (optional, use privateKeyPath instead)
	PrivateKeyPath         string `json:"privateKeyPath"`         // Path to SSH private key (optional, use password instead)
	PrivateKeyPassword     string `json:"privateKeyPassword"`     // Password for encrypted private key (optional, blank = no passphrase)
	UseSSHAutomaticKeyPair bool   `json:"useSSHAutomaticKeyPair"` // Use automatically generated SSH key pair (default: false)
	SSHPort                int    `json:"sshPort"`                // SSH port (default: 22)

	// Node Role Settings
	Role string `json:"role"` // "manager", "worker", or "both" (required)

	// System Settings
	NewHostname        string `json:"newHostname"`        // New hostname to set (optional, idempotent)
	RebootOnCompletion bool   `json:"rebootOnCompletion"` // Reboot node after deployment (default: false)

	// Distributed Storage Settings (per-node)
	StorageEnabled bool `json:"storageEnabled"` // Enable distributed storage on this node (default: false)

	// Script Execution
	ScriptsEnabled bool `json:"scriptsEnabled"` // Enable script execution on this node (default: true)

	// Custom Labels
	Labels map[string]string `json:"labels"` // Custom Docker node labels (key-value pairs)
}

// Load loads the configuration from a JSON file.
// If configPath is empty, it looks for a file with the same name as the binary in the binary's directory.
func Load(configPath string) (*Config, error) {
	// If no config path specified, use default (binary name + .json in binary directory)
	if configPath == "" {
		execPath, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable path: %w", err)
		}
		execDir := filepath.Dir(execPath)
		execName := filepath.Base(execPath)
		// Remove extension if present
		execNameNoExt := execName
		if ext := filepath.Ext(execName); ext != "" {
			execNameNoExt = execName[:len(execName)-len(ext)]
		}
		configPath = filepath.Join(execDir, execNameNoExt+".json")
	}

	// Read the file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Parse JSON
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Apply defaults
	cfg.ApplyDefaults()

	// Store the absolute config path for debugging
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		// Fallback to original path if absolute path resolution fails
		cfg.ConfigPath = configPath
	} else {
		cfg.ConfigPath = absPath
	}

	return &cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if len(c.Nodes) == 0 {
		return fmt.Errorf("no nodes defined in configuration")
	}

	managerCount := 0
	for i, node := range c.Nodes {
		if node.SSHFQDNorIP == "" {
			return fmt.Errorf("node %d: sshFQDNorIP is required", i)
		}
		if node.Role != "manager" && node.Role != "worker" && node.Role != "both" {
			return fmt.Errorf("node %d (%s): role must be 'manager', 'worker', or 'both'", i, node.SSHFQDNorIP)
		}
		// "both" counts as a manager (it will be a manager that also has OSD storage)
		if node.Role == "manager" || node.Role == "both" {
			managerCount++
		}

		// If not using automatic key pair, require password or privateKeyPath
		if !node.UseSSHAutomaticKeyPair && node.Password == "" && node.PrivateKeyPath == "" {
			return fmt.Errorf("node %d (%s): either password, privateKeyPath, or useSSHAutomaticKeyPair must be specified", i, node.SSHFQDNorIP)
		}
	}

	if managerCount == 0 {
		return fmt.Errorf("at least one manager node is required")
	}

	return nil
}

// ApplyDefaults applies default values to the configuration.
// Default values are centralized in the defaults package.
func (c *Config) ApplyDefaults() {
	// Global defaults
	if c.GlobalSettings.OverlayProvider == "" {
		c.GlobalSettings.OverlayProvider = defaults.OverlayProviderNone
	}

	// DistributedStorage defaults (now under GlobalSettings)
	ds := &c.GlobalSettings.DistributedStorage
	if ds.Provider == "" {
		ds.Provider = StorageProviderMicroCeph
	}
	if ds.PoolName == "" {
		ds.PoolName = defaults.CephPoolName
	}

	// MicroCeph provider defaults
	mc := &ds.Providers.MicroCeph
	if mc.SnapChannel == "" {
		mc.SnapChannel = defaults.MicroCephSnapChannel
	}
	if mc.MountPath == "" {
		mc.MountPath = defaults.CephFSMountPath
	}
	if mc.LoopDeviceDirectory == "" {
		mc.LoopDeviceDirectory = defaults.CephLoopDeviceDirectory
	}
	if mc.LoopDeviceSizeGB == 0 {
		mc.LoopDeviceSizeGB = defaults.CephLoopDeviceSizeGB
	}
	// LoopDeviceThinProvision defaults to true (set explicitly since zero value is false)
	// This is handled by checking if the struct was unmarshaled with the field set
	if mc.RadosGatewayPort == 0 {
		mc.RadosGatewayPort = defaults.RadosGatewayPort
	}

	// Node defaults
	for i := range c.Nodes {
		// Enabled defaults to true if not explicitly set
		if c.Nodes[i].Enabled == nil {
			enabled := true
			c.Nodes[i].Enabled = &enabled
		}

		// SSH defaults
		if c.Nodes[i].Username == "" {
			c.Nodes[i].Username = defaults.SSHUsername
		}
		if c.Nodes[i].SSHPort == 0 {
			c.Nodes[i].SSHPort = defaults.SSHPort
		}
	}
}

// IsEnabled returns true if the node is enabled for deployment.
func (n *NodeConfig) IsEnabled() bool {
	if n.Enabled == nil {
		return true // Default to enabled
	}
	return *n.Enabled
}

// GetStorageNodes returns all nodes that have distributed storage enabled.
func (c *Config) GetStorageNodes() []NodeConfig {
	var storageNodes []NodeConfig
	for _, node := range c.Nodes {
		if node.IsEnabled() && node.StorageEnabled {
			storageNodes = append(storageNodes, node)
		}
	}
	return storageNodes
}

// GetDistributedStorage returns the distributed storage configuration.
func (c *Config) GetDistributedStorage() *DistributedStorage {
	return &c.GlobalSettings.DistributedStorage
}

// IsStorageEnabled returns true if distributed storage is enabled globally.
func (c *Config) IsStorageEnabled() bool {
	return c.GlobalSettings.DistributedStorage.Enabled
}

// GetDecommissioning returns the decommissioning configuration.
func (c *Config) GetDecommissioning() *Decommissioning {
	return &c.GlobalSettings.Decommissioning
}

// IsDecommissioning returns true if decommissioning mode is enabled.
func (c *Config) IsDecommissioning() bool {
	return c.GlobalSettings.Decommissioning.Enabled
}

// ShouldRemoveStorage returns true if storage should be removed during decommissioning.
// Falls back to distributedStorage.forceRecreation if not explicitly set.
func (d *Decommissioning) ShouldRemoveStorage(ds *DistributedStorage) bool {
	if d.RemoveStorage != nil {
		return *d.RemoveStorage
	}
	return ds.ForceRecreation
}

// ShouldRemoveDockerSwarm returns true if Docker Swarm should be removed during decommissioning.
// Defaults to true if not explicitly set.
func (d *Decommissioning) ShouldRemoveDockerSwarm() bool {
	if d.RemoveDockerSwarm != nil {
		return *d.RemoveDockerSwarm
	}
	return true
}
