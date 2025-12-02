package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the cluster configuration loaded from JSON.
type Config struct {
	GlobalSettings GlobalSettings `json:"globalSettings"`
	Nodes          []NodeConfig   `json:"nodes"`
	ConfigPath     string         `json:"-"` // Path to the config file (not serialized)
}

// DistributedStorageType represents the type of distributed storage backend.
type DistributedStorageType string

const (
	StorageTypeNone      DistributedStorageType = "none"
	StorageTypeMicroCeph DistributedStorageType = "microceph"
)

// MicroCephProviderConfig contains MicroCeph-specific configuration.
type MicroCephProviderConfig struct {
	// SnapChannel is the snap channel to install MicroCeph from.
	// Default: "latest/stable"
	SnapChannel string `json:"snapChannel"`

	// UseLoopDevices uses loop file-backed OSDs instead of physical disks.
	// Useful for testing and development. Each loop device is 4GB.
	// Default: false (use physical disks)
	UseLoopDevices bool `json:"useLoopDevices"`

	// LoopDeviceCount is the number of loop devices to create per node when UseLoopDevices is true.
	// Default: 3
	LoopDeviceCount int `json:"loopDeviceCount"`

	// LoopDeviceSizeGB is the size of each loop device in GB when UseLoopDevices is true.
	// Default: 4
	LoopDeviceSizeGB int `json:"loopDeviceSizeGB"`

	// EnableRGW enables the Ceph Object Gateway (S3-compatible) service.
	// Default: false
	EnableRGW bool `json:"enableRGW"`

	// RGWPort is the port for the RGW service when EnableRGW is true.
	// Default: 8080
	RGWPort int `json:"rgwPort"`
}

// StorageProviders contains provider-specific configurations.
type StorageProviders struct {
	MicroCeph MicroCephProviderConfig `json:"microceph"`
}

// DistributedStorage contains distributed storage configuration.
// This is under GlobalSettings to keep all cluster-wide settings together.
type DistributedStorage struct {
	// Enabled controls whether distributed storage is configured.
	// Default: false
	Enabled bool `json:"enabled"`

	// Type specifies the distributed storage backend: "none", "microceph"
	// Default: "microceph"
	Type DistributedStorageType `json:"type"`

	// ForceRecreation forces teardown and recreation of the storage cluster during deployment.
	// WARNING: This will delete all data in the storage cluster.
	// Default: false
	ForceRecreation bool `json:"forceRecreation"`

	// MountPath is where the distributed storage will be mounted on nodes.
	// Default: "/mnt/distributed-storage"
	MountPath string `json:"mountPath"`

	// PoolName is the name of the storage pool to create.
	// Default: "docker-swarm"
	PoolName string `json:"poolName"`

	// PoolSize is the replication factor for the storage pool.
	// Default: 3 (for 3-way replication)
	PoolSize int `json:"poolSize"`

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

// GlobalSettings contains cluster-wide configuration.
type GlobalSettings struct {
	ClusterName                    string             `json:"clusterName"`                    // Cluster name (required)
	OverlayProvider                string             `json:"overlayProvider"`                // "netbird", "tailscale", "wireguard", "none" (default: "none")
	OverlayConfig                  string             `json:"overlayConfig"`                  // Provider-specific config (e.g., Netbird setup key, Tailscale auth key)
	SetRootPassword                string             `json:"setRootPassword"`                // Set root password on all nodes (optional, empty = no change)
	ServicesDir                    string             `json:"servicesDir"`                    // Directory containing service YAML files (default: "services" relative to binary)
	DistributedStorage             DistributedStorage `json:"distributedStorage"`             // Distributed storage configuration
	PreScripts                     []ScriptConfig     `json:"preScripts"`                     // Scripts to execute before deployment
	PostScripts                    []ScriptConfig     `json:"postScripts"`                    // Scripts to execute after deployment
	RemoveSSHPublicKeyOnCompletion bool               `json:"removeSSHPublicKeyOnCompletion"` // Remove SSH public key from nodes on completion (default: false)
}

// NodeConfig represents a single node's configuration.
type NodeConfig struct {
	// Node Control
	Enabled *bool `json:"enabled"` // Enable this node for deployment (default: true if nil)

	// SSH Connection Settings
	Hostname              string `json:"hostname"`              // Hostname or IP address (required)
	Username              string `json:"username"`              // SSH username (required, default: "root")
	Password              string `json:"password"`              // SSH password (optional, use privateKeyPath instead)
	PrivateKeyPath        string `json:"privateKeyPath"`        // Path to SSH private key (optional, use password instead)
	UseSSHAutomaticKeyPair bool   `json:"useSSHAutomaticKeyPair"` // Use automatically generated SSH key pair (default: false)
	SSHPort               int    `json:"sshPort"`               // SSH port (default: 22)

	// Node Role Settings
	Role string `json:"role"` // "manager" or "worker" (required)

	// System Settings
	NewHostname        string `json:"newHostname"`        // New hostname to set (optional, idempotent)
	RebootOnCompletion bool   `json:"rebootOnCompletion"` // Reboot node after deployment (default: false)

	// Distributed Storage Settings (per-node)
	StorageEnabled bool `json:"storageEnabled"` // Enable distributed storage on this node (default: false)

	// Docker Swarm Settings
	AdvertiseAddr string `json:"advertiseAddr"` // Override auto-detected advertise address for Swarm

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
		if node.Hostname == "" {
			return fmt.Errorf("node %d: hostname is required", i)
		}
		if node.Role != "manager" && node.Role != "worker" {
			return fmt.Errorf("node %d (%s): role must be 'manager' or 'worker'", i, node.Hostname)
		}
		if node.Role == "manager" {
			managerCount++
		}

		// If not using automatic key pair, require password or privateKeyPath
		if !node.UseSSHAutomaticKeyPair && node.Password == "" && node.PrivateKeyPath == "" {
			return fmt.Errorf("node %d (%s): either password, privateKeyPath, or useSSHAutomaticKeyPair must be specified", i, node.Hostname)
		}
	}

	if managerCount == 0 {
		return fmt.Errorf("at least one manager node is required")
	}

	return nil
}

// ApplyDefaults applies default values to the configuration.
func (c *Config) ApplyDefaults() {
	// Global defaults
	if c.GlobalSettings.OverlayProvider == "" {
		c.GlobalSettings.OverlayProvider = "none"
	}

	// DistributedStorage defaults (now under GlobalSettings)
	ds := &c.GlobalSettings.DistributedStorage
	if ds.Type == "" {
		ds.Type = StorageTypeMicroCeph
	}
	if ds.MountPath == "" {
		ds.MountPath = "/mnt/distributed-storage"
	}
	if ds.PoolName == "" {
		ds.PoolName = "docker-swarm"
	}
	if ds.PoolSize == 0 {
		ds.PoolSize = 3
	}

	// MicroCeph provider defaults
	mc := &ds.Providers.MicroCeph
	if mc.SnapChannel == "" {
		mc.SnapChannel = "latest/stable"
	}
	if mc.LoopDeviceCount == 0 {
		mc.LoopDeviceCount = 3
	}
	if mc.LoopDeviceSizeGB == 0 {
		mc.LoopDeviceSizeGB = 4
	}
	if mc.RGWPort == 0 {
		mc.RGWPort = 8080
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
			c.Nodes[i].Username = "root"
		}
		if c.Nodes[i].SSHPort == 0 {
			c.Nodes[i].SSHPort = 22
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
