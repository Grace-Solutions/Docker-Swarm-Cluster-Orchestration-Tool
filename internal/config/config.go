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
}

// ScriptConfig represents a script to execute on nodes.
type ScriptConfig struct {
	Enabled    bool   `json:"enabled"`    // Enable this script (default: true)
	Name       string `json:"name"`       // Script name/description
	Source     string `json:"source"`     // Local path or http/https URL
	Parameters string `json:"parameters"` // Script parameters/arguments
}

// GlobalSettings contains cluster-wide configuration.
type GlobalSettings struct {
	ClusterName              string         `json:"clusterName"`              // Cluster name (required)
	OverlayProvider          string         `json:"overlayProvider"`          // "netbird", "tailscale", "wireguard", "none" (default: "none")
	OverlayConfig            string         `json:"overlayConfig"`            // Provider-specific config (e.g., Netbird setup key, Tailscale auth key)
	GlusterVolume                  string         `json:"glusterVolume"`                  // GlusterFS volume name (default: "docker-swarm-0001")
	GlusterMount                   string         `json:"glusterMount"`                   // GlusterFS mount path (default: "/mnt/GlusterFS/Docker/Swarm/0001/data")
	GlusterBrick                   string         `json:"glusterBrick"`                   // GlusterFS brick path (default: "/mnt/GlusterFS/Docker/Swarm/0001/brick")
	GlusterDiskManagement          bool           `json:"glusterDiskManagement"`          // Enable automatic disk detection, formatting, and mounting (default: false, uses OS disk folders)
	SetRootPassword                string         `json:"setRootPassword"`                // Set root password on all nodes (optional, empty = no change)
	ServicesDir                    string         `json:"servicesDir"`                    // Directory containing service YAML files (default: "services" relative to binary)
	PreScripts                     []ScriptConfig `json:"preScripts"`                     // Scripts to execute before deployment
	PostScripts                    []ScriptConfig `json:"postScripts"`                    // Scripts to execute after deployment
	RemoveSSHPublicKeyOnCompletion bool           `json:"removeSSHPublicKeyOnCompletion"` // Remove SSH public key from nodes on completion (default: false)
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

	// GlusterFS Settings (per-node overrides)
	GlusterEnabled bool   `json:"glusterEnabled"` // Enable GlusterFS on this node (workers only)
	GlusterMount   string `json:"glusterMount"`   // Override global glusterMount for this node
	GlusterBrick   string `json:"glusterBrick"`   // Override global glusterBrick for this node

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
		if node.GlusterEnabled && node.Role != "worker" {
			return fmt.Errorf("node %d (%s): glusterEnabled can only be set on workers", i, node.Hostname)
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
	if c.GlobalSettings.GlusterVolume == "" {
		c.GlobalSettings.GlusterVolume = "docker-swarm-0001"
	}
	if c.GlobalSettings.GlusterMount == "" {
		c.GlobalSettings.GlusterMount = "/mnt/GlusterFS/Docker/Swarm/0001/data"
	}
	if c.GlobalSettings.GlusterBrick == "" {
		c.GlobalSettings.GlusterBrick = "/mnt/GlusterFS/Docker/Swarm/0001/brick"
	}

	// Script defaults
	for i := range c.GlobalSettings.PreScripts {
		if !c.GlobalSettings.PreScripts[i].Enabled {
			c.GlobalSettings.PreScripts[i].Enabled = true
		}
	}
	for i := range c.GlobalSettings.PostScripts {
		if !c.GlobalSettings.PostScripts[i].Enabled {
			c.GlobalSettings.PostScripts[i].Enabled = true
		}
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

		// GlusterFS defaults (inherit from global if not set)
		if c.Nodes[i].GlusterMount == "" {
			c.Nodes[i].GlusterMount = c.GlobalSettings.GlusterMount
		}
		if c.Nodes[i].GlusterBrick == "" {
			c.Nodes[i].GlusterBrick = c.GlobalSettings.GlusterBrick
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

// GetEffectiveGlusterMount returns the effective GlusterFS mount path for a node.
func (n *NodeConfig) GetEffectiveGlusterMount(globalMount string) string {
	if n.GlusterMount != "" {
		return n.GlusterMount
	}
	return globalMount
}

// GetEffectiveGlusterBrick returns the effective GlusterFS brick path for a node.
func (n *NodeConfig) GetEffectiveGlusterBrick(globalBrick string) string {
	if n.GlusterBrick != "" {
		return n.GlusterBrick
	}
	return globalBrick
}

