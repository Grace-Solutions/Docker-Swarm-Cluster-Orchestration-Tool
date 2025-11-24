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

// GlobalSettings contains cluster-wide configuration.
type GlobalSettings struct {
	ClusterName       string `json:"clusterName"`       // Cluster name (required)
	OverlayProvider   string `json:"overlayProvider"`   // "netbird", "tailscale", "wireguard", "none" (default: "none")
	GlusterVolume     string `json:"glusterVolume"`     // GlusterFS volume name (default: "docker-swarm-0001")
	GlusterMount      string `json:"glusterMount"`      // GlusterFS mount path (default: "/mnt/GlusterFS/Docker/Swarm/0001/data")
	GlusterBrick      string `json:"glusterBrick"`      // GlusterFS brick path (default: "/mnt/GlusterFS/Docker/Swarm/0001/brick")
	DeployPortainer   bool   `json:"deployPortainer"`   // Deploy Portainer after setup (default: true)
	PortainerPassword string `json:"portainerPassword"` // Portainer admin password (default: auto-generated)
}

// NodeConfig represents a single node's configuration.
type NodeConfig struct {
	// SSH Connection Settings
	Hostname       string `json:"hostname"`       // Hostname or IP address (required)
	Username       string `json:"username"`       // SSH username (required, default: "root")
	Password       string `json:"password"`       // SSH password (optional, use privateKeyPath instead)
	PrivateKeyPath string `json:"privateKeyPath"` // Path to SSH private key (optional, use password instead)
	SSHPort        int    `json:"sshPort"`        // SSH port (default: 22)

	// Node Role Settings
	PrimaryMaster bool   `json:"primaryMaster"` // Is this the primary master? (exactly one required)
	Role          string `json:"role"`          // "manager" or "worker" (required)

	// Overlay Network Settings (per-node overrides)
	OverlayProvider string `json:"overlayProvider"` // Override global overlayProvider for this node
	OverlayConfig   string `json:"overlayConfig"`   // Provider-specific config (e.g., Netbird setup key, Tailscale auth key)

	// GlusterFS Settings (per-node overrides)
	GlusterEnabled bool   `json:"glusterEnabled"` // Enable GlusterFS on this node (workers only)
	GlusterMount   string `json:"glusterMount"`   // Override global glusterMount for this node
	GlusterBrick   string `json:"glusterBrick"`   // Override global glusterBrick for this node

	// Docker Swarm Settings
	AdvertiseAddr string `json:"advertiseAddr"` // Override auto-detected advertise address for Swarm
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

	primaryMasterCount := 0
	for i, node := range c.Nodes {
		if node.Hostname == "" {
			return fmt.Errorf("node %d: hostname is required", i)
		}
		if node.Role != "manager" && node.Role != "worker" {
			return fmt.Errorf("node %d (%s): role must be 'manager' or 'worker'", i, node.Hostname)
		}
		if node.PrimaryMaster {
			primaryMasterCount++
			if node.Role != "manager" {
				return fmt.Errorf("node %d (%s): primaryMaster must be a manager", i, node.Hostname)
			}
		}
		if node.GlusterEnabled && node.Role != "worker" {
			return fmt.Errorf("node %d (%s): glusterEnabled can only be set on workers", i, node.Hostname)
		}
		if node.Password == "" && node.PrivateKeyPath == "" {
			return fmt.Errorf("node %d (%s): either password or privateKeyPath must be specified", i, node.Hostname)
		}
	}

	if primaryMasterCount != 1 {
		return fmt.Errorf("exactly one node must be marked as primaryMaster (found %d)", primaryMasterCount)
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

	// Node defaults
	for i := range c.Nodes {
		// SSH defaults
		if c.Nodes[i].Username == "" {
			c.Nodes[i].Username = "root"
		}
		if c.Nodes[i].SSHPort == 0 {
			c.Nodes[i].SSHPort = 22
		}

		// Overlay defaults (inherit from global if not set)
		if c.Nodes[i].OverlayProvider == "" {
			c.Nodes[i].OverlayProvider = c.GlobalSettings.OverlayProvider
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

// GetEffectiveOverlayProvider returns the effective overlay provider for a node.
func (n *NodeConfig) GetEffectiveOverlayProvider(globalProvider string) string {
	if n.OverlayProvider != "" {
		return n.OverlayProvider
	}
	return globalProvider
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

