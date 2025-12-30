// Package nodeconfig provides extensible per-node configuration handlers
// for management panels and firewall configuration.
package nodeconfig

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/config"
	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// loggerInterface defines the logging methods we need.
type loggerInterface interface {
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
}

// NodeConfigurator handles per-node configuration tasks.
type NodeConfigurator struct {
	sshPool *ssh.Pool
	log     loggerInterface
}

// NewNodeConfigurator creates a new node configurator.
func NewNodeConfigurator(sshPool *ssh.Pool) *NodeConfigurator {
	return &NodeConfigurator{
		sshPool: sshPool,
		log:     logging.L().With("component", "nodeconfig"),
	}
}

// ConfigureNode applies all per-node configurations (management panel, firewall, etc.).
func (nc *NodeConfigurator) ConfigureNode(ctx context.Context, node config.NodeConfig) error {
	hostname := node.SSHFQDNorIP

	// Configure Management Panel if enabled
	if node.ManagementPanel.Enabled {
		nc.log.Infow("configuring management panel", "host", hostname, "type", node.ManagementPanel.GetType())
		if err := nc.configureManagementPanel(ctx, node); err != nil {
			return fmt.Errorf("failed to configure management panel on %s: %w", hostname, err)
		}
	}

	// Configure Firewall if enabled
	if node.Firewall.HasFirewallEnabled() {
		nc.log.Infow("configuring firewall", "host", hostname)
		if err := nc.configureFirewall(ctx, node); err != nil {
			return fmt.Errorf("failed to configure firewall on %s: %w", hostname, err)
		}
	}

	return nil
}

// ConfigureAllNodes applies per-node configurations to all enabled nodes.
func (nc *NodeConfigurator) ConfigureAllNodes(ctx context.Context, nodes []config.NodeConfig) error {
	for _, node := range nodes {
		if node.IsEnabled() {
			if err := nc.ConfigureNode(ctx, node); err != nil {
				return err
			}
		}
	}
	return nil
}

// configureManagementPanel installs and configures the specified management panel.
func (nc *NodeConfigurator) configureManagementPanel(ctx context.Context, node config.NodeConfig) error {
	panelType := node.ManagementPanel.GetType()
	hostname := node.SSHFQDNorIP

	switch panelType {
	case config.ManagementPanelWebmin:
		return nc.installWebmin(ctx, hostname)
	case config.ManagementPanel1Panel:
		return nc.install1Panel(ctx, hostname)
	case config.ManagementPanelCockpit:
		return nc.installCockpit(ctx, hostname)
	default:
		nc.log.Warnw("unknown management panel type, defaulting to webmin", "type", panelType)
		return nc.installWebmin(ctx, hostname)
	}
}

// installWebmin installs Webmin on the node.
func (nc *NodeConfigurator) installWebmin(ctx context.Context, hostname string) error {
	nc.log.Infow("installing Webmin", "host", hostname)

	// Check if already installed
	checkCmd := "dpkg -l webmin 2>/dev/null | grep -q '^ii' && echo 'installed' || echo 'not_installed'"
	stdout, _, _ := nc.sshPool.Run(ctx, hostname, checkCmd)
	if strings.TrimSpace(stdout) == "installed" {
		nc.log.Infow("Webmin already installed", "host", hostname)
		return nil
	}

	// Install Webmin using the official setup script
	// The setup-repos.sh requires 'y' input for confirmation, so we pipe echo "y"
	// We also need to install required dependencies first
	installScript := `#!/bin/bash
set -e

# Install required dependencies
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl apt-transport-https gnupg

# Create downloads directory
WEBMINDOWNLOADDIRECTORY="/tmp/webmin-install"
mkdir -p "$WEBMINDOWNLOADDIRECTORY"

# Download and run the repository setup script
WEBMINSCRIPTURL="https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh"
WEBMINSCRIPTFILEPATH="$WEBMINDOWNLOADDIRECTORY/setup-repos.sh"
curl -fsSL -o "$WEBMINSCRIPTFILEPATH" "$WEBMINSCRIPTURL"
chmod +x "$WEBMINSCRIPTFILEPATH"

# Run the setup script with 'y' confirmation (non-interactive)
echo "y" | bash "$WEBMINSCRIPTFILEPATH" 2>&1 || true

# Update package lists after adding repo
apt-get update -qq

# Install Webmin
apt-get install -y --install-recommends webmin

# Enable and start Webmin
systemctl enable webmin
systemctl start webmin

# Cleanup
rm -rf "$WEBMINDOWNLOADDIRECTORY"

echo "Webmin installed successfully"
`
	if _, stderr, err := nc.sshPool.Run(ctx, hostname, installScript); err != nil {
		return fmt.Errorf("webmin installation failed: %w (stderr: %s)", err, stderr)
	}

	nc.log.Infow("Webmin installed successfully", "host", hostname, "accessUrl", fmt.Sprintf("https://%s:10000", hostname))
	return nil
}

// install1Panel installs 1Panel on the node.
func (nc *NodeConfigurator) install1Panel(ctx context.Context, hostname string) error {
	nc.log.Infow("installing 1Panel", "host", hostname)

	// Check if already installed
	checkCmd := "which 1pctl && echo 'installed' || echo 'not_installed'"
	stdout, _, _ := nc.sshPool.Run(ctx, hostname, checkCmd)
	if stdout == "installed\n" || stdout == "installed" {
		nc.log.Infow("1Panel already installed", "host", hostname)
		return nil
	}

	// Install 1Panel using official script
	installScript := `#!/bin/bash
set -e

# Install 1Panel using official installer
curl -fsSL https://resource.1panel.hk/quick_start.sh | bash

echo "1Panel installed successfully"
`
	if _, stderr, err := nc.sshPool.Run(ctx, hostname, installScript); err != nil {
		return fmt.Errorf("1panel installation failed: %w (stderr: %s)", err, stderr)
	}

	nc.log.Infow("1Panel installed successfully", "host", hostname)
	return nil
}

// installCockpit installs Cockpit on the node.
func (nc *NodeConfigurator) installCockpit(ctx context.Context, hostname string) error {
	nc.log.Infow("installing Cockpit", "host", hostname)

	// Check if already installed
	checkCmd := "which cockpit-ws && echo 'installed' || echo 'not_installed'"
	stdout, _, _ := nc.sshPool.Run(ctx, hostname, checkCmd)
	if stdout == "installed\n" || stdout == "installed" {
		nc.log.Infow("Cockpit already installed", "host", hostname)
		return nil
	}

	// Install Cockpit
	installScript := `#!/bin/bash
set -e

# Install Cockpit
apt-get update -qq
apt-get install -y cockpit

# Enable and start Cockpit
systemctl enable --now cockpit.socket

echo "Cockpit installed successfully"
`
	if _, stderr, err := nc.sshPool.Run(ctx, hostname, installScript); err != nil {
		return fmt.Errorf("cockpit installation failed: %w (stderr: %s)", err, stderr)
	}

	nc.log.Infow("Cockpit installed successfully", "host", hostname)
	return nil
}

