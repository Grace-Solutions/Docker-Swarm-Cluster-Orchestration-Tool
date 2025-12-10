# Binaries

This directory contains pre-built `dscotctl` (Docker Swarm Cluster Orchestration Tool Control) binaries for Linux, macOS, and Windows.

## Available Binaries

- **`dscotctl-linux-amd64`**: Linux binary for x86_64 / amd64 systems
- **`dscotctl-linux-arm64`**: Linux binary for aarch64 / arm64 systems
- **`dscotctl-darwin-amd64`**: macOS binary for Intel systems
- **`dscotctl-darwin-arm64`**: macOS binary for Apple Silicon (M1/M2/M3)
- **`dscotctl-windows-amd64.exe`**: Windows binary for x86_64 / amd64 systems

All binaries are:
- ✅ **Statically linked** (CGO_ENABLED=0) - no external dependencies
- ✅ **Self-contained** - no runtime requirements beyond OS kernel
- ✅ **Cross-platform** - run from any machine with SSH access to target nodes
- ✅ **Version embedded** - run with `-version` to see build info

## Usage

### Linux / macOS

``bash
# Deploy cluster from configuration file
./dscotctl-linux-amd64 -config dscotctl.json

# Validate configuration without deploying
./dscotctl-linux-amd64 -config dscotctl.json -dry-run

# Show version
./dscotctl-linux-amd64 -version

# Show help
./dscotctl-linux-amd64 -help
``

### Windows

``powershell
# Deploy cluster from configuration file
.\dscotctl-windows-amd64.exe -config dscotctl.json

# Validate configuration without deploying
.\dscotctl-windows-amd64.exe -config dscotctl.json -dry-run

# Show version
.\dscotctl-windows-amd64.exe -version

# Show help
.\dscotctl-windows-amd64.exe -help
``

## Configuration

Create a JSON configuration file (see `dscotctl.json.example` in this directory) that defines:

- **Global settings**: Cluster name, overlay provider, distributed storage, scripts
- **Node definitions**: SSH connection details, roles (manager/worker), hostnames, labels
- **Scripts**: Pre/post deployment scripts with conditional execution (optional)

The tool will:
1. SSH into each node
2. Install dependencies (Docker, overlay provider, MicroCeph)
3. Configure Docker Swarm with managers and workers
4. Set up MicroCeph distributed storage with CephFS (if enabled)
5. Execute pre/post deployment scripts (if configured)
6. Apply custom labels for service placement

### MicroCeph Disk Management

MicroCeph uses disk selection with regex-based inclusion/exclusion patterns:

**Configuration:**
```json
{
  "globalSettings": {
    "distributedStorage": {
      "enabled": true,
      "provider": "microceph",
      "providers": {
        "microceph": {
          "eligibleDisks": {
            "inclusionExpression": ["^/dev/sd[b-z]$", "^/dev/nvme[0-9]n1$"],
            "exclusionExpression": ["^/dev/sda$", "^/dev/vda$"]
          },
          "allowLoopDevices": true,
          "loopDeviceSizeGB": 16
        }
      }
    }
  }
}
```

**Disk Selection Logic:**
1. All disks → Apply Inclusion Filter (OR) → Included Disks
2. Included Disks → Apply Exclusion Filter (OR) → Eligible Disks

- **Inclusion (OR)**: Disk passes if it matches ANY inclusion pattern
- **Exclusion (OR)**: Disk dropped if it matches ANY exclusion pattern

**Loop Devices:**
- When `allowLoopDevices: true` and no physical disks are available
- Creates a loop device of `loopDeviceSizeGB` size
- Useful for testing and development environments

### Script Conditional Execution

Pre and post deployment scripts support conditional execution based on node properties. This allows you to run scripts only on specific nodes (e.g., workers only, managers only, specific hostnames, custom labels).

**Script Fields:**
- `enabled` - Must be `true` for script to execute (default: `false`)
- `continueOnError` - If `true`, deployment continues even if script fails (default: `false`)
- `name` - Script name/description for logging
- `source` - Local file path or HTTP/HTTPS URL
- `parameters` - Command-line arguments to pass to the script
- `conditions` - Array of conditions (all must match, empty = run on all nodes)

**Supported Properties:**
- `role` - Node role (manager/worker)
- `hostname` - Node hostname
- `username` - SSH username
- `newHostname` - New hostname to set
- `storageEnabled` - Distributed storage enabled (true/false)
- `rebootOnCompletion` - Reboot on completion (true/false)
- `scriptsEnabled` - Scripts enabled (true/false)
- `useSSHAutomaticKeyPair` - Use automatic key pair (true/false)
- `enabled` - Node enabled (true/false)
- `sshPort` - SSH port number
- `advertiseAddr` - Advertise address
- `label.<key>` - Custom label value (e.g., `label.environment`)

**Supported Operators:**
- `=` or `==` or `equals` - Case-insensitive equality
- `!=` or `notequals` - Case-insensitive inequality
- `regex` or `matches` - Case-insensitive regex match
- `!regex` or `notmatches` - Case-insensitive regex non-match

**Negate Field:**
- `negate: false` (default) - Use condition result as-is
- `negate: true` - Flip the condition result (NOT logic)
- Works with any operator for flexible logic

**Condition Logic:**
- Empty conditions array = run on all nodes
- Multiple conditions = ALL must match (AND logic)
- Use `negate: true` to invert any condition

**Examples:**

```json
{
  "preScripts": [
    {
      "enabled": true,
      "continueOnError": false,
      "name": "critical-pre-check",
      "source": "https://example.com/pre-check.sh",
      "parameters": "--strict",
      "conditions": []
    },
    {
      "enabled": true,
      "continueOnError": true,
      "name": "worker-only-script",
      "source": "https://example.com/worker-setup.sh",
      "parameters": "",
      "conditions": [
        { "property": "role", "operator": "=", "value": "worker", "negate": false }
      ]
    },
    {
      "enabled": true,
      "name": "non-manager-nodes",
      "source": "https://example.com/non-manager-setup.sh",
      "parameters": "",
      "conditions": [
        { "property": "role", "operator": "=", "value": "manager", "negate": true }
      ]
    },
    {
      "enabled": true,
      "name": "production-managers",
      "source": "https://example.com/prod-manager-setup.sh",
      "parameters": "",
      "conditions": [
        { "property": "role", "operator": "=", "value": "manager", "negate": false },
        { "property": "label.environment", "operator": "=", "value": "production", "negate": false }
      ]
    },
    {
      "enabled": true,
      "name": "vps-nodes-regex",
      "source": "https://example.com/vps-setup.sh",
      "parameters": "",
      "conditions": [
        { "property": "hostname", "operator": "regex", "value": "^vps-.*", "negate": false }
      ]
    },
    {
      "enabled": true,
      "name": "non-vps-nodes",
      "source": "https://example.com/non-vps-setup.sh",
      "parameters": "",
      "conditions": [
        { "property": "hostname", "operator": "regex", "value": "^vps-.*", "negate": true }
      ]
    }
  ]
}
```

### Root Password Management

The `setRootPassword` parameter allows you to set a consistent root password across all nodes:

- **Empty string `""` (default)**: No password change
  - ✅ Leaves existing root passwords unchanged
  - ✅ Safe for nodes with existing password policies

- **Non-empty string**: Sets root password on all nodes
  - ✅ Ensures consistent root access across cluster
  - ✅ Useful for standardizing credentials
  - ✅ Applied early in deployment (Phase 2.5, after hostname setting)
  - ⚠️ Password is stored in plain text in JSON config
  - ⚠️ Ensure config file has appropriate permissions (chmod 600)

**Example:**
```json
{
  "globalSettings": {
    "setRootPassword": "YourSecurePasswordHere"
  }
}
```

**Security recommendations:**
- Use strong, unique passwords
- Protect config file: `chmod 600 dscotctl.json`
- Consider using SSH keys instead of passwords for authentication
- Rotate passwords regularly
- Use a password manager or secrets management system

## SSH Key Management

The tool automatically generates and manages ED25519 SSH keys for passwordless authentication:

### How It Works

1. **Key Generation**: Tool always generates an SSH key pair (stored in `sshkeys/yyyy.MM.dd.HHmm/`)
2. **Key Installation**: Public key is installed to `~/.ssh/authorized_keys` for the configured username
3. **Authentication Priority** (per node):
   - If `useSSHAutomaticKeyPair: true` → Uses generated key (overrides password/privateKeyPath)
   - Else if `privateKeyPath` is set → Uses that private key
   - Else → Uses password authentication

### Key Features

- ✅ Keys stored in `sshkeys/yyyy.MM.dd.HHmm/` next to the binary
- ✅ Existing keys are reused across deployments
- ✅ Keys are never deleted (kept for future use)
- ✅ Public key installed on **all nodes** (even those using password initially)
- ✅ Enables passwordless SSH for future operations
- ✅ Maps to the `username` specified in node config (e.g., `root`, `ubuntu`, etc.)

### Important Notes

**Root Access Required:**
- All nodes must have root privileges (either direct `root` user or passwordless `sudo`)
- Commands like `hostnamectl`, `chpasswd`, Docker, and MicroCeph require root access
- If using non-root user (e.g., `ubuntu`), ensure passwordless sudo is configured

**SSH Key User Mapping:**
- Public key is installed for the `username` specified in node config
- Example: If `username: "ubuntu"`, key authenticates as `ubuntu` user
- Example: If `username: "root"`, key authenticates as `root` user

## Examples

**Basic deployment:**
``bash
./dscotctl-linux-amd64 -config production.json
``

**Test configuration:**
``bash
./dscotctl-linux-amd64 -config staging.json -dry-run
``

**Deploy from Windows to Linux nodes:**
``powershell
.\dscotctl-windows-amd64.exe -config cluster.json
``

## Repository Clone Command

``bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Orchestration-Tool.git && \
  cd ./Docker-Swarm-Cluster-Orchestration-Tool && \
  chmod -R -v +x ./
``
