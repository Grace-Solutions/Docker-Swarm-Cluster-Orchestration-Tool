# Binaries

This directory contains pre-built `clusterctl` binaries for Linux (amd64 and arm64) and Windows (amd64).

## Available Binaries

- **`clusterctl-linux-amd64`**: Linux binary for x86_64 / amd64 systems
- **`clusterctl-linux-arm64`**: Linux binary for aarch64 / arm64 systems  
- **`clusterctl-windows-amd64.exe`**: Windows binary for x86_64 / amd64 systems

All binaries are:
- ✅ **Statically linked** (CGO_ENABLED=0) - no external dependencies
- ✅ **Self-contained** - no runtime requirements beyond OS kernel
- ✅ **Cross-platform** - run from any machine with SSH access to target nodes

## Usage

### Linux

``bash
# Deploy cluster from configuration file
./clusterctl-linux-amd64 -config clusterctl.json

# Validate configuration without deploying
./clusterctl-linux-amd64 -config clusterctl.json -dry-run

# Show help
./clusterctl-linux-amd64 -help
``

### Windows

``powershell
# Deploy cluster from configuration file
.\clusterctl-windows-amd64.exe -config clusterctl.json

# Validate configuration without deploying
.\clusterctl-windows-amd64.exe -config clusterctl.json -dry-run

# Show help
.\clusterctl-windows-amd64.exe -help
``

## Configuration

Create a JSON configuration file (see `clusterctl.json.example` in this directory) that defines:

- **Global settings**: Cluster name, overlay provider, GlusterFS paths, scripts
- **Node definitions**: SSH connection details, roles (manager/worker), hostnames, labels
- **Scripts**: Pre/post deployment scripts with conditional execution (optional)

The tool will:
1. SSH into each node
2. Install dependencies (Docker, overlay provider, GlusterFS)
3. Configure Docker Swarm with managers and workers
4. Set up GlusterFS distributed storage (if enabled)
5. Execute pre/post deployment scripts (if configured)
6. Apply custom labels for service placement

### GlusterFS Disk Management

The `glusterDiskManagement` parameter controls how GlusterFS bricks are created:

- **`false` (default)**: Uses OS disk folders (e.g., `/mnt/gluster-brick1`)
  - ✅ Simple setup - no additional disks required
  - ✅ Works on any system
  - ⚠️ Not recommended for production (performance, capacity)
  - ✅ Perfect for testing, development, home labs

- **`true`**: Automatically detects, formats, and mounts dedicated disks
  - ✅ Production-ready - dedicated storage for GlusterFS
  - ✅ Formats disks with XFS (inode size 512 as recommended)
  - ✅ Adds to /etc/fstab for persistence
  - ✅ Automatically excludes nodes without available disks
  - ⚠️ Requires at least one non-OS disk on worker nodes
  - ℹ️ Workers without available disks are excluded from GlusterFS cluster

**Example:**
```json
{
  "globalSettings": {
    "glusterBrick": "/mnt/gluster-brick1",
    "glusterDiskManagement": true
  }
}
```

When `glusterDiskManagement: true`:
- Tool detects available non-OS disks on each worker
- Formats first available disk with XFS
- Mounts at `glusterBrick` path
- Adds to /etc/fstab for automatic mounting on reboot
- Workers without disks are automatically excluded (no errors)

### Script Conditional Execution

Pre and post deployment scripts support conditional execution based on node properties. This allows you to run scripts only on specific nodes (e.g., workers only, managers only, specific hostnames, custom labels).

**Supported Properties:**
- `role` - Node role (manager/worker)
- `hostname` - Node hostname
- `username` - SSH username
- `newHostname` - New hostname to set
- `glusterEnabled` - GlusterFS enabled (true/false)
- `rebootOnCompletion` - Reboot on completion (true/false)
- `scriptsEnabled` - Scripts enabled (true/false)
- `useSSHAutomaticKeyPair` - Use automatic key pair (true/false)
- `enabled` - Node enabled (true/false)
- `sshPort` - SSH port number
- `advertiseAddr` - Advertise address
- `glusterMount` - GlusterFS mount path
- `glusterBrick` - GlusterFS brick path
- `label.<key>` - Custom label value (e.g., `label.environment`)

**Supported Operators:**
- `=` or `==` or `equals` - Case-insensitive equality
- `!=` or `notequals` - Case-insensitive inequality
- `regex` or `matches` - Case-insensitive regex match
- `!regex` or `notmatches` - Case-insensitive regex non-match

**Condition Logic:**
- Empty conditions array = run on all nodes
- Multiple conditions = ALL must match (AND logic)

**Examples:**

```json
{
  "preScripts": [
    {
      "enabled": true,
      "name": "worker-only-script",
      "source": "https://example.com/worker-setup.sh",
      "parameters": "",
      "conditions": [
        {
          "property": "role",
          "operator": "=",
          "value": "worker"
        }
      ]
    },
    {
      "enabled": true,
      "name": "production-managers",
      "source": "https://example.com/prod-manager-setup.sh",
      "parameters": "",
      "conditions": [
        {
          "property": "role",
          "operator": "=",
          "value": "manager"
        },
        {
          "property": "label.environment",
          "operator": "=",
          "value": "production"
        }
      ]
    },
    {
      "enabled": true,
      "name": "vps-nodes-regex",
      "source": "https://example.com/vps-setup.sh",
      "parameters": "",
      "conditions": [
        {
          "property": "hostname",
          "operator": "regex",
          "value": "^vps-.*"
        }
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
- Protect config file: `chmod 600 clusterctl.json`
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
- Commands like `hostnamectl`, `chpasswd`, Docker, and GlusterFS require root access
- If using non-root user (e.g., `ubuntu`), ensure passwordless sudo is configured

**SSH Key User Mapping:**
- Public key is installed for the `username` specified in node config
- Example: If `username: "ubuntu"`, key authenticates as `ubuntu` user
- Example: If `username: "root"`, key authenticates as `root` user

## Examples

**Basic deployment:**
``bash
./clusterctl-linux-amd64 -config production.json
``

**Test configuration:**
``bash
./clusterctl-linux-amd64 -config staging.json -dry-run
``

**Deploy from Windows to Linux nodes:**
``powershell
.\clusterctl-windows-amd64.exe -config cluster.json
``

## Repository Clone Command

``bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && \
  cd ./Docker-Swarm-Cluster-Configuration-Service && \
  chmod -R -v +x ./
``
