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

- **Global settings**: Cluster name, overlay provider, GlusterFS paths, Portainer settings
- **Node definitions**: SSH connection details, roles (manager/worker), hostnames, labels
- **Scripts**: Pre/post deployment scripts (optional)

The tool will:
1. SSH into each node
2. Install dependencies (Docker, overlay provider, GlusterFS)
3. Configure Docker Swarm with managers and workers
4. Set up GlusterFS distributed storage (if enabled)
5. Deploy Portainer (if enabled)
6. Apply custom labels for service placement

## SSH Key Management

The tool automatically generates and manages ED25519 SSH keys:

- Keys are stored in `sshkeys/yyyy.MM.dd.HHmm/` next to the binary
- Existing keys are reused across deployments
- Keys are never deleted (kept for future use)
- Per-node control via `useSSHAutomaticKeyPair` setting

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
