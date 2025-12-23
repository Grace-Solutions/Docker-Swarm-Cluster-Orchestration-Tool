# Docker Swarm Cluster Orchestration Tool

`dscotctl` (Docker Swarm Cluster Orchestration Tool Control) is a Go-based orchestrator that automates Docker Swarm cluster deployment, management, and teardown with MicroCeph distributed storage integration via SSH.

## Features

- ✅ **Automated Deployment** - Deploy complete Docker Swarm clusters from JSON configuration
- ✅ **SSH-Based Orchestration** - Server-initiated connections, no agents required
- ✅ **MicroCeph Integration** - Distributed storage with CephFS and optional S3 (RADOS Gateway)
- ✅ **Overlay Networking** - Support for Netbird, Tailscale, and WireGuard
- ✅ **Service Deployment** - Generic YAML-based service deployment system
- ✅ **Teardown/Reset** - Clean cluster removal with optional data preservation
- ✅ **Geolocation Detection** - Automatic region detection and node labeling

## Deployment & Teardown Flow

```mermaid
graph TB
    Start([Start]) --> Config[Load Configuration]
    Config --> Deploy{Deploy or Teardown?}

    Deploy -->|Deploy| SSH1[Phase 1: SSH Setup]
    SSH1 --> Hostname[Phase 2: Set Hostnames]
    Hostname --> PreScript[Phase 3: Pre-Scripts]
    PreScript --> Deps[Phase 4: Install Dependencies]
    Deps --> Overlay[Phase 5: Overlay Network]
    Overlay --> Storage[Phase 6: MicroCeph Setup]
    Storage --> Swarm[Phase 7: Docker Swarm]
    Swarm --> Labels[Phase 8: Geolocation & Labels]
    Labels --> Services[Phase 9: Deploy Services]
    Services --> PostScript[Phase 10: Post-Scripts]
    PostScript --> Reboot[Phase 11: Reboot Nodes]
    Reboot --> Complete1([✅ Deployment Complete])

    Deploy -->|Teardown| SSH2[Phase 1: SSH Setup]
    SSH2 --> RemoveStacks[Phase 2: Remove Stacks]
    RemoveStacks --> LeaveSwarm[Phase 3: Leave Swarm]
    LeaveSwarm --> TeardownStorage[Phase 4: Teardown MicroCeph]
    TeardownStorage --> NetworkDecision{Remove Networks?}
    NetworkDecision -->|Yes| RemoveNetworks[Phase 5: Remove Networks]
    NetworkDecision -->|No| SkipNetworks[Phase 5: Skip Networks]
    RemoveNetworks --> Complete2([✅ Teardown Complete])
    SkipNetworks --> Complete2

    style Start fill:#90EE90
    style Complete1 fill:#90EE90
    style Complete2 fill:#FFB6C1
    style Deploy fill:#87CEEB
    style DataDecision fill:#FFD700
    style NetworkDecision fill:#FFD700
```

## Quick Start

### Deploy a Cluster

```bash
# 1. Create a configuration file (see binaries/dscotctl.json.example)
cp binaries/dscotctl.json.example dscotctl.json

# 2. Edit the configuration with your nodes and credentials
nano dscotctl.json

# 3. Deploy the cluster
./binaries/dscotctl-linux-amd64 -config dscotctl.json
```

### Teardown a Cluster

```bash
# Teardown cluster (keeps networks and data for connectivity)
./binaries/dscotctl-linux-amd64 -config dscotctl.json -teardown

# Full teardown (removes everything including data - WARNING: destructive)
./binaries/dscotctl-linux-amd64 -config dscotctl.json -teardown -remove-overlays
```

### Deployment Phases

When you run `dscotctl -config dscotctl.json`, the following phases execute:

1. **Phase 1**: SSH Connection Pool - Establish SSH connections to all nodes
2. **Phase 2**: Set Hostnames - Idempotently set new hostnames (if configured)
3. **Phase 3**: Pre-Deployment Scripts - Execute custom scripts before setup
4. **Phase 4**: Install Dependencies - Install Docker, overlay provider, MicroCeph
5. **Phase 5**: Configure Overlay Network - Setup VPN mesh (Netbird/Tailscale/WireGuard)
6. **Phase 6**: Setup MicroCeph - Create distributed storage cluster with CephFS
7. **Phase 7**: Setup Docker Swarm - Initialize swarm and join nodes
8. **Phase 8**: Detect Geolocation & Apply Labels - Auto-detect region and apply all labels
9. **Phase 9**: Deploy Services - Deploy services from `binaries/services/` folder
10. **Phase 10**: Post-Deployment Scripts - Execute custom scripts after setup
11. **Phase 11**: Reboot Nodes - Gracefully reboot nodes (if configured)
12. **Phase 12**: SSH Key Cleanup - Remove SSH keys from nodes (if configured)

### Teardown Phases

When you run `dscotctl -config dscotctl.json -teardown`, the following phases execute:

1. **Phase 1**: SSH Connection Pool - Establish SSH connections to all nodes
2. **Phase 2**: Remove Stacks - Remove all deployed Docker stacks
3. **Phase 3**: Leave Swarm - All nodes leave the Docker Swarm
4. **Phase 4**: Teardown MicroCeph - Unmount CephFS and optionally remove storage
5. **Phase 5**: Remove Networks (Optional) - Remove overlay networks (`-remove-overlays`)

**Key Features:**
- ✅ **Parallel execution** - All nodes configured simultaneously for speed
- ✅ **Idempotent** - Safe to re-run, only changes what's needed
- ✅ **Automatic detection** - Geolocation, overlay IPs, and advertise addresses
- ✅ **No primary master required** - Deploy from any control server
- ✅ **Comprehensive labeling** - Automatic geo + infrastructure + custom labels

### Configuration File Format

See `binaries/dscotctl.json.example` for a complete example. The configuration has two main sections:

#### Global Settings

```json
{
  "globalSettings": {
    "clusterName": "production-swarm",
    "overlayProvider": "netbird",
    "overlayConfig": "your-netbird-setup-key-here",
    "serviceDefinitionDirectory": "",
    "removeSSHPublicKeyOnCompletion": false,
    "distributedStorage": {
      "enabled": true,
      "provider": "microceph",
      "poolName": "docker-swarm-0001",
      "providers": {
        "microceph": {
          "snapChannel": "squid/stable",
          "mountPath": "/mnt/MicroCephFS/docker-swarm-0001",
          "allowLoopDevices": true,
          "loopDeviceSizeGB": 16
        }
      }
    },
    "preScripts": [],
    "postScripts": []
  }
}
```

- `clusterName`: Name of the Docker Swarm cluster (required)
- `overlayProvider`: **Global** overlay network provider: `netbird`, `tailscale`, `wireguard`, or `none` (default: `none`)
  - **Note**: All nodes must use the same overlay provider as they need to communicate in the same network
- `overlayConfig`: Provider-specific configuration (applies to all nodes):
  - **Netbird**: Setup key (e.g., `NB_SETUP_KEY`)
  - **Tailscale**: Auth key (e.g., `TS_AUTHKEY`)
  - **WireGuard**: Interface name or config path (e.g., `wg0` or `/etc/wireguard/wg0.conf`)
- `sshKeyType`: SSH key type for auto-generation: `ed25519` (default, recommended) or `rsa` (for compatibility with older systems)
- `serviceDefinitionDirectory`: Directory containing service definition YAML files (default: `services` relative to binary)
- `removeSSHPublicKeyOnCompletion`: Remove SSH public key from nodes on deployment completion (default: `false`)
  - **Note**: Only affects nodes using `useSSHAutomaticKeyPair=true`
  - When `false` (default): SSH public key remains installed on nodes for future deployments
  - When `true`: SSH public key is removed from nodes' `~/.ssh/authorized_keys` after deployment completes
  - **Important**: Local private key is always kept in timestamped folders for future use
- `distributedStorage`: MicroCeph distributed storage configuration (see example config for full options)
- `preScripts`: Array of scripts to execute **before** deployment on all nodes
- `postScripts`: Array of scripts to execute **after** deployment on all nodes

**Script Configuration:**
- `enabled`: Enable/disable this script (default: `true`)
- `name`: Script name/description
- `source`: Script source - can be:
  - **HTTP/HTTPS URL**: Downloaded and executed (e.g., `https://example.com/script.sh`)
  - **Local path**: Transferred via SSH and executed (not yet implemented)
- `parameters`: Command-line parameters to pass to the script

#### Per-Node Configuration

Each node supports extensive per-node configuration with overrides:

```json
{
  "nodes": [
    {
      "hostname": "manager1.example.com",
      "newHostname": "swarm-manager-01",
      "username": "root",
      "password": "",
      "privateKeyPath": "",
      "useSSHAutomaticKeyPair": true,
      "sshPort": 22,
      "role": "manager",
      "rebootOnCompletion": false,
      "storageEnabled": true,
      "advertiseAddr": "",
      "scriptsEnabled": true,
      "labels": {
        "environment": "production",
        "customer": "acme-corp"
      }
    },
    {
      "hostname": "worker1.example.com",
      "newHostname": "swarm-worker-01",
      "username": "admin",
      "password": "your-password",
      "useSSHAutomaticKeyPair": false,
      "sshPort": 2222,
      "role": "worker",
      "rebootOnCompletion": true,
      "storageEnabled": true,
      "scriptsEnabled": true,
      "labels": {
        "environment": "production",
        "gpu": "nvidia-a100"
      }
    }
  ]
}
```

**SSH Connection Settings:**
- `hostname`: Hostname or IP address (required)
- `username`: SSH username per node (default: `root`)
- `password`: SSH password (use this OR `privateKeyPath` OR `useSSHAutomaticKeyPair`)
- `privateKeyPath`: Path to SSH private key (use this OR `password` OR `useSSHAutomaticKeyPair`)
- `useSSHAutomaticKeyPair`: Use automatically generated SSH key pair (default: `false`)
  - When `true`: Uses auto-generated key from `sshkeys/` directory (generated once, reused across deployments)
  - When `false`: Connects with `password` or `privateKeyPath` and installs the auto-generated public key for future use
  - **Key Type**: Controlled by `globalSettings.sshKeyType` - `ed25519` (default) or `rsa` (4096-bit for compatibility)
  - **Key Generation**: New key pair is generated **only when**:
    - The `sshkeys/` directory doesn't exist, OR
    - The `sshkeys/` directory is empty (no UUID folders), OR
    - The latest UUID folder doesn't contain valid `PrivateKey` and `PublicKey` files
  - **Key Reuse**: Otherwise, uses existing key pair from latest folder (by modified date descending)
  - **Location**: `sshkeys/<uuid>/PrivateKey.ppk` and `sshkeys/<uuid>/PublicKey.pubkey` next to binary
  - **Public Key Comment**: `ssh-<uuid>` (e.g., `ssh-ed25519 AAAA... ssh-a1b2c3d4-e5f6-...`)
  - **Persistence**: Keys are never deleted from disk, always kept for future deployments
- `sshPort`: SSH port per node (default: `22`)

**Node Role Settings:**
- `role`: `manager`, `worker`, or `both` (required)
  - `manager`: Swarm manager node (MON only for MicroCeph)
  - `worker`: Swarm worker node (OSD only for MicroCeph)
  - `both`: Joins swarm as manager AND gets OSD storage (for smaller clusters)
  - **Note**: First manager/both in the list becomes the primary master

**System Settings:**
- `newHostname`: New hostname to set on this node (optional, idempotent)
  - If blank, hostname is not changed
  - Uses `hostnamectl set-hostname` for idempotent hostname changes
- `rebootOnCompletion`: Reboot this node after deployment (default: `false`)
  - Initiates reboot with 15-second delay
  - SSH connection is terminated cleanly before reboot
- `scriptsEnabled`: Enable script execution on this node (default: `true`)
  - If `false`, pre/post scripts are skipped for this node

**Storage Settings:**
- `storageEnabled`: Enable distributed storage (MicroCeph) on this node (default: `false`)

**Docker Swarm Settings:**
- `advertiseAddr`: Override auto-detected advertise address for Swarm (optional)

**Custom Labels:**
- `labels`: Key-value pairs for custom Docker node labels (optional)
  - Example: `{"environment": "production", "storage": "ssd", "gpu": "nvidia-a100"}`
  - Custom labels are merged with automatic labels (see below)
  - Custom labels override automatic labels if there's a conflict

### Automatic Node Labels

The deployer automatically applies comprehensive labels to each Docker Swarm node during Phase 8 of deployment. These labels are detected by making outbound calls from each node itself.

**Geolocation Labels** (detected via ip-api.com):
- `geo.public-ip`: Public IP address of the node
- `geo.country`: Country name (e.g., "United States")
- `geo.country-code`: ISO country code (e.g., "us")
- `geo.region`: Region/state code (e.g., "CA")
- `geo.region-name`: Region/state name (e.g., "California")
- `geo.city`: City name (e.g., "San Francisco")
- `geo.timezone`: Timezone (e.g., "America/Los_Angeles")
- `geo.isp`: Internet Service Provider name

**Infrastructure Labels** (from configuration):
- `overlay.provider`: Overlay network provider (e.g., "netbird", "tailscale")
- `storage.enabled`: "true" or "false"
- `storage.provider`: Storage provider (e.g., "microceph")
- `storage.mount-path`: CephFS mount path (if enabled)
- `cluster.name`: Cluster name from global settings
- `node.role`: "manager", "worker", or "both"

**Label Precedence:**
1. Automatic labels are applied first
2. Custom labels from the `labels` field override automatic labels
3. All labels are applied via `docker node update --label-add` on the primary master

**Example Usage:**
```bash
# Deploy services to specific regions
docker service create --constraint 'node.labels.geo.country-code==us' nginx

# Deploy to nodes with SSD storage
docker service create --constraint 'node.labels.storage==ssd' postgres

# Deploy to production environment only
docker service create --constraint 'node.labels.environment==production' myapp

# Deploy to storage-enabled nodes with CephFS mount
docker service create --constraint 'node.labels.storage.enabled==true' \
  --mount type=bind,src=/mnt/MicroCephFS/docker-swarm-0001,dst=/data myapp
```

### SSH Multi-Session Support

The deployer uses **parallel SSH sessions** for maximum performance:
- All nodes are configured **simultaneously** using goroutines
- Each node gets its own SSH connection from the pool
- Operations like dependency installation, overlay setup, and storage configuration run in parallel
- This dramatically reduces deployment time for large clusters

The SSH pool (`internal/ssh/pool.go`) manages connections efficiently:
- Connections are created on-demand and reused
- Each host can have different authentication credentials
- Thread-safe with mutex protection
- `RunAll()` method executes commands on multiple hosts in parallel

## Features

- **Swarm master orchestration**
  - Initialise a Swarm manager with distributed storage.
  - Run a controller server that coordinates nodes via JSON-over-TCP.
- **Node convergence**
  - Nodes register with the controller and are converged onto the desired
    state (Swarm role, overlay provider, storage participation).
- **Overlay providers**
  - Netbird (`netbird`)
  - Tailscale (`tailscale`)
  - WireGuard (`wireguard`)
  - Or no overlay (`none`)
- **MicroCeph distributed storage**
  - CephFS for POSIX-compliant shared storage
  - Optional RADOS Gateway (S3) support
- **Auto-installation of dependencies**
  - Docker and Docker Compose (`docker` CLI plugin and/or `docker-compose`).
  - Netbird, Tailscale, WireGuard tools.
  - MicroCeph snap package.

## Legacy Mode: Node-Agent Deployment

**Note:** This mode is deprecated. Use the `deploy` command with JSON config instead.

The legacy mode used wrapper scripts (`cluster-master-init.sh`, `cluster-node-join.sh`) for node-agent style deployment. These scripts are still available but the recommended approach is to use the JSON configuration file with the `dscotctl` binary directly.

**Note**: Services are deployed via the generic service deployment system from YAML files in the `binaries/services/` directory.

## CLI overview

The main entry points are:

- `dscotctl -config <config.json>` - Deploy cluster from JSON configuration
- `dscotctl -config <config.json> -teardown` - Teardown cluster
- `dscotctl -version` - Show version information

Run `dscotctl -help` for detailed flags.

## Linux wrapper scripts

For convenience, Linux wrapper scripts live under `./binaries` and execute
pre-built `dscotctl` binaries relative to the script directory:

- `cluster-master-init.sh` wraps `dscotctl master init`.
- `cluster-master-serve.sh` wraps `dscotctl master serve` (listen/server mode).
- `cluster-node-join.sh` wraps `dscotctl node join` (node/client mode).

Each script:

- Detects the architecture via `uname -m`.
- Selects `dscotctl-linux-amd64` or `dscotctl-linux-arm64` from the
  `binaries/` directory.
- Passes through all additional arguments to the underlying `dscotctl`
  subcommand.

See `binaries/README.md` for examples and usage notes.

## Building

Use the PowerShell build script for cross-platform compilation:

```powershell
.\scripts\build.ps1
```

This builds all targets (Linux amd64/arm64, macOS amd64/arm64, Windows amd64) with embedded version information.

Or build manually from the repository root:

- Linux/amd64:

  ```bash
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o binaries/dscotctl-linux-amd64 ./cmd/dscotctl
  ```

- Linux/arm64:

  ```bash
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o binaries/dscotctl-linux-arm64 ./cmd/dscotctl
  ```

- macOS/arm64 (Apple Silicon):

  ```bash
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o binaries/dscotctl-darwin-arm64 ./cmd/dscotctl
  ```

- Windows/amd64:

  ```bash
  GOOS=windows GOARCH=amd64 go build -o binaries/dscotctl-windows-amd64.exe ./cmd/dscotctl
  ```

Pre-built binaries for these targets are tracked under `./binaries`.

## Documentation

- `GO-IMPLEMENTATION-SPEC.md` – the original design and behavioural spec.
- `docs/README.md` – higher-level architecture and CLI overview.
- `binaries/README.md` – documentation for the Linux wrapper scripts and binaries.

## Logging

`dscotctl` writes plain-text log lines in the format:

```text
[2025-01-01T12:00:00Z] - [INFO] - message
```

- Logs are emitted to **stderr** and to a log file named `dscotctl.log` in the
  current working directory by default.
- Override the log file path via `DSCOTCTL_LOG_FILE`.
- Control the minimum log level via `DSCOTCTL_LOG_LEVEL`
  (e.g. `debug`, `info`, `warn`, `error`; default is `info`).

Controller and node logs include detailed Swarm and storage events after each
join so you can see which token was used, which Swarm cluster the node joined,
and the current storage status on that node.

## Notes

- The Go implementation is idempotent: commands are safe to re-run and converge
  the system onto the desired state.
- Overlay provider config is passed as a **string** via `overlayConfig` and
  mapped to provider-specific environment variables (e.g. `NB_SETUP_KEY` for
  Netbird, `TS_AUTHKEY` for Tailscale).
- Dependency installers (`internal/deps`) make a best-effort to support
  multiple Linux distributions, with Ubuntu/Debian (`apt-get`) given
  precedence.
