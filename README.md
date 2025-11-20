# Docker Swarm Cluster Configuration Service

`clusterctl` is a Go-based orchestrator that automates Docker Swarm
initialisation, node joins, overlay networking, and GlusterFS integration.

The project is designed around a **single binary** (`clusterctl`) plus
optional convenience wrapper scripts for Linux.

## Features

- **Swarm master orchestration**
  - Initialise a Swarm manager and optional GlusterFS state paths.
  - Run a controller server that coordinates nodes via JSON-over-TCP.
- **Node convergence**
  - Nodes register with the controller and are converged onto the desired
    state (Swarm role, overlay provider, GlusterFS participation).
- **Overlay providers**
  - Netbird (`netbird`)
  - Tailscale (`tailscale`)
  - WireGuard (`wireguard`)
  - Or no overlay (`none`)
- **GlusterFS support**
  - Optional brick preparation, volume creation, and mounts.
- **Auto-installation of dependencies**
  - Docker and Docker Compose (`docker` CLI plugin and/or `docker-compose`).
  - Netbird, Tailscale, WireGuard tools.
  - GlusterFS client utilities.

## Quickstart (primary master on Linux)

On a fresh Linux host that can reach your Netbird/Tailscale/WireGuard network,
you can get to the binaries and start the primary master controller with:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && \
  cd ./Docker-Swarm-Cluster-Configuration-Service && \
  chmod -R -v +x ./ && \
  cd ./binaries && \
  clear && \
  ./cluster-master-init.sh \
    --primary-master \
    --listen 0.0.0.0:7000 \
    --advertise-addr <PRIMARY_MANAGER_IP>:2377 \
    --min-managers 1 \
    --min-workers 0 \
    --wait-for-minimum
```

Replace `<PRIMARY_MANAGER_IP>` with the address you want Swarm to use for this
manager (often the overlay IP).

### Quickstart: additional manager node (Linux)

On another Linux host that should participate as a Swarm **manager**:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && \
  cd ./Docker-Swarm-Cluster-Configuration-Service && \
  chmod -R -v +x ./ && \
  cd ./binaries && \
  clear && \
  ./cluster-node-join.sh \
    --master <PRIMARY_MANAGER_IP>:7000 \
    --role manager \
    --overlay-provider netbird \
    --overlay-config <NETBIRD_SETUP_KEY> \
    --enable-glusterfs
```

### Quickstart: worker node (Linux)

On a Linux host that should run Swarm **worker** tasks:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && \
  cd ./Docker-Swarm-Cluster-Configuration-Service && \
  chmod -R -v +x ./ && \
  cd ./binaries && \
  clear && \
  ./cluster-node-join.sh \
    --master <PRIMARY_MANAGER_IP>:7000 \
    --role worker \
    --overlay-provider netbird \
    --overlay-config <NETBIRD_SETUP_KEY> \
    --enable-glusterfs
```

Replace `<NETBIRD_SETUP_KEY>` with your Netbird setup key (or switch
`--overlay-provider` / `--overlay-config` to match your chosen overlay).

## CLI overview

The main entry points are:

- `clusterctl master init [flags]`
- `clusterctl master serve [flags]`
- `clusterctl master reset [flags]`
- `clusterctl node join [flags]`
- `clusterctl node reset [flags]`

Run `clusterctl help` or any command with `-h`/`--help` for detailed flags.

## Linux wrapper scripts

For convenience, Linux wrapper scripts live under `./binaries` and execute
pre-built `clusterctl` binaries relative to the script directory:

- `cluster-master-init.sh` wraps `clusterctl master init`.
- `cluster-master-serve.sh` wraps `clusterctl master serve` (listen/server
  mode).
- `cluster-node-join.sh` wraps `clusterctl node join` (node/client mode).

Each script:

- Detects the architecture via `uname -m`.
- Selects `clusterctl-linux-amd64` or `clusterctl-linux-arm64` from the
  `binaries/` directory.
- Passes through all additional arguments to the underlying `clusterctl`
  subcommand.

See `binaries/README.md` for examples and usage notes.

## Building

From the repository root:

- Linux/amd64:

  ```bash
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o binaries/clusterctl-linux-amd64 ./cmd/clusterctl
  ```

- Linux/arm64:

  ```bash
  GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o binaries/clusterctl-linux-arm64 ./cmd/clusterctl
  ```

- Windows/amd64:

  ```bash
  GOOS=windows GOARCH=amd64 go build -o binaries/clusterctl-windows-amd64.exe ./cmd/clusterctl
  ```

Pre-built binaries for these targets are tracked under `./binaries`.

## Documentation

- `GO-IMPLEMENTATION-SPEC.md` – the original design and behavioural spec.
- `docs/README.md` – higher-level architecture and CLI overview.
- `binaries/README.md` – documentation for the Linux wrapper scripts and
  binaries.

## Logging

`clusterctl` writes plain-text log lines in the format:

```text
[2025-01-01T12:00:00Z] - [INFO] - message
```

- Logs are emitted to **stderr** and to a log file named `clusterctl.log` in the
  current working directory by default.
- Override the log file path via `CLUSTERCTL_LOG_FILE`.
- Control the minimum log level via `CLUSTERCTL_LOG_LEVEL`
  (e.g. `debug`, `info`, `warn`, `error`; default is `info`).

Controller and node logs include detailed Swarm and GlusterFS events after each
join so you can see which token was used, which Swarm cluster the node joined,
and the current GlusterFS volume/mount status on that node.

## Notes

- The Go implementation is idempotent: commands like `node join` and
  `master init` are safe to re-run and converge the system onto the desired
  state.
- Overlay provider config is passed as a **string** via `--overlay-config` and
  mapped to provider-specific environment variables (e.g. `NB_SETUP_KEY` for
  Netbird, `TS_AUTHKEY` for Tailscale).
- Dependency installers (`internal/deps`) make a best-effort to support
  multiple Linux distributions, with Ubuntu/Debian (`apt-get`) given
  precedence.
