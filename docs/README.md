# Docker Swarm Cluster Configuration Service – Documentation

This folder contains documentation for the `clusterctl` Go-based orchestrator
and its Linux wrapper scripts.

## Contents

- `README.md` (this file) – overview of the system, architecture, and usage.
- `../GO-IMPLEMENTATION-SPEC.md` – original implementation spec and design
  notes.
- `../binaries/README.md` – documentation for the Linux wrapper scripts under
  `binaries/`.

## High-level architecture

The orchestrator is a **single Go binary** (`clusterctl`) with three
high-level modes:

- `clusterctl master init` – prepare a host as the initial Swarm manager and
  optionally set up GlusterFS state paths.
- `clusterctl master serve` – run the controller server that coordinates
  nodes via a JSON-over-TCP protocol.
- `clusterctl node join` – register a node and converge it onto the desired
  state (overlay, Swarm role, GlusterFS participation).

Key internal packages:

- `internal/controller` – master-side TCP server, state management, and
  minimum-node gating.
- `internal/nodeagent` – node-side join/reset logic.
- `internal/overlay` – overlay provider abstraction for Netbird, Tailscale,
  WireGuard, or `none`.
- `internal/swarm` – Docker Swarm initialisation and join.
- `internal/gluster` – GlusterFS brick, volume, and mount management.
- `internal/deps` – helper functions to ensure Docker, docker-compose,
  Netbird, Tailscale, WireGuard, and GlusterFS are installed.
- `internal/ipdetect` – IP auto-detection with CGNAT and RFC1918 preference.
- `internal/logging` – simple text logger that writes `[utc-timestamp] - [LEVEL] - message` lines to stderr and an optional log file, with level controlled by `CLUSTERCTL_LOG_LEVEL` and file path by `CLUSTERCTL_LOG_FILE`.

## Quickstart (primary master on Linux)

A typical first step is to bring up a **primary master** that both initialises
the controller state and starts serving join requests. On a fresh Linux host,
you can also have GlusterFS wired up in one shot using the default state/brick
layout:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && \
  cd ./Docker-Swarm-Cluster-Configuration-Service && \
  chmod -R -v +x ./ && \
  cd ./binaries && \
  clear && \
  ./cluster-master-init.sh \
    --primary-master \
    --enable-glusterfs \
    --state-dir /mnt/GlusterFS/0001/data \
    --listen 0.0.0.0:7000 \
    --advertise-addr <PRIMARY_MANAGER_ADDR> \
    --min-managers 1 \
    --min-workers 0 \
    --wait-for-minimum
```

One-line version:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && cd ./Docker-Swarm-Cluster-Configuration-Service && chmod -R -v +x ./ && cd ./binaries && clear && ./cluster-master-init.sh --primary-master --enable-glusterfs --state-dir /mnt/GlusterFS/0001/data --listen 0.0.0.0:7000 --advertise-addr <PRIMARY_MANAGER_ADDR> --min-managers 1 --min-workers 0 --wait-for-minimum
```

With `--enable-glusterfs` and the default `--state-dir`:

- **State dir (controller + data mount):** `/mnt/GlusterFS/0001/data`
- **Brick dir (where Gluster bricks live on this node):** `/mnt/GlusterFS/0001/brick`
- **Volume name:** `0001` (derived from the parent directory name)

Replace `<PRIMARY_MANAGER_IP>` with the address you want Swarm to use for this
manager (typically your overlay IP).

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

One-line version:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && cd ./Docker-Swarm-Cluster-Configuration-Service && chmod -R -v +x ./ && cd ./binaries && clear && ./cluster-node-join.sh --master <PRIMARY_MANAGER_IP>:7000 --role manager --overlay-provider netbird --overlay-config <NETBIRD_SETUP_KEY> --enable-glusterfs
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

One-line version:

```bash
git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && cd ./Docker-Swarm-Cluster-Configuration-Service && chmod -R -v +x ./ && cd ./binaries && clear && ./cluster-node-join.sh --master <PRIMARY_MANAGER_IP>:7000 --role worker --overlay-provider netbird --overlay-config <NETBIRD_SETUP_KEY> --enable-glusterfs
```

Replace `<NETBIRD_SETUP_KEY>` with your Netbird setup key (or switch
`--overlay-provider` / `--overlay-config` to match your chosen overlay).

## CLI overview

Main commands:

- `clusterctl master init [flags]`
- `clusterctl master serve [flags]`
- `clusterctl master reset [flags]`
- `clusterctl node join [flags]`
- `clusterctl node reset [flags]`

Commonly used flags:

- `--state-dir` – controller state directory
  (default: `/mnt/GlusterFS/0001/data`).
- `--listen` – controller listen address (default: `0.0.0.0:7000`).
- `--advertise-addr` – Swarm advertise address for managers.
- `--overlay-provider` – `netbird`, `tailscale`, `wireguard`, or `none`.
- `--overlay-config` – provider-specific config string, e.g. setup/auth keys.
- `--enable-glusterfs` – enable GlusterFS participation on a node.
- `--master` – controller address (`host:port`) for node commands.

For full behaviour and field-level semantics, see
`../GO-IMPLEMENTATION-SPEC.md`.

## Logging and troubleshooting

`clusterctl` logs are plain text lines in the format:

```text
[2025-01-01T12:00:00Z] - [INFO] - message
```

- By default, logs go to **stderr** and to a log file named `clusterctl.log` in the
  current working directory.
- You can override the log file path via `CLUSTERCTL_LOG_FILE`.
- You can control the minimum log level via `CLUSTERCTL_LOG_LEVEL`
  (e.g. `debug`, `info`, `warn`, `error`; default is `info`).

Controller and node logs include detailed Swarm and GlusterFS events so you can
trace exactly how each node joined, which token was used, and what the current
GlusterFS volume/mount status is.

## Linux wrapper scripts

For convenience, Linux wrapper scripts live under `../binaries` and execute
pre-built binaries relative to the script directory:

- `cluster-master-init.sh` – wraps `clusterctl master init`.
- `cluster-master-serve.sh` – wraps `clusterctl master serve`.
- `cluster-node-join.sh` – wraps `clusterctl node join`.

Each script:

- Detects `uname -m` and selects `clusterctl-linux-amd64` or
  `clusterctl-linux-arm64` accordingly.
- Runs the appropriate `clusterctl` subcommand, passing through any
  additional CLI flags.

Refer to `../binaries/README.md` for usage examples and notes about
permissions and environment variables (e.g. Netbird/Tailscale setup keys).

