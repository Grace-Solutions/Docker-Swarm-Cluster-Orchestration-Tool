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
- `internal/logging` – structured logging using zap.

## CLI overview

Main commands:

- `clusterctl master init [flags]`
- `clusterctl master serve [flags]`
- `clusterctl master reset [flags]`
- `clusterctl node join [flags]`
- `clusterctl node reset [flags]`

Commonly used flags:

- `--state-dir` – controller state directory
  (default: `/data/GlusterFS/0001/orchestration`).
- `--listen` – controller listen address (default: `0.0.0.0:7000`).
- `--advertise-addr` – Swarm advertise address for managers.
- `--overlay-provider` – `netbird`, `tailscale`, `wireguard`, or `none`.
- `--overlay-config` – provider-specific config string, e.g. setup/auth keys.
- `--enable-glusterfs` – enable GlusterFS participation on a node.
- `--master` – controller address (`host:port`) for node commands.

For full behaviour and field-level semantics, see
`../GO-IMPLEMENTATION-SPEC.md`.

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

