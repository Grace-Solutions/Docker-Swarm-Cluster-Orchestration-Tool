# Go Swarm Cluster Orchestrator – Ground-Up Implementation Spec

> This document specifies a **pure Go** implementation (no shell wrappers) of the
> Swarm + overlay + GlusterFS orchestrator, as a **single binary** with
> parameters. The goal is to keep the **same end results and architecture** as
> the current scripts, but with Go as the source of truth.

---

## 1. Scope & Goals

- Single static Go binary (e.g. `clusterctl`) compiled for Linux.
- No dependency on `bash` wrapper scripts at runtime.
- Preserve current behaviour:
  - Docker Swarm cluster (managers + workers).
  - Overlay-first connectivity (CGNAT / RFC1918 IP selection).
  - Controller ↔ node JSON handshake.
  - GlusterFS as first-class, optional but fully supported.
  - Optional minimum-node wait/gating.
- Default server bind: `0.0.0.0:<port>` so loopback, overlay IP, and LAN
  connections all work, including the “first master == server” case.

Non-goals in this spec:
- Firewall configuration (explicitly out of scope).
- OS package installation logic (assume Docker, GlusterFS, overlay client are
  present or managed elsewhere).

---

## 2. High-Level Architecture

Single binary with three main modes:

- `clusterctl master init` – prepare a host as initial Swarm manager and
  (optionally) GlusterFS brick.
- `clusterctl master serve` – run the controller server (JSON-over-TCP).
- `clusterctl node join` – register node and converge it onto the desired
  state (overlay, Swarm, GlusterFS).

Internal components (Go packages):

- `config` – typed configuration from YAML + env + flags.
- `ipdetect` – primary IP selection (CGNAT → RFC1918 → other → loopback).
- `overlay` – interface & providers (Netbird/Tailscale/WireGuard/none).
- `swarm` – Swarm init/join/token inspection.
- `gluster` – GlusterFS topology, bricks, volumes, mounts.
- `controller` – master-side TCP server + state store + optional gating.
- `nodeagent` – client-side registration + converge logic.
- `logging` – plain-text logs with log levels, writing `[utc-timestamp] - [LEVEL] - message` lines to stderr and an optional log file (`CLUSTERCTL_LOG_FILE`) with level controlled by `CLUSTERCTL_LOG_LEVEL`.

Data store: simple local filesystem under a “state dir” (e.g.
`/data/GlusterFS/0001/orchestration`) using JSON or BoltDB for durability.

---

## 3. CLI & Configuration

### 3.1 Commands

- `clusterctl master init`
  - Detect/confirm Docker & GlusterFS.
  - Optionally create/prepare storage paths for GlusterFS bricks.
  - Optionally initialize Swarm if not already initialized.

- `clusterctl master serve`
  - Start controller server listening on `--listen` (default `0.0.0.0:7000`).
  - Serve JSON responses based on current state and min-node config.

- `clusterctl node join`
  - Auto-detect primary IP (using `ipdetect`).
  - Register with master, receive config, then:
    - Ensure overlay connectivity as requested.
    - Join Swarm as manager or worker.
    - Participate in GlusterFS as directed.

### 3.2 Flags (overview)

Common flags:
- `--config /path/to/config.yaml`
- `--overlay-provider {netbird|tailscale|wireguard|none}`
- `--overlay-config /path/to/overlay.json`
- `--enable-glusterfs` / `--disable-glusterfs`

Master-only:
- `--state-dir /data/GlusterFS/0001/orchestration`
- `--advertise-addr <ip>`
- `--listen 0.0.0.0:7000`
- `--min-managers N`
- `--min-workers N`
- `--wait-for-minimum` (bool, default: false)

Node-only:
- `--master <ip:port>`
- `--role {manager|worker}`
- `--ip <override-ip>`
- `--hostname <override-hostname>`

---

## 4. Controller Server Behaviour

- TCP server listening on configured address (default `0.0.0.0:7000`).
- For each incoming connection:
  - Read exactly one JSON request, then write exactly one JSON response, then
    close connection.
  - Decode into a `NodeRegistration` struct (hostname, role, IP, OS, CPU,
    memory, Docker version, Gluster capability, timestamp).
  - Persist registration in state store; update counts of managers/workers.

Response semantics:

- Fields include at minimum:
  - `Status` ("ready" or "waiting")
  - `SwarmRole`, `SwarmJoinToken`, `SwarmManagerAddr`
  - `OverlayType`, `OverlayPayload`
  - `GlusterEnabled`, `GlusterVolume`, `GlusterMount`, `GlusterBrick`

- When `--wait-for-minimum` is **not** set (default):
  - `Status` is always `"ready"`.

- When `--wait-for-minimum` **is** set and thresholds are provided:
  - If current counts are below thresholds, respond with `Status = "waiting"`
    and include informational counts.
  - Otherwise respond with `Status = "ready"` and Swarm/Gluster instructions.

State consistency:
- On restart, controller reloads prior registrations and cluster metadata from
  `--state-dir` so decisions remain stable.

---

## 5. Node Agent Behaviour

`clusterctl node join` performs:

1. Determine node identity
   - Use `--ip` / `--hostname` if provided, otherwise call `ipdetect` and OS
     APIs to populate.
2. Connect to controller and send `NodeRegistration` JSON.
3. Parse response JSON; if `Status = "waiting"`, backoff and retry.
4. Once `Status = "ready"`:
   - Configure overlay provider (if any).
   - If node is not part of Swarm, join using provided role/token/address.
   - If GlusterFS is enabled:
     - Prepare brick or mountpoint as directed.
     - Join or mount the target volume.
5. Log progress and final result with clear success/failure messages.

Node agent must be idempotent: repeated `join` should converge to the same
state without error.

---

## 6. IP Detection & Overlay Integration

`ipdetect` replicates the current behaviour:
- Inspect all non-loopback IPv4 addresses.
- Prefer addresses in:
  1. CGNAT `100.64.0.0/10` (overlay backbones like Netbird/Tailscale)
  2. RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  3. Remaining non-loopback addresses
  4. Fall back to loopback as last resort

The `overlay` package exposes a simple interface, e.g.:
- `EnsureConnected(ctx, config) error` – validate or establish overlay
  connectivity based on provider-specific CLI/API.

---

## 7. GlusterFS Integration

- `gluster` package manages:
  - Discovering or provisioning brick paths on participating nodes.
  - Creating/joining volumes.
  - Ensuring mounts at well-known paths used by Swarm services.
- Controller decides which nodes are Gluster-capable and assigns roles
  (brick vs client-only) in its responses.
- Node agent executes those instructions via `gluster` helpers.

GlusterFS remains a core part of the design; Swarm services assume shared
storage (or at minimum, predictable mounts) where appropriate.

---

## 8. Observability & Logging

- Structured logs (JSON or key=value) with levels: DEBUG, INFO, WARN, ERROR.
- Controller logs:
  - Node registrations and current counts.
  - Decisions about gating and Swarm/Gluster instructions.
- Node logs:
  - Outgoing registration payload summary.
  - Overlay/Swarm/Gluster steps and their outcomes.

---

## 9. Build & Cross-Compilation

- Primary target: `linux/amd64` static binary.
- Support building on Windows using Go cross-compilation:
  - Example: `GOOS=linux GOARCH=amd64 go build -o clusterctl ./cmd/clusterctl`.
- No runtime dependency on shell; all behaviour lives in Go code.

