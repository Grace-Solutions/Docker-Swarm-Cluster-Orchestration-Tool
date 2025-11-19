#Repository Clone command
   ```bash
    git clone https://github.com/Grace-Solutions/Docker-Swarm-Cluster-Configuration-Service.git && cd ./Docker-Swarm-Cluster-Configuration-Service && chmod -R -v +x ./
   ```

# Linux wrapper scripts for clusterctl

This directory contains pre-built `clusterctl` binaries and convenience
wrapper scripts for Linux.

## Binaries

The following binaries are tracked and expected in this directory:

- `clusterctl-linux-amd64`  "linux/amd64" build of the Go CLI.
- `clusterctl-linux-arm64`  "linux/arm64" build of the Go CLI.
- `clusterctl-windows-amd64.exe`  "windows/amd64" build (for reference and
  distribution; not used by the Linux wrapper scripts).

## Wrapper scripts

The scripts below are intended for **Linux** and execute the local
`clusterctl` Linux binary from this directory, selecting the correct build
based on `uname -m`.

### `cluster-master-init.sh`

Initialise the Swarm master node and optional GlusterFS paths.

- Resolves its own directory.
- Detects the architecture via `uname -m` and chooses:
  - `clusterctl-linux-amd64` for `x86_64` / `amd64`.
  - `clusterctl-linux-arm64` for `aarch64` / `arm64`.
- Executes:
  - `clusterctl master init "$@"`

Example:

- `./cluster-master-init.sh --state-dir /data/GlusterFS/0001/orchestration --enable-glusterfs`

### `cluster-master-serve.sh`

Run the controller in listen/serve mode on the master:

- Performs the same architecture detection as `cluster-master-init.sh`.
- Executes:
  - `clusterctl master serve "$@"`

Example:

- `./cluster-master-serve.sh --state-dir /data/GlusterFS/0001/orchestration --listen 0.0.0.0:7000 --wait-for-minimum --min-managers 1 --min-workers 1`

### `cluster-node-join.sh`

Join a node/client to the cluster:

- Performs architecture detection as above.
- Executes:
  - `clusterctl node join "$@"`

Example:

- `./cluster-node-join.sh --master 10.0.0.10:7000 --role worker --overlay-provider netbird --overlay-config YOUR_NETBIRD_SETUP_KEY --enable-glusterfs`

## Usage notes

1. Make the scripts executable on Linux after checkout:

   ```bash
   chmod +x cluster-master-init.sh cluster-master-serve.sh cluster-node-join.sh
   chmod +x clusterctl-linux-amd64 clusterctl-linux-arm64
   ```

2. Overlay providers like Netbird and Tailscale accept configuration via
   environment variables, e.g. `NB_SETUP_KEY` and `TS_AUTHKEY`. The Go
   implementation already maps `--overlay-config` into these env vars for the
   underlying CLI.

3. The scripts themselves are thin wrappers; **all logic lives in the Go
   binary**. For advanced scenarios (e.g. Swarm reset, node deregistration),
   invoke `clusterctl` directly:

   ```bash
   ./clusterctl-linux-amd64 master reset --state-dir /data/GlusterFS/0001/orchestration
   ./clusterctl-linux-amd64 node reset --master 10.0.0.10:7000 --deregister --overlay-provider tailscale
   ```

For a more detailed system overview, see `../docs/README.md` and the root
`README.md`.

