#!/usr/bin/env bash
set -euo pipefail

# Wrapper to join a node/client to the Swarm cluster.
# This script detects the local CPU architecture and selects the
# appropriate clusterctl Linux binary from this directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
ARCH="$(uname -m)"

BIN="$SCRIPT_DIR/clusterctl-linux-amd64"
case "$ARCH" in
  x86_64|amd64)
    BIN="$SCRIPT_DIR/clusterctl-linux-amd64"
    ;;
  aarch64|arm64)
    BIN="$SCRIPT_DIR/clusterctl-linux-arm64"
    ;;
  *)
    echo "[cluster-node-join] Unsupported architecture '$ARCH'. Expected x86_64/amd64 or aarch64/arm64." >&2
    exit 1
    ;;
esac

if [[ ! -f "$BIN" ]]; then
  echo "[cluster-node-join] clusterctl binary not found at $BIN" >&2
  exit 1
fi

exec "$BIN" node join "$@"

