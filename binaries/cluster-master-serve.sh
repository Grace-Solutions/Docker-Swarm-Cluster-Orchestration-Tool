#!/usr/bin/env bash
set -euo pipefail

# Wrapper to run the controller in master serve (listen) mode.
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
    echo "[cluster-master-serve] Unsupported architecture '$ARCH'. Expected x86_64/amd64 or aarch64/arm64." >&2
    exit 1
    ;;
esac

if [[ ! -f "$BIN" ]]; then
  echo "[cluster-master-serve] clusterctl binary not found at $BIN" >&2
  exit 1
fi

exec "$BIN" master serve "$@"

