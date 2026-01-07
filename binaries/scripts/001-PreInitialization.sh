#!/bin/bash
# 001-PreInitialization.sh - Runs before service deployment
#
# NOTE: Service-specific directories are created DYNAMICALLY by parseBindMounts()
# in the Go code, which parses bind mounts from each service YAML file.
# This script should NOT create hardcoded service directories.
#
# Environment variables available:
#   STORAGE_MOUNT_PATH      - Base storage mount path (e.g., /mnt/MicroCephFS/docker-swarm-0001)
#   SERVICE_DATA_DIR        - Service data subdirectory name (e.g., "data")
#   SERVICE_DEFINITIONS_DIR - Service definitions subdirectory name (e.g., "ServiceDefinitions")
#   DISTRIBUTED_STORAGE     - "true" if distributed storage is enabled
#   NODE_HOSTNAME           - This node's hostname

set -e

echo "[PreInit] Starting pre-initialization..."
echo "[PreInit] STORAGE_MOUNT_PATH: ${STORAGE_MOUNT_PATH}"
echo "[PreInit] NODE_HOSTNAME: ${NODE_HOSTNAME}"

# Exit early if no storage path configured
if [ -z "${STORAGE_MOUNT_PATH}" ]; then
    echo "[PreInit] No storage mount path configured, skipping pre-initialization"
    exit 0
fi

# =============================================================================
# Service Definitions Directory
# =============================================================================
echo "[PreInit] Creating ServiceDefinitions directory..."
mkdir -p "${STORAGE_MOUNT_PATH}/${SERVICE_DEFINITIONS_DIR}"
echo "[PreInit] ServiceDefinitions directory ready"

echo "[PreInit] ✅ Pre-initialization complete"
echo "[PreInit] NOTE: Service directories are created dynamically from YAML bind mounts"

