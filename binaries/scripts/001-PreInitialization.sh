#!/bin/bash
# 001-PreInitialization.sh - Runs before service deployment
# Environment variables available:
#   STORAGE_MOUNT_PATH     - Base storage mount path (e.g., /mnt/MicroCephFS/docker-swarm-0001)
#   SERVICE_DATA_DIR       - Service data subdirectory name (e.g., "data")
#   SERVICE_DEFINITIONS_DIR- Service definitions subdirectory name (e.g., "ServiceDefinitions")
#   PRIMARY_MASTER         - Primary master node hostname
#   HAS_DEDICATED_WORKERS  - "true" if cluster has dedicated workers
#   DISTRIBUTED_STORAGE    - "true" if distributed storage is enabled
#   NODE_HOSTNAME          - This node's hostname

set -e

echo "[PreInit] Starting pre-initialization..."
echo "[PreInit] STORAGE_MOUNT_PATH: ${STORAGE_MOUNT_PATH}"
echo "[PreInit] DISTRIBUTED_STORAGE: ${DISTRIBUTED_STORAGE}"
echo "[PreInit] NODE_HOSTNAME: ${NODE_HOSTNAME}"

# Exit early if no storage path configured
if [ -z "${STORAGE_MOUNT_PATH}" ]; then
    echo "[PreInit] No storage mount path configured, skipping pre-initialization"
    exit 0
fi

BASE_PATH="${STORAGE_MOUNT_PATH}/${SERVICE_DATA_DIR}"

# =============================================================================
# NginxUI Pre-Initialization (Per-Node Directories)
# =============================================================================
echo "[PreInit] Initializing NginxUI for node: ${NODE_HOSTNAME}..."

# Each node gets its own directory to avoid write contention
# Structure: NginxUI/<hostname>/nginx (nginx config) and NginxUI/<hostname>/nginxui (UI data)
NGINXUI_BASE="${BASE_PATH}/NginxUI/${NODE_HOSTNAME}"
NGINX_PATH="${NGINXUI_BASE}/nginx"
NGINXUI_PATH="${NGINXUI_BASE}/nginxui"

# Create all required directories for NginxUI self-check
echo "[PreInit] Creating NginxUI directories at ${NGINXUI_BASE}..."
mkdir -p "${NGINX_PATH}/conf.d"
mkdir -p "${NGINX_PATH}/sites-available"
mkdir -p "${NGINX_PATH}/sites-enabled"
mkdir -p "${NGINX_PATH}/streams-available"
mkdir -p "${NGINX_PATH}/streams-enabled"
mkdir -p "${NGINX_PATH}/logs"
mkdir -p "${NGINXUI_PATH}"

# Create empty log files if they don't exist (NginxUI checks these)
touch "${NGINX_PATH}/logs/access.log"
touch "${NGINX_PATH}/logs/error.log"

# Download mime.types if not exists
MIME_TYPES_PATH="${NGINX_PATH}/mime.types"
if [ ! -f "${MIME_TYPES_PATH}" ]; then
    echo "[PreInit] Downloading mime.types..."
    curl -sSL -o "${MIME_TYPES_PATH}" 'https://raw.githubusercontent.com/nginx/nginx/master/conf/mime.types'
    echo "[PreInit] mime.types downloaded"
else
    echo "[PreInit] mime.types already exists"
fi

# Create nginx.conf if not exists (includes all directories for NginxUI self-check)
NGINX_CONF_PATH="${NGINX_PATH}/nginx.conf"
if [ ! -f "${NGINX_CONF_PATH}" ]; then
    echo "[PreInit] Creating nginx.conf..."
    cat > "${NGINX_CONF_PATH}" << 'NGINX_CONF_EOF'
user  nginx;
worker_processes  auto;

error_log  /etc/nginx/logs/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /etc/nginx/logs/access.log  main;

    sendfile        on;
    keepalive_timeout  65;

    # Include conf.d directory (NginxUI self-check)
    include /etc/nginx/conf.d/*.conf;

    # Include sites-enabled directory (NginxUI self-check)
    include /etc/nginx/sites-enabled/*;
}

# Include streams-enabled directory (NginxUI self-check)
stream {
    include /etc/nginx/streams-enabled/*;
}
NGINX_CONF_EOF
    echo "[PreInit] nginx.conf created"
else
    echo "[PreInit] nginx.conf already exists"
fi

# =============================================================================
# Portainer Pre-Initialization
# =============================================================================
echo "[PreInit] Initializing Portainer..."

PORTAINER_PATH="${BASE_PATH}/Portainer"
mkdir -p "${PORTAINER_PATH}/data"
echo "[PreInit] Portainer directories created"

# =============================================================================
# Service Definitions Directory
# =============================================================================
echo "[PreInit] Creating ServiceDefinitions directory..."
mkdir -p "${STORAGE_MOUNT_PATH}/${SERVICE_DEFINITIONS_DIR}"
echo "[PreInit] ServiceDefinitions directory ready"

echo "[PreInit] ✅ Pre-initialization complete"

