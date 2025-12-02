#!/bin/bash
#
# GlusterFS Complete Teardown Script
# This script completely removes GlusterFS from a node.
# Run this on each node before deploying MicroCeph.
#
# Usage: ./teardown-glusterfs.sh [--force]
#   --force  Skip confirmation prompt
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

FORCE=false
if [[ "$1" == "--force" ]]; then
    FORCE=true
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# Check if GlusterFS is installed
if ! command -v gluster &> /dev/null && ! dpkg -l | grep -q glusterfs; then
    log_info "GlusterFS does not appear to be installed. Nothing to do."
    exit 0
fi

log_warn "=========================================="
log_warn "  GlusterFS Complete Teardown"
log_warn "=========================================="
log_warn "This will PERMANENTLY remove:"
log_warn "  - All GlusterFS volumes"
log_warn "  - All GlusterFS bricks"
log_warn "  - All GlusterFS mounts"
log_warn "  - GlusterFS packages"
log_warn "  - All GlusterFS configuration"
log_warn "=========================================="

if [[ "$FORCE" != "true" ]]; then
    read -p "Are you sure you want to continue? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        log_info "Aborted."
        exit 0
    fi
fi

# Step 1: Stop all GlusterFS volumes
log_info "Step 1: Stopping GlusterFS volumes..."
for vol in $(gluster volume list 2>/dev/null || true); do
    log_info "  Stopping volume: $vol"
    gluster volume stop "$vol" force --mode=script 2>/dev/null || true
done

# Step 2: Delete all GlusterFS volumes
log_info "Step 2: Deleting GlusterFS volumes..."
for vol in $(gluster volume list 2>/dev/null || true); do
    log_info "  Deleting volume: $vol"
    gluster volume delete "$vol" --mode=script 2>/dev/null || true
done

# Step 3: Unmount all GlusterFS mounts
log_info "Step 3: Unmounting GlusterFS filesystems..."
mount | grep glusterfs | awk '{print $3}' | while read mnt; do
    log_info "  Unmounting: $mnt"
    umount -f "$mnt" 2>/dev/null || umount -l "$mnt" 2>/dev/null || true
done

# Step 4: Remove GlusterFS entries from fstab
log_info "Step 4: Cleaning /etc/fstab..."
sed -i '/glusterfs/d' /etc/fstab 2>/dev/null || true
sed -i '/GlusterFS/d' /etc/fstab 2>/dev/null || true

# Step 5: Detach from peers
log_info "Step 5: Detaching from peers..."
for peer in $(gluster peer status 2>/dev/null | grep "Hostname:" | awk '{print $2}'); do
    log_info "  Detaching peer: $peer"
    gluster peer detach "$peer" force --mode=script 2>/dev/null || true
done

# Step 6: Stop GlusterFS services
log_info "Step 6: Stopping GlusterFS services..."
systemctl stop glusterd 2>/dev/null || true
systemctl stop glusterfsd 2>/dev/null || true
systemctl disable glusterd 2>/dev/null || true
systemctl disable glusterfsd 2>/dev/null || true

# Step 7: Remove GlusterFS packages
log_info "Step 7: Removing GlusterFS packages..."
apt-get purge -y glusterfs-server glusterfs-client glusterfs-common 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# Step 8: Clean up GlusterFS directories
log_info "Step 8: Cleaning up GlusterFS directories..."
rm -rf /var/lib/glusterd 2>/dev/null || true
rm -rf /var/log/glusterfs 2>/dev/null || true
rm -rf /etc/glusterfs 2>/dev/null || true

# Step 9: Clean up common GlusterFS mount/brick paths
log_info "Step 9: Cleaning up common GlusterFS paths..."
COMMON_PATHS=(
    "/mnt/GlusterFS"
    "/mnt/glusterfs"
    "/data/glusterfs"
    "/data/brick"
    "/gluster"
)
for path in "${COMMON_PATHS[@]}"; do
    if [[ -d "$path" ]]; then
        log_info "  Removing: $path"
        rm -rf "$path" 2>/dev/null || true
    fi
done

# Step 10: Kill any remaining GlusterFS processes
log_info "Step 10: Killing remaining GlusterFS processes..."
pkill -9 gluster 2>/dev/null || true
pkill -9 glusterd 2>/dev/null || true
pkill -9 glusterfsd 2>/dev/null || true

log_info "=========================================="
log_info "  GlusterFS teardown complete!"
log_info "=========================================="
log_info "The node is now ready for MicroCeph."

