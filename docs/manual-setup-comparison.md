# Manual Setup vs dscotctl: Time Savings Breakdown

This document details what you would need to do manually to achieve the same result as running `dscotctl` once. Each section represents hours of work that the tool completes in seconds.

---

## Summary

| Component | Manual Time (per node) | With dscotctl |
|-----------|----------------------|---------------|
| SSH Key Setup | 10-15 min | Automatic |
| Hostname Configuration | 5 min | Automatic |
| Docker Installation | 15-20 min | Automatic |
| Docker Swarm Setup | 20-30 min | Automatic |
| MicroCeph/Distributed Storage | 45-90 min | Automatic |
| Overlay Network (Netbird/Tailscale/WireGuard) | 20-30 min | Automatic |
| Keepalived HA/VIP | 30-45 min | Automatic |
| Firewall Configuration | 30-60 min | Automatic |
| Service Deployment (Portainer, Nginx, etc.) | 30-45 min | Automatic |
| Node Labels & Geolocation | 15-20 min | Automatic |
| SSL Certificate Generation | 15-20 min | Automatic |
| Directory Structure & Permissions | 10-15 min | Automatic |
| **Total for 3-node cluster** | **6-10 hours** | **5-10 minutes** |

---

## 1. SSH Key Generation & Distribution

### Manual Steps (per node):
```bash
# On your workstation
ssh-keygen -t ed25519 -f ~/.ssh/cluster_key -N ""

# For EACH node:
ssh-copy-id -i ~/.ssh/cluster_key.pub root@node1.example.com
ssh-copy-id -i ~/.ssh/cluster_key.pub root@node2.example.com
ssh-copy-id -i ~/.ssh/cluster_key.pub root@node3.example.com

# Test connections
ssh -i ~/.ssh/cluster_key root@node1.example.com "echo 'Connected'"
# Repeat for each node...
```

**Time:** 10-15 minutes (more with troubleshooting auth issues)

---

## 2. Hostname Configuration

### Manual Steps (per node):
```bash
# SSH into each node
ssh root@node1

# Set hostname
hostnamectl set-hostname docker-swarm-node-0001

# Update /etc/hosts
echo "127.0.0.1 docker-swarm-node-0001" >> /etc/hosts

# Verify
hostname
# Repeat for each node with different hostnames...
```

**Time:** 5 minutes per node

---

## 3. Docker Installation & Configuration

### Manual Steps (per node):
```bash
# Remove old versions
apt-get remove docker docker-engine docker.io containerd runc

# Install prerequisites
apt-get update
apt-get install -y ca-certificates curl gnupg lsb-release

# Add Docker GPG key
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

# Install Docker
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Configure Docker daemon for TCP access (required for Portainer)
cat > /etc/docker/daemon.json << 'EOF'
{
  "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"],
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"}
}
EOF

# Override systemd to not pass -H flag
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/dockerd
EOF

# Reload and restart
systemctl daemon-reload
systemctl restart docker
systemctl enable docker

# Verify
docker run hello-world
# Repeat for each node...
```

**Time:** 15-20 minutes per node

---

## 4. Docker Swarm Initialization

### Manual Steps:
```bash
# On the FIRST manager node - initialize swarm
docker swarm init --advertise-addr <MANAGER_IP>

# Save the join tokens (they're different for managers vs workers!)
docker swarm join-token manager
docker swarm join-token worker

# On EACH additional manager node:
docker swarm join --token SWMTKN-1-xxx-manager <MANAGER_IP>:2377

# On EACH worker node:
docker swarm join --token SWMTKN-1-xxx-worker <MANAGER_IP>:2377

# Verify cluster
docker node ls

# Create overlay networks
docker network create --driver overlay --attachable ingress-routing
docker network create --driver overlay --attachable backend
```

**Time:** 20-30 minutes (more with troubleshooting connectivity)

---

## 5. MicroCeph Distributed Storage Setup

### Manual Steps (per node):
```bash
# Install MicroCeph
snap install microceph --channel reef/stable

# On the FIRST node - bootstrap the cluster
microceph cluster bootstrap

# Generate join tokens for other nodes
microceph cluster add node2
microceph cluster add node3

# On OTHER nodes - join the cluster
microceph cluster join <TOKEN>

# On EACH node with storage:
# Find available disks
lsblk
# Add each disk as an OSD
microceph disk add /dev/sdb --wipe

# OR create loop devices if no physical disks:
mkdir -p /mnt/ceph-loops
dd if=/dev/zero of=/mnt/ceph-loops/osd0.img bs=1M count=16384 status=progress
LOOP=$(losetup --find --show /mnt/ceph-loops/osd0.img)
microceph disk add $LOOP --wipe

# Wait for cluster to become healthy
ceph status  # Repeat until HEALTH_OK

# Create CephFS filesystem
ceph fs volume create docker-swarm

# On EACH node - mount CephFS
mkdir -p /mnt/MicroCephFS/docker-swarm
MONITORS=$(ceph mon dump | grep -oP '\d+\.\d+\.\d+\.\d+' | head -1)
SECRET=$(ceph auth get-key client.admin)
mount -t ceph $MONITORS:/ /mnt/MicroCephFS/docker-swarm -o name=admin,secret=$SECRET

# Add to /etc/fstab for persistence
echo "$MONITORS:/ /mnt/MicroCephFS/docker-swarm ceph name=admin,secret=$SECRET,_netdev 0 0" >> /etc/fstab

# Optional: Enable RADOS Gateway for S3
microceph enable rgw
radosgw-admin user create --uid=s3user --display-name="S3 User"
radosgw-admin subuser create --uid=s3user --subuser=s3user:swift --access=full
# Save and distribute credentials...
```

**Time:** 45-90 minutes (Ceph is complex and error-prone)

---

## 6. Overlay Network Setup (Netbird/Tailscale/WireGuard)

### Manual Steps (per node) - Netbird Example:
```bash
# Install Netbird
curl -fsSL https://pkgs.netbird.io/install.sh | sh

# Start the service
systemctl enable netbird
systemctl start netbird

# Authenticate with setup key
netbird up --setup-key YOUR_SETUP_KEY

# Verify connectivity
netbird status
ping other-node-hostname

# Repeat for each node...
```

**Time:** 20-30 minutes (more with firewall/NAT issues)

---

## 7. Keepalived High Availability VIP

### Manual Steps (per node):
```bash
# Install Keepalived
apt-get install -y keepalived

# Find an available VIP (requires scanning the network)
for ip in $(seq 200 254); do
  ping -c 1 -W 1 192.168.1.$ip > /dev/null 2>&1 || echo "Available: 192.168.1.$ip"
done

# Configure Keepalived on EACH node (with different priorities!)
cat > /etc/keepalived/keepalived.conf << 'EOF'
vrrp_instance VI_DOCKER {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 100  # Different on each node: 100, 99, 98...
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass secretpass
    }
    virtual_ipaddress {
        192.168.1.250/24
    }
}
EOF

# Enable and start
systemctl enable keepalived
systemctl start keepalived

# Verify VIP is active
ip addr show | grep 192.168.1.250
```

**Time:** 30-45 minutes (VIP conflicts, priority tuning)

---

## 8. Firewall Configuration (iptables)

### Manual Steps (per node):
```bash
# Install persistence
apt-get install -y iptables-persistent

# Backup existing rules
iptables-save > /root/iptables-backup.rules

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (don't lock yourself out!)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow Docker Swarm ports
iptables -A INPUT -p tcp --dport 2377 -j ACCEPT  # Cluster management
iptables -A INPUT -p tcp --dport 7946 -j ACCEPT  # Node communication
iptables -A INPUT -p udp --dport 7946 -j ACCEPT
iptables -A INPUT -p udp --dport 4789 -j ACCEPT  # Overlay network

# Allow overlay network interface
iptables -A INPUT -i wt0 -j ACCEPT  # Netbird
iptables -A INPUT -i tailscale0 -j ACCEPT  # Tailscale

# Allow Keepalived VRRP
iptables -A INPUT -p vrrp -j ACCEPT
iptables -A INPUT -d 224.0.0.18/32 -j ACCEPT

# Allow Docker bridge
iptables -A INPUT -i docker0 -j ACCEPT

# Block all other public traffic
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -s 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -s 192.168.0.0/16 -j ACCEPT
iptables -P INPUT DROP

# Save rules
iptables-save > /etc/iptables/rules.v4

# Repeat for each node...
```

**Time:** 30-60 minutes (one mistake = locked out)

---

## 9. Service Deployment

### Manual Steps:
```bash
# Create directory structure on shared storage
mkdir -p /mnt/MicroCephFS/docker-swarm/Portainer/data
mkdir -p /mnt/MicroCephFS/docker-swarm/Nginx/{conf,ssl,logs}
mkdir -p /mnt/MicroCephFS/docker-swarm/secrets

# Download/create nginx.conf, mime.types, default site configs...
curl -o /mnt/MicroCephFS/docker-swarm/Nginx/conf/mime.types \
  https://raw.githubusercontent.com/nginx/nginx/master/conf/mime.types

# Create docker-compose files
cat > portainer-stack.yml << 'EOF'
version: '3.8'
services:
  portainer:
    image: portainer/portainer-ce:latest
    # ... 50+ lines of configuration
EOF

# Deploy stacks
docker stack deploy -c portainer-stack.yml Portainer
docker stack deploy -c nginx-stack.yml Nginx

# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /mnt/MicroCephFS/docker-swarm/Nginx/ssl/default.key \
  -out /mnt/MicroCephFS/docker-swarm/Nginx/ssl/default.crt \
  -subj "/CN=localhost"

# Configure reverse proxy routes...
```

**Time:** 30-45 minutes

---

## 10. Node Labels & Geolocation

### Manual Steps (per node):
```bash
# Query geolocation API
curl -s http://ip-api.com/json | jq

# Apply labels to each node
docker node update --label-add geo.country="United States" node1
docker node update --label-add geo.region="Virginia" node1
docker node update --label-add geo.city="Ashburn" node1
docker node update --label-add geo.isp="Amazon" node1
docker node update --label-add storage.enabled=true node1
docker node update --label-add loadbalancer=true node1
# Repeat for EVERY label on EVERY node...
```

**Time:** 15-20 minutes

---

## The Bottom Line

For a **3-node cluster**, manual setup takes approximately **6-10 hours** of focused work by someone who knows exactly what they're doing. Add troubleshooting time for first-timers, and you're looking at **1-2 days**.

With `dscotctl`:

```bash
# Edit config
nano dscotctl.json

# Deploy everything
./dscotctl-linux-amd64 -configpath dscotctl.json
```

**Total time: 5-10 minutes.**

That's a **98% reduction in deployment time** and eliminates the risk of human error in security-critical configurations like firewalls and authentication.

