# Services Directory

Docker Stack YAML files in this directory are automatically deployed to your Docker Swarm cluster.

---

## Included Services

| File | Service | Description |
|------|---------|-------------|
| `001-PortainerAgent.yml` | Portainer Agent | Global agent on all nodes for container management |
| `002-NginxUI.yml` | NginxUI | Web-based Nginx management with reverse proxy for cluster services |
| `003-Portainer.yml` | Portainer CE | Docker management GUI accessible via `/portainer/` |

---

## Service File Format

```yaml
# NAME: My Service
# DESCRIPTION: Brief description
# ENABLED: true

version: '3.8'

services:
  my-service:
    image: my-image:latest
    deploy:
      resources:
        limits:
          cpus: '8'
          memory: 2G
        reservations:
          memory: 512M
```

| Metadata | Description |
|----------|-------------|
| `NAME` | Service name (defaults to filename) |
| `DESCRIPTION` | Brief description |
| `ENABLED` | `true` or `false` (default: `true`) |

---

## Deployment Order

Services deploy in **alphabetical order by filename**. Use numeric prefixes:

```
001-PortainerAgent.yml  → First
002-NginxUI.yml         → Second
003-Portainer.yml       → Third
100-MyApp.yml           → After core services
```

---

## Networks

| Network | Purpose | Subnet |
|---------|---------|--------|
| `DOCKER-SWARM-CLUSTER-INTERNAL-COMMUNICATION` | Internal cluster traffic (no external access) | 10.10.0.0/20 |
| `ingress` | Docker's default routing mesh for published ports | Managed by Docker |

```yaml
networks:
  DOCKER-SWARM-CLUSTER-INTERNAL-COMMUNICATION:
    external: true
```

For external-facing services, use Docker's default `ingress` network via published ports.

---

## Storage Path Replacement

Storage paths are automatically replaced with your configured `mountPath`:

```yaml
# In YAML file:
volumes:
  - /mnt/MicroCephFS/docker-swarm-0001/data:/data

# Becomes (if mountPath is /mnt/MicroCephFS/my-cluster):
volumes:
  - /mnt/MicroCephFS/my-cluster/data:/data
```

---

## Adding Services

1. Create `XXX-ServiceName.yml` in this directory
2. Add metadata headers
3. Run deployment:
```bash
./dscotctl-linux-amd64 -configpath dscotctl.json.example
```

## Disabling Services

Change `# ENABLED: true` to `# ENABLED: false` or rename file to `.yml.disabled`

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Service fails to deploy | Check `dscotctl` logs for errors |
| Network not found | Ensure deployment completed Phase 7 (Swarm setup) |
| Storage path errors | Verify CephFS is mounted on nodes |
| Constraint failures | Check node labels match service constraints |
