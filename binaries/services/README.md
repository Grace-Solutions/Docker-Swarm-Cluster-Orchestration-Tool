# Services Directory

This directory contains Docker Stack YAML files that will be automatically deployed to your Docker Swarm cluster.

## How It Works

1. **Automatic Discovery**: `clusterctl` scans this directory for `.yml` and `.yaml` files
2. **Metadata Parsing**: Each file's metadata is read from comment headers
3. **Selective Deployment**: Only enabled services are deployed
4. **Progress Tracking**: Detailed logging shows discovery, deployment progress, and metrics

## Service File Format

Each service file should be a valid Docker Stack Compose file (version 3.x) with metadata in comment headers:

```yaml
# NAME: My Service
# DESCRIPTION: Brief description of what this service does
# ENABLED: true

version: '3.8'

services:
  my-service:
    image: my-image:latest
    # ... rest of your service definition
```

### Metadata Fields

- **NAME**: Service name (optional - defaults to filename without extension)
- **DESCRIPTION**: Brief description of the service (optional)
- **ENABLED**: `true` or `false` - controls whether the service is deployed (default: `true`)

## Adding New Services

1. Create a new `.yml` or `.yaml` file in this directory
2. Add metadata headers at the top
3. Define your Docker Stack services
4. Run `clusterctl -config your-config.json`

The service will be automatically discovered and deployed if enabled.

## Disabling Services

To disable a service without deleting it:

1. Edit the service file
2. Change `# ENABLED: true` to `# ENABLED: false`
3. Re-run deployment

Or simply remove/rename the file (e.g., add `.disabled` extension).

## Example Services

### Portainer (Included)

`portainer.yml` - Container management UI for Docker Swarm
- Accessible at `https://<any-node-ip>:9443`
- Includes Portainer Agent (global) and Portainer CE (replicated)
- Uses GlusterFS for persistent storage

## Network Requirements

Services should use the pre-created overlay networks:

- **DOCKER-SWARM-INTERNAL**: Internal cluster communication (subnet: 10.128.0.0/16)
- **DOCKER-SWARM-EXTERNAL**: External-facing services (subnet: 10.129.0.0/16)

Example:
```yaml
networks:
  DOCKER-SWARM-INTERNAL:
    external: true
  DOCKER-SWARM-EXTERNAL:
    external: true
```

## Storage

For persistent storage, use GlusterFS mount paths:

```yaml
volumes:
  - /mnt/GlusterFS/Docker/Swarm/0001/data/YourService:/data
```

## Deployment Logs

During deployment, `clusterctl` logs:
- Total services found
- Enabled vs disabled count
- Processing progress (e.g., "deploying service 2/5")
- Success/failure for each service
- Final metrics (total time, success count, failure count)

## Best Practices

1. **One service per file**: Keep each stack in its own file for easier management
2. **Use descriptive names**: Make filenames and NAME metadata clear
3. **Document dependencies**: Use DESCRIPTION to note any prerequisites
4. **Test before enabling**: Set `ENABLED: false` while testing new services
5. **Use constraints**: Leverage node labels for service placement

## Troubleshooting

If a service fails to deploy:
1. Check the `clusterctl` logs for error details
2. Verify the YAML syntax is valid
3. Ensure required networks exist
4. Check node constraints match your cluster
5. Verify storage paths are accessible

## Advanced Usage

### Custom Service Names

The stack name defaults to the NAME metadata field. If not specified, it uses the filename without extension.

### Multiple Environments

You can maintain different service directories for different environments:

```bash
# Production
clusterctl -config prod.json  # Uses binaries/services/

# Staging (copy services to different location)
# Modify config to point to different services directory
```

