package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// ServiceMetadata represents metadata parsed from a service YAML file
type ServiceMetadata struct {
	Name        string
	Description string
	Enabled     bool
	FilePath    string
	FileName    string
}

// DeploymentMetrics tracks deployment statistics
type DeploymentMetrics struct {
	TotalFound    int
	TotalEnabled  int
	TotalDisabled int
	TotalSuccess  int
	TotalFailed   int
	StartTime     time.Time
	EndTime       time.Time
	Duration      time.Duration
}

// ClusterInfo contains information about the cluster composition for dynamic constraint handling
type ClusterInfo struct {
	HasDedicatedWorkers bool // true if there are nodes with role="worker" (not just managers or "both")
}

const (
	DefaultServiceDefinitionDirectory = "services"
)

// DiscoverServices scans the service definition directory for YAML files and parses metadata
func DiscoverServices(serviceDefDir string) ([]ServiceMetadata, error) {
	log := logging.L().With("component", "services")

	// If serviceDefDir is empty, use default relative to binary
	if serviceDefDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable path: %w", err)
		}
		binaryDir := filepath.Dir(exePath)
		serviceDefDir = filepath.Join(binaryDir, DefaultServiceDefinitionDirectory)
	}

	log.Infow("scanning service definition directory", "path", serviceDefDir)

	// Check if directory exists
	if _, err := os.Stat(serviceDefDir); os.IsNotExist(err) {
		log.Warnw("service definition directory does not exist", "path", serviceDefDir)
		return []ServiceMetadata{}, nil
	}

	// Read directory
	entries, err := os.ReadDir(serviceDefDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read service definition directory: %w", err)
	}

	var services []ServiceMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		fileName := entry.Name()
		ext := strings.ToLower(filepath.Ext(fileName))

		// Only process .yml and .yaml files
		if ext != ".yml" && ext != ".yaml" {
			continue
		}

		filePath := filepath.Join(serviceDefDir, fileName)
		metadata, err := parseServiceMetadata(filePath, fileName)
		if err != nil {
			log.Warnw("failed to parse service metadata", "file", fileName, "error", err)
			continue
		}

		services = append(services, metadata)
	}

	// Sort services by filename for deployment order (e.g., 001-service.yml, 002-service.yml)
	sort.Slice(services, func(i, j int) bool {
		return services[i].FileName < services[j].FileName
	})

	return services, nil
}

// parseServiceMetadata extracts metadata from a service YAML file
func parseServiceMetadata(filePath, fileName string) (ServiceMetadata, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return ServiceMetadata{}, fmt.Errorf("failed to read file: %w", err)
	}

	metadata := ServiceMetadata{
		FilePath: filePath,
		FileName: fileName,
		Enabled:  true, // Default to enabled
	}

	// Parse metadata from comments at the top of the file
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Stop parsing at first non-comment line
		if !strings.HasPrefix(line, "#") {
			break
		}

		// Remove leading '#' and trim
		line = strings.TrimSpace(strings.TrimPrefix(line, "#"))

		// Parse metadata fields
		if strings.HasPrefix(line, "NAME:") {
			metadata.Name = strings.TrimSpace(strings.TrimPrefix(line, "NAME:"))
		} else if strings.HasPrefix(line, "DESCRIPTION:") {
			metadata.Description = strings.TrimSpace(strings.TrimPrefix(line, "DESCRIPTION:"))
		} else if strings.HasPrefix(line, "ENABLED:") {
			enabledStr := strings.TrimSpace(strings.TrimPrefix(line, "ENABLED:"))
			metadata.Enabled = strings.ToLower(enabledStr) == "true"
		}
	}

	// If no name was specified, use filename without extension
	if metadata.Name == "" {
		metadata.Name = strings.TrimSuffix(fileName, filepath.Ext(fileName))
	}

	return metadata, nil
}

// DeployServices deploys all enabled services to the Docker Swarm cluster.
// storageMountPath is the distributed storage mount path for path replacement in service YAMLs.
// clusterInfo contains cluster composition for dynamic constraint handling.
func DeployServices(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, serviceDefDir string, storageMountPath string, clusterInfo ClusterInfo) (*DeploymentMetrics, error) {
	log := logging.L().With("component", "services")
	metrics := &DeploymentMetrics{
		StartTime: time.Now(),
	}

	// Log cluster composition for constraint handling
	log.Infow("cluster composition for constraint handling",
		"hasDedicatedWorkers", clusterInfo.HasDedicatedWorkers,
	)

	// Discover services
	services, err := DiscoverServices(serviceDefDir)
	if err != nil {
		return metrics, fmt.Errorf("failed to discover services: %w", err)
	}

	metrics.TotalFound = len(services)

	// Count enabled/disabled
	for _, svc := range services {
		if svc.Enabled {
			metrics.TotalEnabled++
		} else {
			metrics.TotalDisabled++
		}
	}

	// Log discovery summary
	log.Infow("service discovery complete",
		"totalFound", metrics.TotalFound,
		"enabled", metrics.TotalEnabled,
		"disabled", metrics.TotalDisabled,
	)

	// Log each service
	for i, svc := range services {
		status := "enabled"
		if !svc.Enabled {
			status = "disabled"
		}
		log.Infow(fmt.Sprintf("service %d/%d", i+1, metrics.TotalFound),
			"name", svc.Name,
			"file", svc.FileName,
			"status", status,
			"description", svc.Description,
		)
	}

	// Deploy enabled services
	for i, svc := range services {
		if !svc.Enabled {
			log.Infow(fmt.Sprintf("skipping disabled service %d/%d", i+1, metrics.TotalFound),
				"name", svc.Name,
			)
			continue
		}

		log.Infow(fmt.Sprintf("deploying service %d/%d", i+1, metrics.TotalFound),
			"name", svc.Name,
			"file", svc.FileName,
		)

		if err := deployService(ctx, sshPool, primaryMaster, svc, storageMountPath, clusterInfo); err != nil {
			log.Errorw(fmt.Sprintf("failed to deploy service %d/%d", i+1, metrics.TotalFound),
				"name", svc.Name,
				"error", err,
			)
			metrics.TotalFailed++
		} else {
			log.Infow(fmt.Sprintf("✅ successfully deployed service %d/%d", i+1, metrics.TotalFound),
				"name", svc.Name,
			)
			metrics.TotalSuccess++
		}
	}

	// Calculate final metrics
	metrics.EndTime = time.Now()
	metrics.Duration = metrics.EndTime.Sub(metrics.StartTime)

	// Log final summary
	log.Infow("service deployment complete",
		"totalFound", metrics.TotalFound,
		"enabled", metrics.TotalEnabled,
		"disabled", metrics.TotalDisabled,
		"success", metrics.TotalSuccess,
		"failed", metrics.TotalFailed,
		"duration", metrics.Duration.String(),
	)

	// Show final network summary
	showNetworkSummary(ctx, sshPool, primaryMaster)

	return metrics, nil
}

// deployService deploys a single service to the Docker Swarm cluster
func deployService(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, svc ServiceMetadata, storageMountPath string, clusterInfo ClusterInfo) error {
	log := logging.L().With("component", "services", "service", svc.Name)

	// Read service file
	content, err := os.ReadFile(svc.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	// Replace storage mount paths if storageMountPath is specified
	processedContent := string(content)
	modified := false
	if storageMountPath != "" {
		newContent := replaceStoragePaths(processedContent, storageMountPath)
		if newContent != processedContent {
			processedContent = newContent
			modified = true
			log.Infow("replaced storage mount paths", "storageMountPath", storageMountPath)
		}
	}

	// Adjust placement constraints based on cluster composition
	// If no dedicated workers, replace node.role==worker with node.role==manager
	processedContent, constraintChanged := adjustPlacementConstraints(processedContent, clusterInfo)
	if constraintChanged {
		modified = true
		log.Infow("adjusted placement constraints for cluster composition", "hasDedicatedWorkers", clusterInfo.HasDedicatedWorkers)
	}

	// Save modified content back to local file so it can be redeployed with dynamic settings
	if modified {
		if err := os.WriteFile(svc.FilePath, []byte(processedContent), 0644); err != nil {
			log.Warnw("failed to save modified service file", "file", svc.FilePath, "error", err)
		} else {
			log.Infow("saved modified service file", "file", svc.FilePath)
		}
	}

	// Create temporary file on remote host
	remoteFile := fmt.Sprintf("/tmp/dscotctl-service-%s.yml", svc.Name)

	// Write content to remote file
	writeCmd := fmt.Sprintf("cat > %s << 'DSCOTCTL_EOF'\n%s\nDSCOTCTL_EOF", remoteFile, processedContent)

	log.Infow("uploading service definition", "host", primaryMaster, "remoteFile", remoteFile, "size", len(processedContent))

	if _, stderr, err := sshPool.Run(ctx, primaryMaster, writeCmd); err != nil {
		return fmt.Errorf("failed to upload service file: %w (stderr: %s)", err, stderr)
	}

	// Deploy using docker stack deploy with --prune to remove orphaned services
	// Use --detach=true explicitly to avoid warning about future default change
	deployCmd := fmt.Sprintf("docker stack deploy --prune --detach=true -c %s %s", remoteFile, svc.Name)

	log.Infow("deploying Docker stack", "host", primaryMaster, "stack", svc.Name, "command", deployCmd)

	stdout, stderr, err := sshPool.Run(ctx, primaryMaster, deployCmd)
	if err != nil {
		return fmt.Errorf("failed to deploy stack: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✅ stack deployed", "stack", svc.Name, "stdout", strings.TrimSpace(stdout))

	// Clean up temporary file
	cleanupCmd := fmt.Sprintf("rm -f %s", remoteFile)
	if _, _, err := sshPool.Run(ctx, primaryMaster, cleanupCmd); err != nil {
		log.Warnw("failed to cleanup temporary file", "file", remoteFile, "error", err)
	}

	// Verify deployment - show service status, networks, and logs
	verifyDeployment(ctx, sshPool, primaryMaster, svc.Name)

	return nil
}

// adjustPlacementConstraints modifies placement constraints in YAML content based on cluster composition.
// If the cluster has no dedicated workers (all managers or "both"), it replaces node.role==worker
// with node.role==manager so services can be scheduled on manager nodes.
// Returns the modified content and a boolean indicating if changes were made.
func adjustPlacementConstraints(content string, clusterInfo ClusterInfo) (string, bool) {
	if clusterInfo.HasDedicatedWorkers {
		// Cluster has dedicated workers, no adjustment needed
		return content, false
	}

	// No dedicated workers - replace node.role==worker with node.role==manager
	// Pattern matches various YAML formats:
	//   - node.role==worker
	//   - node.role == worker
	//   - "node.role==worker"
	pattern := regexp.MustCompile(`node\.role\s*==\s*worker`)
	if !pattern.MatchString(content) {
		return content, false
	}

	modified := pattern.ReplaceAllString(content, "node.role==manager")
	return modified, true
}

// replaceStoragePaths replaces distributed storage mount paths in YAML content with the configured path.
// It dynamically matches any /mnt/<storage-type>/<cluster-name> pattern and replaces with storageMountPath.
// Preserves any subdirectories after the base mount path.
func replaceStoragePaths(content string, storageMountPath string) string {
	// Dynamic pattern: /mnt/<any-storage-type>/<any-cluster-name>
	// Matches: /mnt/GlusterFS/docker-swarm-0001, /mnt/cephfs/my-cluster, /mnt/nfs/prod, etc.
	// The pattern matches /mnt/ followed by a storage type name and cluster/volume name
	// Storage type: alphanumeric with optional hyphens/underscores (e.g., GlusterFS, MicroCephFS, cephfs, nfs)
	// Cluster name: alphanumeric with optional hyphens/underscores/dots (e.g., docker-swarm-0001, my-cluster)
	// Preserves anything after (e.g., /data/Portainer, /scripts)
	pattern := `/mnt/[A-Za-z0-9_-]+/[A-Za-z0-9._-]+`

	re := regexp.MustCompile(pattern)
	return re.ReplaceAllString(content, storageMountPath)
}

// verifyDeployment shows verification info for a deployed service including
// service status, network info, and recent logs.
func verifyDeployment(ctx context.Context, sshPool *ssh.Pool, host string, stackName string) {
	log := logging.L().With("component", "services", "stack", stackName)

	// Get service list for this stack
	serviceListCmd := fmt.Sprintf("docker service ls --filter name=%s --format '{{.ID}}\\t{{.Name}}\\t{{.Mode}}\\t{{.Replicas}}\\t{{.Image}}'", stackName)
	log.Infow("→ verifying deployment", "command", serviceListCmd)

	stdout, _, err := sshPool.Run(ctx, host, serviceListCmd)
	if err != nil {
		log.Warnw("failed to get service list", "error", err)
	} else if strings.TrimSpace(stdout) != "" {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		for _, line := range lines {
			parts := strings.Split(line, "\t")
			if len(parts) >= 5 {
				log.Infow("  service status",
					"id", parts[0],
					"name", parts[1],
					"mode", parts[2],
					"replicas", parts[3],
					"image", parts[4],
				)
			}
		}
	}

	// Get networks used by services in this stack
	networkCmd := fmt.Sprintf("docker service inspect %s_%s --format '{{range .Spec.TaskTemplate.Networks}}{{.Target}} {{end}}' 2>/dev/null || docker service inspect %s --format '{{range .Spec.TaskTemplate.Networks}}{{.Target}} {{end}}' 2>/dev/null || echo ''", stackName, stackName, stackName)
	stdout, _, err = sshPool.Run(ctx, host, networkCmd)
	if err == nil && strings.TrimSpace(stdout) != "" {
		networkIDs := strings.Fields(strings.TrimSpace(stdout))
		for _, netID := range networkIDs {
			// Get network details
			netDetailCmd := fmt.Sprintf("docker network inspect %s --format '{{.Name}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}|{{.Ingress}}|{{.Internal}}'", netID)
			netOut, _, nerr := sshPool.Run(ctx, host, netDetailCmd)
			if nerr == nil && strings.TrimSpace(netOut) != "" {
				parts := strings.Split(strings.TrimSpace(netOut), "|")
				if len(parts) >= 4 {
					netType := "overlay"
					if parts[2] == "true" {
						netType = "ingress"
					} else if parts[3] == "true" {
						netType = "internal"
					}
					log.Infow("  network",
						"name", parts[0],
						"subnet", parts[1],
						"type", netType,
					)
				}
			}
		}
	}

	// Get recent logs (last 5 lines) for services in this stack
	logsCmd := fmt.Sprintf("docker service logs --tail 5 --no-trunc %s_%s 2>&1 || docker service logs --tail 5 --no-trunc %s 2>&1 || echo 'no logs available'", stackName, stackName, stackName)
	log.Infow("→ recent logs", "command", fmt.Sprintf("docker service logs --tail 5 %s", stackName))
	stdout, _, err = sshPool.Run(ctx, host, logsCmd)
	if err == nil && strings.TrimSpace(stdout) != "" {
		logLines := strings.Split(strings.TrimSpace(stdout), "\n")
		// Show at most 5 lines
		maxLines := 5
		if len(logLines) < maxLines {
			maxLines = len(logLines)
		}
		for i := 0; i < maxLines; i++ {
			// Truncate long lines
			line := logLines[i]
			if len(line) > 200 {
				line = line[:200] + "..."
			}
			log.Infow("  log", "line", line)
		}
	}
}

// showNetworkSummary displays a summary of all Docker networks at the end of deployment.
func showNetworkSummary(ctx context.Context, sshPool *ssh.Pool, host string) {
	log := logging.L().With("component", "services")

	// Get all networks with their subnets
	networkCmd := "docker network ls --format '{{.Name}}' | xargs -I {} docker network inspect {} --format '{{.Name}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}|{{.Driver}}|{{.Ingress}}|{{.Internal}}' 2>/dev/null"
	log.Infow("=== Network Summary ===", "command", "docker network ls + inspect")

	stdout, _, err := sshPool.Run(ctx, host, networkCmd)
	if err != nil {
		log.Warnw("failed to get network summary", "error", err)
		return
	}

	if strings.TrimSpace(stdout) == "" {
		log.Infow("no networks found")
		return
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) >= 5 {
			name := parts[0]
			subnet := parts[1]
			driver := parts[2]
			isIngress := parts[3] == "true"
			isInternal := parts[4] == "true"

			netType := driver
			if isIngress {
				netType = "ingress"
			} else if isInternal {
				netType = "internal"
			}

			// Skip networks without subnets (like host, none)
			if subnet == "" {
				continue
			}

			log.Infow("  network",
				"name", name,
				"subnet", subnet,
				"type", netType,
			)
		}
	}
}
