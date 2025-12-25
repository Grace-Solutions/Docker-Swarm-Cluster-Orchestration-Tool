package services

import (
	"context"
	"encoding/json"
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
	HasDedicatedWorkers bool     // true if there are nodes with role="worker" (not just managers or "both")
	AllNodes            []string // list of all SSH-accessible nodes for directory creation
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

	// Parse bind mounts from the processed content and create directories on all nodes
	// This ensures directories exist before service deployment to avoid mount failures
	if storageMountPath != "" && len(clusterInfo.AllNodes) > 0 {
		bindMountPaths := parseBindMounts(processedContent, storageMountPath)
		if len(bindMountPaths) > 0 {
			if err := ensureDirectoriesOnNodes(ctx, sshPool, clusterInfo.AllNodes, bindMountPaths, svc.Name); err != nil {
				log.Warnw("failed to create some bind mount directories", "error", err)
				// Continue anyway - directories might already exist or be created by other means
			}
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

// parseBindMounts extracts host paths from bind mount volume definitions in YAML content.
// It parses both short form ("host:container") and long form (source:/path, target:/path) volumes.
// Only returns paths that start with the storage mount path prefix.
func parseBindMounts(content string, storageMountPath string) []string {
	if storageMountPath == "" {
		return nil
	}

	var paths []string
	seenPaths := make(map[string]bool)

	// Pattern for short form volumes: - /host/path:/container/path or - /host/path:/container/path:ro
	shortFormPattern := regexp.MustCompile(`^\s*-\s*([^:\s]+):([^:\s]+)(?::[^:\s]+)?$`)

	// Pattern for long form source: /host/path
	longFormPattern := regexp.MustCompile(`^\s*source:\s*([^\s]+)`)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		var hostPath string

		// Try short form first
		if matches := shortFormPattern.FindStringSubmatch(line); len(matches) >= 2 {
			hostPath = matches[1]
		} else if matches := longFormPattern.FindStringSubmatch(line); len(matches) >= 2 {
			// Try long form
			hostPath = matches[1]
		}

		// Only include paths under the storage mount path
		if hostPath != "" && strings.HasPrefix(hostPath, storageMountPath) {
			// Normalize path and avoid duplicates
			hostPath = strings.TrimSuffix(hostPath, "/")
			if !seenPaths[hostPath] {
				seenPaths[hostPath] = true
				paths = append(paths, hostPath)
			}
		}
	}

	return paths
}

// ensureDirectoriesOnNodes creates directories on all nodes if they don't exist.
// This is idempotent - directories are created with mkdir -p only if they don't exist.
func ensureDirectoriesOnNodes(ctx context.Context, sshPool *ssh.Pool, nodes []string, directories []string, serviceName string) error {
	if len(directories) == 0 || len(nodes) == 0 {
		return nil
	}

	log := logging.L().With("component", "services", "service", serviceName)

	// Build a single command that creates all directories
	// Using mkdir -p makes this idempotent
	var quotedPaths []string
	for _, dir := range directories {
		quotedPaths = append(quotedPaths, fmt.Sprintf("'%s'", dir))
	}
	mkdirCmd := fmt.Sprintf("mkdir -p %s", strings.Join(quotedPaths, " "))

	log.Infow("ensuring bind mount directories exist",
		"directories", directories,
		"nodeCount", len(nodes),
	)

	// Create directories on all nodes in parallel by iterating
	// (SSH pool handles connection reuse)
	var errors []string
	for _, node := range nodes {
		log.Infow("creating directories", "host", node, "command", mkdirCmd)
		if _, stderr, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
			errMsg := fmt.Sprintf("%s: %v (stderr: %s)", node, err, stderr)
			log.Warnw("failed to create directories on node", "host", node, "error", err, "stderr", stderr)
			errors = append(errors, errMsg)
		} else {
			log.Infow("✅ directories created", "host", node)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to create directories on some nodes: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ServiceInfo represents Docker service information from JSON output.
type ServiceInfo struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	Mode     string `json:"Mode"`
	Replicas string `json:"Replicas"`
	Image    string `json:"Image"`
}

// NetworkInfo represents Docker network information from JSON output.
type NetworkInfo struct {
	Name     string `json:"Name"`
	Scope    string `json:"Scope"`
	Driver   string `json:"Driver"`
	Ingress  bool   `json:"Ingress"`
	Internal bool   `json:"Internal"`
	IPAM     struct {
		Config []struct {
			Subnet  string `json:"Subnet"`
			Gateway string `json:"Gateway"`
		} `json:"Config"`
	} `json:"IPAM"`
}

// verifyDeployment shows verification info for a deployed service including
// service status, network info, and recent logs. Uses JSON output from Docker
// for reliable parsing.
func verifyDeployment(ctx context.Context, sshPool *ssh.Pool, host string, stackName string) {
	log := logging.L().With("component", "services", "stack", stackName)

	// Get all services filtered by stack label (more reliable than name filter)
	// Use JSON format for proper parsing
	serviceListCmd := fmt.Sprintf("docker service ls --filter label=com.docker.stack.namespace=%s --format json", stackName)
	log.Infow("→ verifying deployment", "command", serviceListCmd)

	stdout, _, err := sshPool.Run(ctx, host, serviceListCmd)
	if err != nil {
		log.Warnw("failed to get service list", "error", err)
		return
	}

	// Parse JSON lines (each line is a separate JSON object)
	var serviceNames []string
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var svc ServiceInfo
		if err := json.Unmarshal([]byte(line), &svc); err != nil {
			log.Warnw("failed to parse service JSON", "line", line, "error", err)
			continue
		}
		log.Infow("  service status",
			"id", svc.ID,
			"name", svc.Name,
			"mode", svc.Mode,
			"replicas", svc.Replicas,
			"image", svc.Image,
		)
		serviceNames = append(serviceNames, svc.Name)
	}

	// Get networks used by services in this stack using JSON
	// Collect unique network IDs from all services
	networkIDs := make(map[string]bool)
	for _, svcName := range serviceNames {
		inspectCmd := fmt.Sprintf("docker service inspect %s --format json", svcName)
		stdout, _, err := sshPool.Run(ctx, host, inspectCmd)
		if err != nil {
			continue
		}
		// Parse the service inspect output to get network IDs
		// The output is a JSON array with one element
		var inspectResult []struct {
			Spec struct {
				TaskTemplate struct {
					Networks []struct {
						Target string `json:"Target"`
					} `json:"Networks"`
				} `json:"TaskTemplate"`
			} `json:"Spec"`
		}
		if err := json.Unmarshal([]byte(stdout), &inspectResult); err != nil {
			continue
		}
		if len(inspectResult) > 0 {
			for _, net := range inspectResult[0].Spec.TaskTemplate.Networks {
				networkIDs[net.Target] = true
			}
		}
	}

	// Get details for each network using JSON
	for netID := range networkIDs {
		netInspectCmd := fmt.Sprintf("docker network inspect %s --format json", netID)
		stdout, _, err := sshPool.Run(ctx, host, netInspectCmd)
		if err != nil {
			continue
		}
		// Output is a JSON array
		var networks []NetworkInfo
		if err := json.Unmarshal([]byte(stdout), &networks); err != nil {
			continue
		}
		if len(networks) > 0 {
			net := networks[0]
			netType := "overlay"
			if net.Ingress {
				netType = "ingress"
			} else if net.Internal {
				netType = "internal"
			}
			subnet := ""
			if len(net.IPAM.Config) > 0 {
				subnet = net.IPAM.Config[0].Subnet
			}
			log.Infow("  network",
				"name", net.Name,
				"subnet", subnet,
				"type", netType,
			)
		}
	}

	// Get recent logs for each service
	for _, svcName := range serviceNames {
		logsCmd := fmt.Sprintf("docker service logs --tail 5 --no-trunc %s 2>&1", svcName)
		log.Infow("→ recent logs", "command", fmt.Sprintf("docker service logs --tail 5 %s", svcName))
		stdout, _, err := sshPool.Run(ctx, host, logsCmd)
		if err == nil && strings.TrimSpace(stdout) != "" && !strings.Contains(stdout, "no logs available") {
			logLines := strings.Split(strings.TrimSpace(stdout), "\n")
			maxLines := 5
			if len(logLines) < maxLines {
				maxLines = len(logLines)
			}
			for i := 0; i < maxLines; i++ {
				line := logLines[i]
				if len(line) > 200 {
					line = line[:200] + "..."
				}
				log.Infow("  log", "service", svcName, "line", line)
			}
		}
	}
}

// showNetworkSummary displays a summary of all Docker networks at the end of deployment.
// Uses JSON output from Docker for reliable parsing.
func showNetworkSummary(ctx context.Context, sshPool *ssh.Pool, host string) {
	log := logging.L().With("component", "services")

	// Get all networks in JSON format
	networkListCmd := "docker network ls --format json"
	log.Infow("=== Network Summary ===", "command", networkListCmd)

	stdout, _, err := sshPool.Run(ctx, host, networkListCmd)
	if err != nil {
		log.Warnw("failed to get network list", "error", err)
		return
	}

	if strings.TrimSpace(stdout) == "" {
		log.Infow("no networks found")
		return
	}

	// Parse JSON lines and get details for each network
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var netBasic struct {
			Name   string `json:"Name"`
			Driver string `json:"Driver"`
		}
		if err := json.Unmarshal([]byte(line), &netBasic); err != nil {
			continue
		}

		// Get full network details using JSON inspect
		inspectCmd := fmt.Sprintf("docker network inspect %s --format json", netBasic.Name)
		stdout, _, err := sshPool.Run(ctx, host, inspectCmd)
		if err != nil {
			continue
		}

		var networks []NetworkInfo
		if err := json.Unmarshal([]byte(stdout), &networks); err != nil {
			continue
		}
		if len(networks) == 0 {
			continue
		}

		net := networks[0]
		subnet := ""
		if len(net.IPAM.Config) > 0 {
			subnet = net.IPAM.Config[0].Subnet
		}

		// Skip networks without subnets (like host, none)
		if subnet == "" {
			continue
		}

		netType := net.Driver
		if net.Ingress {
			netType = "ingress"
		} else if net.Internal {
			netType = "internal"
		}

		log.Infow("  network",
			"name", net.Name,
			"subnet", subnet,
			"type", netType,
		)
	}
}
