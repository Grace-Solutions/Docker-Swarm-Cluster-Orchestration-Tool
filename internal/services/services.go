package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"dscotctl/internal/defaults"
	"dscotctl/internal/logging"
	"dscotctl/internal/ssh"
)

// ServiceMetadata represents metadata parsed from a service YAML file
type ServiceMetadata struct {
	Name        string
	Description string
	Enabled     bool
	FilePath    string
	FileName    string
	// Nginx proxy configuration (parsed from headers)
	NginxProxy       bool   // NGINX_PROXY: true/false - whether to create a reverse proxy rule
	NginxPath        string // NGINX_PATH: /path - URL path for the proxy (defaults to /ServiceName)
	NginxPort        int    // NGINX_PORT: 8080 - internal port the service listens on
	NginxWebSocket   bool   // NGINX_WEBSOCKET: true/false - enable WebSocket support
	NginxTCPStream   string // NGINX_TCP_STREAM: backend_port:nginx_port - TCP stream proxy (e.g., 8000:9001)
	NginxBasicAuth   string // NGINX_BASIC_AUTH: user:pass - enable basic auth with these credentials
	NginxStripPrefix bool   // NGINX_STRIP_PREFIX: true/false - strip location prefix before proxying (default: true)
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
	HasDedicatedWorkers       bool              // true if there are nodes with role="worker" (not just managers or "both")
	AllNodes                  []string          // list of all SSH-accessible nodes for directory creation
	DistributedStorageEnabled bool              // true if distributed storage is enabled (shared across nodes)
	PrimaryMaster             string            // primary master node SSH address
	DockerManagerHost         string            // hostname/IP for Docker API on primary manager (for Portainer etc.)
	S3CredentialsFile         string            // path to S3 credentials file (if RGW enabled)
	RadosGatewayPort          int               // RADOS Gateway port (if RGW enabled)
	KeepalivedVIP             string            // virtual IP address if keepalived enabled (empty if not)
	PortainerEnabled          bool              // true if Portainer service is deployed
	NodeHostnameToSSH         map[string]string // Docker Swarm hostname -> SSH address mapping
}

const (
	DefaultServiceDefinitionDirectory = "services"
	DefaultScriptsDirectory           = "scripts"
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
		} else if strings.HasPrefix(line, "NGINX_PROXY:") {
			proxyStr := strings.TrimSpace(strings.TrimPrefix(line, "NGINX_PROXY:"))
			metadata.NginxProxy = strings.ToLower(proxyStr) == "true"
		} else if strings.HasPrefix(line, "NGINX_PATH:") {
			metadata.NginxPath = strings.TrimSpace(strings.TrimPrefix(line, "NGINX_PATH:"))
		} else if strings.HasPrefix(line, "NGINX_PORT:") {
			portStr := strings.TrimSpace(strings.TrimPrefix(line, "NGINX_PORT:"))
			if port, err := strconv.Atoi(portStr); err == nil {
				metadata.NginxPort = port
			}
		} else if strings.HasPrefix(line, "NGINX_WEBSOCKET:") {
			wsStr := strings.TrimSpace(strings.TrimPrefix(line, "NGINX_WEBSOCKET:"))
			metadata.NginxWebSocket = strings.ToLower(wsStr) == "true"
		} else if strings.HasPrefix(line, "NGINX_TCP_STREAM:") {
			metadata.NginxTCPStream = strings.TrimSpace(strings.TrimPrefix(line, "NGINX_TCP_STREAM:"))
		} else if strings.HasPrefix(line, "NGINX_BASIC_AUTH:") {
			metadata.NginxBasicAuth = strings.TrimSpace(strings.TrimPrefix(line, "NGINX_BASIC_AUTH:"))
		} else if strings.HasPrefix(line, "NGINX_STRIP_PREFIX:") {
			stripStr := strings.TrimSpace(strings.TrimPrefix(line, "NGINX_STRIP_PREFIX:"))
			// Default is true, so only set false if explicitly "false"
			metadata.NginxStripPrefix = strings.ToLower(stripStr) != "false"
		}
	}

	// If no name was specified, use filename without extension
	if metadata.Name == "" {
		metadata.Name = strings.TrimSuffix(fileName, filepath.Ext(fileName))
	}

	// Default NginxPath to /ServiceName if proxy is enabled but no path specified
	if metadata.NginxProxy && metadata.NginxPath == "" {
		metadata.NginxPath = "/" + strings.ToLower(metadata.Name)
	}

	// Default NginxStripPrefix to true if proxy is enabled and not explicitly set
	if metadata.NginxProxy && !metadata.NginxStripPrefix {
		// Check if it was explicitly set to false by looking for the header
		explicitlySetFalse := false
		for _, line := range lines {
			if strings.HasPrefix(line, "NGINX_STRIP_PREFIX:") {
				stripStr := strings.TrimSpace(strings.TrimPrefix(line, "NGINX_STRIP_PREFIX:"))
				if strings.ToLower(stripStr) == "false" {
					explicitlySetFalse = true
				}
				break
			}
		}
		if !explicitlySetFalse {
			metadata.NginxStripPrefix = true
		}
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

	// Create secrets directory on shared storage if enabled
	if storageMountPath != "" {
		secretsDir := filepath.ToSlash(filepath.Join(storageMountPath, "secrets"))
		log.Infow("creating secrets directory on shared storage", "path", secretsDir)
		mkdirCmd := fmt.Sprintf("mkdir -p '%s'", secretsDir)
		if _, stderr, err := sshPool.Run(ctx, primaryMaster, mkdirCmd); err != nil {
			log.Warnw("failed to create secrets directory", "path", secretsDir, "error", err, "stderr", stderr)
		}
	}

	// Prepare EdgeLoadBalancer (Nginx) if enabled (stateless reverse proxy)
	var nginxConfig *NginxConfig
	if IsEdgeLoadBalancerEnabled(services) {
		log.Infow("EdgeLoadBalancer service detected, preparing deployment")
		nginxConfig, err = PrepareEdgeLoadBalancerDeployment(ctx, sshPool, primaryMaster, storageMountPath)
		if err != nil {
			log.Warnw("failed to prepare EdgeLoadBalancer deployment", "error", err)
			// Continue anyway - Nginx may work with defaults
		}
	} else {
		log.Infow("EdgeLoadBalancer service not enabled, skipping preparation")
	}

	// Run pre-initialization script on ALL nodes (each creates its own directories on shared storage)
	if err := runInitializationScriptOnAllNodes(ctx, sshPool, clusterInfo.AllNodes, serviceDefDir, "001-PreInitialization.sh", storageMountPath, clusterInfo, nil, nginxConfig); err != nil {
		log.Warnw("pre-initialization script failed", "error", err)
		// Continue anyway - services may still deploy successfully
	}

	// Deploy enabled services and track deployed stack names
	var deployedStacks []string
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
			deployedStacks = append(deployedStacks, svc.Name)
		}
	}

	// Upload enabled service definitions to storage
	// If distributed storage is enabled, uploads to one node (shared)
	// If distributed storage is disabled, uploads to all nodes (local)
	if storageMountPath != "" {
		log.Infow("uploading service definitions to storage",
			"distributedStorage", clusterInfo.DistributedStorageEnabled,
		)
		if err := uploadServiceDefinitions(ctx, sshPool, services, storageMountPath, clusterInfo); err != nil {
			log.Warnw("failed to upload some service definitions", "error", err)
		}
	}

	// Run post-initialization script after all services are deployed
	if len(deployedStacks) > 0 {
		if err := runInitializationScript(ctx, sshPool, primaryMaster, serviceDefDir, "002-PostInitialization.sh", storageMountPath, clusterInfo, deployedStacks, nginxConfig); err != nil {
			log.Warnw("post-initialization script failed", "error", err)
			// Continue anyway - services are already deployed
		}
	}

	// Nginx post-deployment: generate proxy rules and reload if config was prepared
	if nginxConfig != nil && nginxConfig.Enabled {
		log.Infow("Nginx service deployed, generating proxy rules",
			"serviceName", nginxConfig.ServiceName,
			"storagePath", nginxConfig.StoragePath,
		)

		// Generate proxy rules for all services with NGINX_PROXY: true
		if err := GenerateProxyRulesForServices(ctx, sshPool, primaryMaster, storageMountPath, services); err != nil {
			log.Warnw("failed to generate Nginx proxy rules", "error", err)
		} else {
			// Reload Nginx to apply new proxy rules
			if err := ReloadNginx(ctx, sshPool, primaryMaster, nginxConfig.ServiceName); err != nil {
				log.Warnw("failed to reload Nginx after proxy rule generation", "error", err)
			}
		}

		log.Infow("✅ Nginx proxy configuration complete")
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

	// Parse bind mounts from the processed content and create directories
	// Storage paths: create on one node if distributed storage, else all nodes
	// Local paths: always create on all nodes (node-local directories like /var/lib/nginx)
	if len(clusterInfo.AllNodes) > 0 {
		bindMounts := parseBindMounts(processedContent, storageMountPath)

		// Handle storage paths (under storageMountPath)
		if len(bindMounts.StoragePaths) > 0 {
			var storageNodes []string
			if clusterInfo.DistributedStorageEnabled {
				// Shared storage - only need to create on one node
				storageNodes = []string{clusterInfo.AllNodes[0]}
				log.Infow("creating storage directories on single node (distributed storage)", "paths", bindMounts.StoragePaths)
			} else {
				// Local storage - create on all nodes
				storageNodes = clusterInfo.AllNodes
				log.Infow("creating storage directories on all nodes (local storage)", "paths", bindMounts.StoragePaths)
			}
			if err := ensureDirectoriesOnNodes(ctx, sshPool, storageNodes, bindMounts.StoragePaths, svc.Name); err != nil {
				log.Warnw("failed to create some storage directories", "error", err)
			}
		}

		// Handle local paths (not under storageMountPath) - always create on ALL nodes
		if len(bindMounts.LocalPaths) > 0 {
			log.Infow("creating local directories on all nodes", "paths", bindMounts.LocalPaths)
			if err := ensureDirectoriesOnNodes(ctx, sshPool, clusterInfo.AllNodes, bindMounts.LocalPaths, svc.Name); err != nil {
				log.Warnw("failed to create some local directories", "error", err)
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
	// Export environment variables for variable substitution in compose files (e.g., ${DOCKER_MANAGER_HOST})
	envExports := fmt.Sprintf("export DOCKER_MANAGER_HOST='%s'", clusterInfo.DockerManagerHost)
	deployCmd := fmt.Sprintf("%s && docker stack deploy --prune --detach=true -c %s %s", envExports, remoteFile, svc.Name)

	log.Infow("deploying Docker stack", "host", primaryMaster, "stack", svc.Name, "dockerManagerHost", clusterInfo.DockerManagerHost)

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

// BindMountPaths contains categorized bind mount paths from service definitions.
type BindMountPaths struct {
	// StoragePaths are paths under the storage mount path (shared/distributed storage)
	StoragePaths []string
	// LocalPaths are absolute paths not under storage mount (node-local directories)
	LocalPaths []string
}

// isFilePath determines if a path likely refers to a file (vs directory).
// Uses heuristic: path has an extension (e.g., .conf, .key, .crt, .htpasswd)
func isFilePath(path string) bool {
	base := filepath.Base(path)
	// Check if the basename has a dot followed by an extension
	// Exclude hidden files/dirs that start with a dot
	if strings.HasPrefix(base, ".") {
		return false
	}
	ext := filepath.Ext(base)
	return ext != ""
}

// getDirectoryForPath returns the directory to create for a given path.
// For file paths, returns the parent directory.
// For directory paths, returns the path itself.
func getDirectoryForPath(path string) string {
	if isFilePath(path) {
		return filepath.Dir(path)
	}
	return path
}

// parseBindMounts extracts host paths from bind mount volume definitions in YAML content.
// It parses both short form ("host:container") and long form (source:/path, target:/path) volumes.
// Returns categorized paths: storage paths (under storageMountPath) and local paths (absolute paths elsewhere).
// For file mounts (paths with extensions like .conf), returns the PARENT directory.
func parseBindMounts(content string, storageMountPath string) BindMountPaths {
	var result BindMountPaths
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

		// Skip empty, relative paths, or named volumes
		if hostPath == "" || !strings.HasPrefix(hostPath, "/") {
			continue
		}

		// Normalize path
		hostPath = strings.TrimSuffix(hostPath, "/")

		// For file mounts (paths with extensions), get parent directory
		// This prevents mkdir -p from creating a directory with the file's name
		dirPath := getDirectoryForPath(hostPath)

		// Avoid duplicates
		if seenPaths[dirPath] {
			continue
		}
		seenPaths[dirPath] = true

		// Categorize: storage path vs local path
		if storageMountPath != "" && strings.HasPrefix(dirPath, storageMountPath) {
			result.StoragePaths = append(result.StoragePaths, dirPath)
		} else {
			result.LocalPaths = append(result.LocalPaths, dirPath)
		}
	}

	return result
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

// uploadServiceDefinitions uploads enabled service YAML files to storage.
// Files are stored in the ServiceDefinitions subdirectory under the storage mount path.
// If distributed storage is enabled, uploads to one node only (shared storage).
// If distributed storage is disabled, uploads to all nodes (local storage).
// If storageMountPath is empty, this function does nothing.
func uploadServiceDefinitions(ctx context.Context, sshPool *ssh.Pool, services []ServiceMetadata, storageMountPath string, clusterInfo ClusterInfo) error {
	if storageMountPath == "" || len(clusterInfo.AllNodes) == 0 {
		return nil
	}

	log := logging.L().With("component", "services")

	// Filter to enabled services only
	var enabledServices []ServiceMetadata
	for _, svc := range services {
		if svc.Enabled {
			enabledServices = append(enabledServices, svc)
		}
	}

	if len(enabledServices) == 0 {
		log.Infow("no enabled services to upload")
		return nil
	}

	// Determine target nodes based on storage type
	var targetNodes []string
	if clusterInfo.DistributedStorageEnabled {
		// Shared storage - only upload to one node
		targetNodes = []string{clusterInfo.AllNodes[0]}
		log.Infow("using distributed storage, uploading to single node", "node", targetNodes[0])
	} else {
		// Local storage - upload to all nodes
		targetNodes = clusterInfo.AllNodes
		log.Infow("using local storage, uploading to all nodes", "nodeCount", len(targetNodes))
	}

	// Build the destination directory path
	destDir := filepath.ToSlash(filepath.Join(storageMountPath, defaults.ServiceDefinitionsSubdir))

	var errors []string

	// Create directory and upload files to each target node
	for _, node := range targetNodes {
		// Create the directory
		mkdirCmd := fmt.Sprintf("mkdir -p '%s'", destDir)
		log.Infow("creating service definitions directory", "host", node, "path", destDir)
		if _, stderr, err := sshPool.Run(ctx, node, mkdirCmd); err != nil {
			errMsg := fmt.Sprintf("%s: failed to create directory: %v (stderr: %s)", node, err, stderr)
			log.Warnw("failed to create service definitions directory", "host", node, "error", err)
			errors = append(errors, errMsg)
			continue
		}

		// Upload each enabled service file to this node
		for _, svc := range enabledServices {
			// Read the local file content
			content, err := os.ReadFile(svc.FilePath)
			if err != nil {
				log.Warnw("failed to read service file", "file", svc.FilePath, "error", err)
				errors = append(errors, fmt.Sprintf("%s/%s: %v", node, svc.Name, err))
				continue
			}

			// Build remote file path
			remoteFile := fmt.Sprintf("%s/%s", destDir, svc.FileName)

			// Write content to remote file using heredoc
			writeCmd := fmt.Sprintf("cat > '%s' << 'DSCOTCTL_EOF'\n%s\nDSCOTCTL_EOF", remoteFile, string(content))

			log.Infow("uploading service definition",
				"service", svc.Name,
				"host", node,
				"remotePath", remoteFile,
				"size", len(content),
			)

			if _, stderr, err := sshPool.Run(ctx, node, writeCmd); err != nil {
				log.Warnw("failed to upload service definition", "service", svc.Name, "host", node, "error", err, "stderr", stderr)
				errors = append(errors, fmt.Sprintf("%s/%s: %v", node, svc.Name, err))
			} else {
				log.Infow("✅ service definition uploaded", "service", svc.Name, "host", node, "remotePath", remoteFile)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to upload some service definitions: %s", strings.Join(errors, "; "))
	}

	log.Infow("✅ all service definitions uploaded",
		"count", len(enabledServices),
		"targetNodes", len(targetNodes),
		"destination", destDir,
	)

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

// NetworkInfo represents Docker network information from JSON output (docker network inspect).
type NetworkInfo struct {
	ID       string `json:"Id"`
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

// NetworkListInfo represents Docker network information from docker network ls --format json.
type NetworkListInfo struct {
	ID       string `json:"ID"`
	Name     string `json:"Name"`
	Driver   string `json:"Driver"`
	Scope    string `json:"Scope"`
	Internal string `json:"Internal"` // "true" or "false" as string
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
				netType = "overlay (ingress)"
			} else if net.Internal {
				netType = "overlay (internal)"
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
// Shows: name, id, driver, scope, internal (true/false), subnet
func showNetworkSummary(ctx context.Context, sshPool *ssh.Pool, host string) {
	log := logging.L().With("component", "services")

	// Get all networks in JSON format
	networkListCmd := "docker network ls --format json"
	log.Infow("=== Network Summary ===")

	stdout, _, err := sshPool.Run(ctx, host, networkListCmd)
	if err != nil {
		log.Warnw("failed to get network list", "error", err)
		return
	}

	if strings.TrimSpace(stdout) == "" {
		log.Infow("no networks found")
		return
	}

	// Parse JSON lines from docker network ls
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var net NetworkListInfo
		if err := json.Unmarshal([]byte(line), &net); err != nil {
			continue
		}

		// Skip host and none networks (not useful to display)
		if net.Name == "host" || net.Name == "none" {
			continue
		}

		// Get subnet/CIDR by inspecting the network
		subnet := ""
		inspectCmd := fmt.Sprintf("docker network inspect %s --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}'", net.ID)
		subnetOut, _, err := sshPool.Run(ctx, host, inspectCmd)
		if err == nil {
			subnet = strings.TrimSpace(subnetOut)
		}

		// Convert internal string to boolean display
		isInternal := strings.EqualFold(net.Internal, "true")

		log.Infow("  network",
			"name", net.Name,
			"id", net.ID,
			"driver", net.Driver,
			"scope", net.Scope,
			"internal", isInternal,
			"subnet", subnet,
		)
	}
}

// runInitializationScriptOnAllNodes runs an initialization script on all nodes in the cluster.
// Each node runs the script in its own context, creating its own directories on shared storage.
func runInitializationScriptOnAllNodes(ctx context.Context, sshPool *ssh.Pool, allNodes []string, serviceDefDir string, scriptName string, storageMountPath string, clusterInfo ClusterInfo, deployedStacks []string, nginxConfig *NginxConfig) error {
	log := logging.L().With("component", "services", "script", scriptName)

	if len(allNodes) == 0 {
		log.Warnw("no nodes to run initialization script on")
		return nil
	}

	log.Infow("running initialization script on all nodes", "nodeCount", len(allNodes))

	for _, node := range allNodes {
		if err := runInitializationScript(ctx, sshPool, node, serviceDefDir, scriptName, storageMountPath, clusterInfo, deployedStacks, nginxConfig); err != nil {
			log.Warnw("initialization script failed on node", "node", node, "error", err)
			// Continue with other nodes
		}
	}

	return nil
}

// runInitializationScript uploads and executes a shell script on the target node with environment variables.
// scriptName should be either "001-PreInitialization.sh" or "002-PostInitialization.sh".
// deployedStacks is only used for post-initialization to pass the list of deployed stack names.
// nginxConfig contains Nginx configuration if Nginx is enabled.
func runInitializationScript(ctx context.Context, sshPool *ssh.Pool, targetNode string, serviceDefDir string, scriptName string, storageMountPath string, clusterInfo ClusterInfo, deployedStacks []string, nginxConfig *NginxConfig) error {
	log := logging.L().With("component", "services", "script", scriptName, "node", targetNode)

	// Scripts are in a "scripts" folder next to the "services" folder
	// If serviceDefDir is provided (e.g., /path/to/services), look for scripts in sibling folder
	var scriptPath string
	if serviceDefDir != "" {
		// serviceDefDir points to "services", scripts are in sibling "scripts" folder
		parentDir := filepath.Dir(serviceDefDir)
		scriptPath = filepath.Join(parentDir, DefaultScriptsDirectory, scriptName)
	} else {
		// Use default relative to binary
		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}
		scriptPath = filepath.Join(filepath.Dir(exePath), DefaultScriptsDirectory, scriptName)
	}

	// Read script content
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Infow("initialization script not found, skipping", "path", scriptPath)
			return nil
		}
		return fmt.Errorf("failed to read script: %w", err)
	}

	log.Infow("running initialization script", "host", targetNode, "size", len(scriptContent))

	// Get the actual hostname of the target node (not the SSH address which may be an IP)
	nodeHostname := targetNode
	if stdout, _, err := sshPool.Run(ctx, targetNode, "hostname 2>/dev/null"); err == nil {
		if h := strings.TrimSpace(stdout); h != "" {
			nodeHostname = h
			log.Infow("resolved node hostname", "sshHost", targetNode, "hostname", nodeHostname)
		}
	}

	// Build environment variables
	envVars := fmt.Sprintf(`export STORAGE_MOUNT_PATH='%s'
export SERVICE_DATA_DIR='%s'
export SERVICE_DEFINITIONS_DIR='%s'
export PRIMARY_MASTER='%s'
export HAS_DEDICATED_WORKERS='%t'
export DISTRIBUTED_STORAGE='%t'
export NODE_HOSTNAME='%s'
`,
		storageMountPath,
		defaults.ServiceDataSubdir,
		defaults.ServiceDefinitionsSubdir,
		clusterInfo.PrimaryMaster,
		clusterInfo.HasDedicatedWorkers,
		clusterInfo.DistributedStorageEnabled,
		nodeHostname,
	)

	// Add deployed stacks for post-init script
	if len(deployedStacks) > 0 {
		envVars += fmt.Sprintf("export DEPLOYED_SERVICES='%s'\n", strings.Join(deployedStacks, ","))
	}

	// Add Nginx configuration if enabled
	if nginxConfig != nil && nginxConfig.Enabled {
		envVars += "export NGINX_ENABLED='true'\n"
		envVars += fmt.Sprintf("export NGINX_SERVICE_NAME='%s'\n", nginxConfig.ServiceName)
	} else {
		envVars += "export NGINX_ENABLED='false'\n"
	}

	// Upload script to remote host
	// Convert CRLF to LF to ensure script works on Linux (Windows files have CRLF)
	remoteScript := fmt.Sprintf("/tmp/dscotctl-%s", scriptName)
	scriptStr := strings.ReplaceAll(string(scriptContent), "\r\n", "\n")
	scriptStr = strings.ReplaceAll(scriptStr, "\r", "\n") // Handle any standalone CR
	uploadCmd := fmt.Sprintf("cat > %s << 'DSCOTCTL_SCRIPT_EOF'\n%s\nDSCOTCTL_SCRIPT_EOF", remoteScript, scriptStr)

	if _, stderr, err := sshPool.Run(ctx, targetNode, uploadCmd); err != nil {
		return fmt.Errorf("failed to upload script: %w (stderr: %s)", err, stderr)
	}

	// Make script executable and run it with environment variables
	execCmd := fmt.Sprintf("%schmod +x %s && %s", envVars, remoteScript, remoteScript)

	log.Infow("executing script", "host", targetNode, "remoteScript", remoteScript)
	stdout, stderr, err := sshPool.Run(ctx, targetNode, execCmd)
	if err != nil {
		// Log output even on failure for debugging
		if stdout != "" {
			log.Infow("script stdout", "output", stdout)
		}
		if stderr != "" {
			log.Warnw("script stderr", "output", stderr)
		}
		return fmt.Errorf("script execution failed: %w", err)
	}

	// Log script output
	if stdout != "" {
		// Split and log each line for readability
		for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
			if line != "" {
				log.Infow(line)
			}
		}
	}

	// Cleanup remote script
	cleanupCmd := fmt.Sprintf("rm -f %s", remoteScript)
	if _, _, err := sshPool.Run(ctx, targetNode, cleanupCmd); err != nil {
		log.Warnw("failed to cleanup script", "file", remoteScript, "error", err)
	}

	log.Infow("✅ initialization script complete", "script", scriptName)
	return nil
}
