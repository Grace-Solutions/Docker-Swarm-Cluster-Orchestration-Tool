package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// S3Credentials represents the S3 credentials file format.
// This is read from the file written by storage setup.
type S3Credentials struct {
	Endpoints  []string `json:"endpoints"`
	AccessKey  string   `json:"accessKey"`
	SecretKey  string   `json:"secretKey"`
	UserID     string   `json:"userId"`
	BucketName string   `json:"bucketName,omitempty"`
}

// NginxUISecrets contains the generated secrets for NginxUI
type NginxUISecrets struct {
	NodeSecret   string
	JWTSecret    string
	CryptoSecret string
}

// NginxUIConfig contains NginxUI deployment configuration
type NginxUIConfig struct {
	Enabled              bool
	Secrets              NginxUISecrets
	ClusterNodes         []NginxUIClusterNode
	ClusterConfigINI     string            // Deprecated: Use PerNodeClusterConfigs instead
	PerNodeClusterConfigs map[string]string // hostname -> cluster config INI (each node gets other nodes only)
	StoragePath          string
	ServiceName          string
}

// NginxUIClusterNode represents a node in the NginxUI cluster
type NginxUIClusterNode struct {
	Hostname      string
	ContainerName string
	NodeLabel     string
}

const (
	// NginxUIServiceNamePattern matches NginxUI service names (NginxUI, nginx-ui, LoadBalancer, etc.)
	NginxUIServiceNamePattern = `(?i)(.*nginx.*ui.*|.*load.*balancer.*)`
	// NginxUILabelKey is the Docker node label for load balancer nodes
	NginxUILabelKey = "loadbalancer"
	// NginxUILabelValue is the expected value for the load balancer label
	NginxUILabelValue = "true"
	// NginxUISecretsFileName is the name of the secrets file
	NginxUISecretsFileName = "secrets"
	// NginxUIDataDir is the subdirectory for NginxUI data
	NginxUIDataDir = "NginxUI"
	// NginxUIPort is the internal port for NginxUI
	NginxUIPort = 9000
)

// IsNginxUIService checks if a service matches the NginxUI pattern
func IsNginxUIService(serviceName string) bool {
	pattern := regexp.MustCompile(NginxUIServiceNamePattern)
	return pattern.MatchString(serviceName)
}

// GenerateNginxUISecrets generates random hex secrets for NginxUI
func GenerateNginxUISecrets() (NginxUISecrets, error) {
	log := logging.L().With("component", "nginxui")

	nodeSecret, err := generateHexSecret(32)
	if err != nil {
		return NginxUISecrets{}, fmt.Errorf("failed to generate node secret: %w", err)
	}

	jwtSecret, err := generateHexSecret(32)
	if err != nil {
		return NginxUISecrets{}, fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	cryptoSecret, err := generateHexSecret(32)
	if err != nil {
		return NginxUISecrets{}, fmt.Errorf("failed to generate crypto secret: %w", err)
	}

	secrets := NginxUISecrets{
		NodeSecret:   nodeSecret,
		JWTSecret:    jwtSecret,
		CryptoSecret: cryptoSecret,
	}

	log.Infow("generated NginxUI secrets",
		"nodeSecret", nodeSecret,
		"jwtSecret", jwtSecret,
		"cryptoSecret", cryptoSecret,
	)

	return secrets, nil
}

// generateHexSecret generates a random hex string of the specified length
func generateHexSecret(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// DiscoverLoadBalancerNodes discovers nodes with the loadbalancer=true label
func DiscoverLoadBalancerNodes(ctx context.Context, sshPool *ssh.Pool, primaryMaster string) ([]NginxUIClusterNode, error) {
	log := logging.L().With("component", "nginxui")

	// Query Docker Swarm for nodes with loadbalancer=true label
	// Get both hostname and ID for computing container hostname
	cmd := fmt.Sprintf("docker node ls --filter 'node.label=%s=%s' --format '{{.Hostname}} {{.ID}}'",
		NginxUILabelKey, NginxUILabelValue)

	log.Infow("discovering load balancer nodes", "command", cmd)

	stdout, stderr, err := sshPool.Run(ctx, primaryMaster, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w (stderr: %s)", err, stderr)
	}

	var nodes []NginxUIClusterNode
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		hostname := parts[0]
		nodeID := parts[1]
		// Container hostname uses LoadBalancer-<node_id> to match YAML template: hostname: 'LoadBalancer-{{.Node.ID}}'
		containerHostname := fmt.Sprintf("LoadBalancer-%s", nodeID)

		nodes = append(nodes, NginxUIClusterNode{
			Hostname:      hostname,
			ContainerName: containerHostname,
			NodeLabel:     fmt.Sprintf("%s=%s", NginxUILabelKey, NginxUILabelValue),
		})
	}

	log.Infow("discovered load balancer nodes", "count", len(nodes), "nodes", nodes)
	return nodes, nil
}

// GenerateClusterConfig generates the NginxUI cluster configuration INI section for a specific node.
// It includes all OTHER nodes in the cluster, excluding selfHostname.
// If selfHostname is empty, all nodes are included.
func GenerateClusterConfig(nodes []NginxUIClusterNode, nodeSecret string, selfHostname string) string {
	if len(nodes) == 0 {
		return ""
	}

	var lines []string
	lines = append(lines, "[cluster]")

	for _, node := range nodes {
		// Skip self - each node only needs to know about OTHER nodes
		if selfHostname != "" && strings.EqualFold(node.Hostname, selfHostname) {
			continue
		}
		// Use container hostname for addressing over overlay network
		// Format: Node = http://<hostname>:9000?name=<display_name>&node_secret=<secret>&enabled=true
		nodeLine := fmt.Sprintf("Node = http://%s:%d?name=%s&node_secret=%s&enabled=true",
			node.ContainerName,
			NginxUIPort,
			node.Hostname,
			nodeSecret,
		)
		lines = append(lines, nodeLine)
	}

	// If only [cluster] header (no other nodes), return empty
	if len(lines) <= 1 {
		return ""
	}

	return strings.Join(lines, "\n")
}

// GeneratePerNodeClusterConfigs generates cluster configs.
// Only the FIRST node gets the cluster config with all other nodes.
// Other nodes get empty config (no cluster section) to prevent cross-sync loops.
// Returns a map of hostname -> cluster config INI section.
func GeneratePerNodeClusterConfigs(nodes []NginxUIClusterNode, nodeSecret string) map[string]string {
	configs := make(map[string]string)
	if len(nodes) == 0 {
		return configs
	}

	// Only first node gets cluster config pointing to all other nodes
	firstNode := nodes[0]
	cfg := GenerateClusterConfig(nodes, nodeSecret, firstNode.Hostname)
	configs[firstNode.Hostname] = cfg

	// Other nodes get empty cluster config (hub-spoke model, first node is hub)
	for i := 1; i < len(nodes); i++ {
		configs[nodes[i].Hostname] = ""
	}

	return configs
}



// ReplaceNginxUISecretsInYAML replaces placeholder secrets in YAML content with generated ones
func ReplaceNginxUISecretsInYAML(content string, secrets NginxUISecrets) string {
	// Replace the default placeholder secrets with generated ones
	replacements := map[string]string{
		"a9f3c7e2b8d14a6f5c0e9d3b7a1f8c4e": secrets.NodeSecret,
		"d4b8f2a6c1e9573d0b4a8f2e6c1d9a7b": secrets.JWTSecret,
		"e7c3a9f1d5b8024e6a3c9f1d7b4e8a2c": secrets.CryptoSecret,
	}

	result := content
	for placeholder, secret := range replacements {
		result = strings.ReplaceAll(result, placeholder, secret)
	}

	return result
}

// PrepareNginxUIDeployment prepares NginxUI for deployment
// This is called before service deployment if NginxUI is enabled
func PrepareNginxUIDeployment(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, clusterInfo ClusterInfo) (*NginxUIConfig, error) {
	log := logging.L().With("component", "nginxui")

	log.Infow("preparing NginxUI deployment")

	config := &NginxUIConfig{
		Enabled:     true,
		StoragePath: storagePath,
		ServiceName: "NginxUI_LoadBalancer",
	}

	// Generate secrets
	secrets, err := GenerateNginxUISecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secrets: %w", err)
	}
	config.Secrets = secrets

	// Discover load balancer nodes
	nodes, err := DiscoverLoadBalancerNodes(ctx, sshPool, primaryMaster)
	if err != nil {
		log.Warnw("failed to discover load balancer nodes", "error", err)
		// Continue without cluster config - nodes might not be labeled yet
	}
	config.ClusterNodes = nodes

	// Generate per-node cluster configurations
	// Each node gets config containing only the OTHER nodes (not itself)
	if len(nodes) > 0 {
		config.PerNodeClusterConfigs = GeneratePerNodeClusterConfigs(nodes, secrets.NodeSecret)
		log.Infow("generated NginxUI per-node cluster configurations",
			"nodeCount", len(nodes),
		)
		// Log cluster config - only hub node has config, others are spokes
		for hostname, cfg := range config.PerNodeClusterConfigs {
			if cfg != "" {
				log.Infow("=== NginxUI Cluster Config (Hub: " + hostname + ") ===")
				for _, line := range strings.Split(cfg, "\n") {
					if line != "" {
						log.Infow("  " + line)
					}
				}
			} else {
				log.Infow("NginxUI spoke node (syncs from hub)", "node", hostname)
			}
		}
	}

	// Log the secrets for operator reference (file is written after deployment by WriteNginxUICredentials)
	log.Infow("=== NginxUI Secrets (will be saved to credentials file after deployment) ===")
	log.Infow("NGINX_UI_NODE_SECRET", "value", secrets.NodeSecret)
	log.Infow("NGINX_UI_APP_JWT_SECRET", "value", secrets.JWTSecret)
	log.Infow("NGINX_UI_CRYPTO_SECRET", "value", secrets.CryptoSecret)

	// Log NginxUI access URLs for each load balancer node
	if len(nodes) > 0 {
		log.Infow("=== NginxUI Management Access URLs ===")
		for _, node := range nodes {
			log.Infow(fmt.Sprintf("  http://%s/nginxui/", node.Hostname))
		}
		log.Infow("Credentials will be generated and saved to secrets directory after deployment")
	}

	log.Infow("✅ NginxUI deployment preparation complete")
	return config, nil
}

// IsNginxUIEnabled checks if NginxUI service is enabled in the discovered services
func IsNginxUIEnabled(services []ServiceMetadata) bool {
	for _, svc := range services {
		if svc.Enabled && IsNginxUIService(svc.Name) {
			return true
		}
	}
	return false
}

// GetNginxUIService returns the NginxUI service metadata if found and enabled
func GetNginxUIService(services []ServiceMetadata) *ServiceMetadata {
	for i := range services {
		if services[i].Enabled && IsNginxUIService(services[i].Name) {
			return &services[i]
		}
	}
	return nil
}

// NginxUIContainerInfo represents a discovered NginxUI container
type NginxUIContainerInfo struct {
	NodeHostname      string // Docker Swarm node hostname (e.g., DOCKER-SWARM-NODE-0000)
	ContainerHostname string // Container's internal hostname (from docker inspect .Config.Hostname)
	ContainerID       string // Container ID
}

// DiscoverNginxUIContainers discovers all running NginxUI containers and their hostnames.
// This should be called AFTER the NginxUI service is deployed.
// serviceName is the full Docker Swarm service name (e.g., "NginxUI_LoadBalancer")
// nodeHostnameToSSH maps Docker Swarm node hostnames to SSH addresses
func DiscoverNginxUIContainers(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, serviceName string, nodeHostnameToSSH map[string]string) ([]NginxUIContainerInfo, error) {
	log := logging.L().With("component", "nginxui")

	// Get all tasks for the service with their node and container info
	// Format: NodeHostname|TaskID
	cmd := fmt.Sprintf(`docker service ps %s --filter 'desired-state=running' --format '{{.Node}}|{{.ID}}' --no-trunc`, serviceName)
	log.Infow("discovering NginxUI containers", "command", cmd)

	stdout, stderr, err := sshPool.Run(ctx, primaryMaster, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to list service tasks: %w (stderr: %s)", err, stderr)
	}

	var containers []NginxUIContainerInfo
	lines := strings.Split(strings.TrimSpace(stdout), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) != 2 {
			log.Warnw("unexpected task format", "line", line)
			continue
		}

		nodeHostname := parts[0]
		taskID := parts[1]

		// Look up the SSH address for this node hostname
		sshHost, ok := nodeHostnameToSSH[nodeHostname]
		if !ok {
			log.Warnw("no SSH mapping found for node hostname", "nodeHostname", nodeHostname, "availableMappings", nodeHostnameToSSH)
			continue
		}

		// Get the container ID for this task on its node
		// Query the specific node to get container info
		containerCmd := fmt.Sprintf(`docker ps --filter 'label=com.docker.swarm.task.id=%s' --format '{{.ID}}' --no-trunc`, taskID)
		containerStdout, _, err := sshPool.Run(ctx, sshHost, containerCmd)
		if err != nil {
			log.Warnw("failed to get container ID", "node", nodeHostname, "sshHost", sshHost, "taskID", taskID, "error", err)
			continue
		}

		containerID := strings.TrimSpace(containerStdout)
		if containerID == "" {
			log.Warnw("no container found for task", "node", nodeHostname, "sshHost", sshHost, "taskID", taskID)
			continue
		}

		// Get the container's hostname from docker inspect
		hostnameCmd := fmt.Sprintf(`docker inspect %s --format '{{.Config.Hostname}}'`, containerID)
		hostnameStdout, _, err := sshPool.Run(ctx, sshHost, hostnameCmd)
		if err != nil {
			log.Warnw("failed to get container hostname", "node", nodeHostname, "sshHost", sshHost, "containerID", containerID, "error", err)
			continue
		}

		containerHostname := strings.TrimSpace(hostnameStdout)
		if containerHostname == "" {
			// Fallback to container ID prefix if hostname is empty
			if len(containerID) >= 12 {
				containerHostname = containerID[:12]
			} else {
				containerHostname = containerID
			}
		}

		containers = append(containers, NginxUIContainerInfo{
			NodeHostname:      nodeHostname,
			ContainerHostname: containerHostname,
			ContainerID:       containerID,
		})

		log.Infow("discovered NginxUI container",
			"node", nodeHostname,
			"sshHost", sshHost,
			"containerHostname", containerHostname,
			"containerID", containerID[:12],
		)
	}

	log.Infow("discovered NginxUI containers", "count", len(containers))
	return containers, nil
}

// UpdateNginxUIClusterConfig updates the cluster configuration in app.ini for the hub node
// after containers are discovered. Only the first (hub) node gets cluster config pointing to other nodes.
func UpdateNginxUIClusterConfig(ctx context.Context, sshPool *ssh.Pool, storagePath string, containers []NginxUIContainerInfo, nodeSecret string, serviceName string) error {
	log := logging.L().With("component", "nginxui")

	if len(containers) < 2 {
		log.Infow("less than 2 NginxUI containers, no cluster config needed", "count", len(containers))
		return nil
	}

	// Sort containers by node hostname to ensure consistent first node selection
	// (hub-spoke model: first node is the hub)
	sortedContainers := make([]NginxUIContainerInfo, len(containers))
	copy(sortedContainers, containers)
	// Simple sort by node hostname
	for i := 0; i < len(sortedContainers)-1; i++ {
		for j := i + 1; j < len(sortedContainers); j++ {
			if sortedContainers[i].NodeHostname > sortedContainers[j].NodeHostname {
				sortedContainers[i], sortedContainers[j] = sortedContainers[j], sortedContainers[i]
			}
		}
	}

	// First container is the hub
	hubContainer := sortedContainers[0]
	otherContainers := sortedContainers[1:]

	// Build cluster config section for the hub - pointing to all OTHER containers
	var clusterLines []string
	clusterLines = append(clusterLines, "[cluster]")
	for _, container := range otherContainers {
		// Use container hostname for addressing over overlay network
		nodeLine := fmt.Sprintf("Node = http://%s:%d?name=%s&node_secret=%s&enabled=true",
			container.ContainerHostname,
			NginxUIPort,
			container.NodeHostname, // Display name
			nodeSecret,
		)
		clusterLines = append(clusterLines, nodeLine)
	}
	clusterConfig := strings.Join(clusterLines, "\n")

	// Update the hub's app.ini
	appIniPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxUIDataDir, hubContainer.NodeHostname, "nginxui", "app.ini"))

	log.Infow("updating NginxUI cluster config on hub node",
		"hubNode", hubContainer.NodeHostname,
		"hubContainerHostname", hubContainer.ContainerHostname,
		"appIniPath", appIniPath,
		"otherNodes", len(otherContainers),
	)

	// Read existing app.ini
	readCmd := fmt.Sprintf("cat '%s' 2>/dev/null || echo ''", appIniPath)
	existingContent, _, err := sshPool.Run(ctx, hubContainer.NodeHostname, readCmd)
	if err != nil {
		return fmt.Errorf("failed to read existing app.ini: %w", err)
	}

	// Remove existing [cluster] section if present
	newContent := removeClusterSection(existingContent)

	// Append new cluster config
	newContent = strings.TrimRight(newContent, "\n") + "\n\n" + clusterConfig + "\n"

	// Write back
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFCLUSTER'\n%s\nEOFCLUSTER", appIniPath, newContent)
	if _, stderr, err := sshPool.Run(ctx, hubContainer.NodeHostname, writeCmd); err != nil {
		return fmt.Errorf("failed to write app.ini: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✅ NginxUI cluster config updated",
		"hubNode", hubContainer.NodeHostname,
		"clusterNodes", len(otherContainers),
	)

	// Log the cluster config for visibility
	log.Infow("=== NginxUI Cluster Config (Hub: " + hubContainer.NodeHostname + ") ===")
	for _, line := range clusterLines {
		log.Infow(line)
	}

	// Force service update to restart all containers and pick up new config
	// In Docker Swarm, containers are managed as tasks - use service update --force
	// This will cause a rolling restart of all containers
	log.Infow("forcing service update to apply cluster config",
		"serviceName", serviceName,
	)
	updateCmd := fmt.Sprintf("docker service update --force %s", serviceName)
	if _, stderr, err := sshPool.Run(ctx, hubContainer.NodeHostname, updateCmd); err != nil {
		log.Warnw("failed to force service update", "error", err, "stderr", stderr)
		// Don't fail - config is written, service can be manually updated
	} else {
		log.Infow("✅ NginxUI service update initiated")
	}

	return nil
}

// removeClusterSection removes the [cluster] section from INI content
func removeClusterSection(content string) string {
	lines := strings.Split(content, "\n")
	var result []string
	inCluster := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[cluster]" {
			inCluster = true
			continue
		}
		// Next section starts
		if inCluster && strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inCluster = false
		}
		if !inCluster {
			result = append(result, line)
		}
	}

	return strings.Join(result, "\n")
}

// NginxUICredentials contains the admin credentials for NginxUI
type NginxUICredentials struct {
	Username string
	Password string
}

// Default admin username (from service YAML env vars)
const (
	NginxUIDefaultUsername = "admin"
)

// UpdateNginxUINodeTokens updates the node tokens in the NginxUI database to match the configured node_secret.
// This is needed because NginxUI creates nodes in its database with a token generated from the Node URL parameter,
// but the actual authentication uses the node_secret from the config. This mismatch causes "version incompatible" errors.
// Must be run on the hub node (first node in sorted order).
func UpdateNginxUINodeTokens(ctx context.Context, sshPool *ssh.Pool, storagePath string, containers []NginxUIContainerInfo, nodeSecret string) error {
	log := logging.L().With("component", "nginxui")

	if len(containers) < 2 {
		log.Infow("less than 2 NginxUI containers, no token update needed", "count", len(containers))
		return nil
	}

	// Sort containers by node hostname to get consistent hub node
	sortedContainers := make([]NginxUIContainerInfo, len(containers))
	copy(sortedContainers, containers)
	for i := 0; i < len(sortedContainers)-1; i++ {
		for j := i + 1; j < len(sortedContainers); j++ {
			if sortedContainers[i].NodeHostname > sortedContainers[j].NodeHostname {
				sortedContainers[i], sortedContainers[j] = sortedContainers[j], sortedContainers[i]
			}
		}
	}

	hubContainer := sortedContainers[0]

	// Path to the hub node's database
	dbPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxUIDataDir, hubContainer.NodeHostname, "nginxui", "database.db"))

	log.Infow("updating NginxUI node tokens in database",
		"hubNode", hubContainer.NodeHostname,
		"dbPath", dbPath,
		"nodeSecret", nodeSecret,
	)

	// Update all tokens in the nodes table to match the configured node_secret
	// This fixes the mismatch between what's in the database and what the containers expect
	updateCmd := fmt.Sprintf(`sqlite3 '%s' "UPDATE nodes SET token='%s';"`, dbPath, nodeSecret)
	if _, stderr, err := sshPool.Run(ctx, hubContainer.NodeHostname, updateCmd); err != nil {
		return fmt.Errorf("failed to update node tokens: %w (stderr: %s)", err, stderr)
	}

	// Verify the update
	verifyCmd := fmt.Sprintf(`sqlite3 '%s' "SELECT id, name, token FROM nodes;"`, dbPath)
	stdout, _, err := sshPool.Run(ctx, hubContainer.NodeHostname, verifyCmd)
	if err != nil {
		log.Warnw("failed to verify token update", "error", err)
	} else {
		log.Infow("✅ NginxUI node tokens updated successfully")
		for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
			if line != "" {
				log.Infow("  " + line)
			}
		}
	}

	return nil
}

// ResetNginxUIAdminPassword resets the admin password using nginx-ui's built-in reset-password command.
// This generates a new random password and returns the credentials.
// The password is logged for operator reference.
func ResetNginxUIAdminPassword(ctx context.Context, sshPool *ssh.Pool, containers []NginxUIContainerInfo) (*NginxUICredentials, error) {
	log := logging.L().With("component", "nginxui")

	if len(containers) == 0 {
		return nil, fmt.Errorf("no NginxUI containers found")
	}

	// Sort containers by node hostname to get consistent hub node
	sortedContainers := make([]NginxUIContainerInfo, len(containers))
	copy(sortedContainers, containers)
	for i := 0; i < len(sortedContainers)-1; i++ {
		for j := i + 1; j < len(sortedContainers); j++ {
			if sortedContainers[i].NodeHostname > sortedContainers[j].NodeHostname {
				sortedContainers[i], sortedContainers[j] = sortedContainers[j], sortedContainers[i]
			}
		}
	}

	hubContainer := sortedContainers[0]

	log.Infow("resetting NginxUI admin password",
		"hubNode", hubContainer.NodeHostname,
		"containerID", hubContainer.ContainerID,
	)

	// Use nginx-ui's built-in reset-password command
	// This generates a new random password and outputs: "User: admin, Password: <password>"
	resetCmd := fmt.Sprintf("docker exec %s nginx-ui reset-password --config=/etc/nginx-ui/app.ini", hubContainer.ContainerID)
	stdout, stderr, err := sshPool.Run(ctx, hubContainer.NodeHostname, resetCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to reset password: %w (stderr: %s)", err, stderr)
	}

	// Parse the output to extract username and password
	// Format: "User: admin, Password: k%hCjY#5DD(d"
	var username, password string
	lines := strings.Split(stdout+stderr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "User:") && strings.Contains(line, "Password:") {
			// Extract username and password from the line
			parts := strings.Split(line, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "User:") {
					username = strings.TrimSpace(strings.TrimPrefix(part, "User:"))
				} else if strings.HasPrefix(part, "Password:") {
					password = strings.TrimSpace(strings.TrimPrefix(part, "Password:"))
				}
			}
		}
	}

	if username == "" || password == "" {
		return nil, fmt.Errorf("failed to parse reset-password output: %s", stdout+stderr)
	}

	creds := &NginxUICredentials{
		Username: username,
		Password: password,
	}

	log.Infow("✅ NginxUI admin password reset successfully",
		"username", creds.Username,
		"password", creds.Password,
	)

	return creds, nil
}

// NginxUIClusterInfo contains comprehensive NginxUI cluster information for the credentials file
type NginxUIClusterInfo struct {
	Credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"credentials"`
	Secrets struct {
		NodeSecret   string `json:"nodeSecret"`
		JWTSecret    string `json:"jwtSecret"`
		CryptoSecret string `json:"cryptoSecret"`
	} `json:"secrets"`
	AccessURLs struct {
		NginxUI   []string `json:"nginxui"`             // URLs to access NginxUI (http://<node>/nginxui/)
		Portainer []string `json:"portainer,omitempty"` // URLs to access Portainer (http://<node>/portainer/)
	} `json:"accessUrls"`
	VirtualIP string `json:"virtualIp,omitempty"` // Virtual IP if keepalived enabled
	Nodes     []struct {
		Hostname      string `json:"hostname"`
		ContainerID   string `json:"containerId"`
		ContainerName string `json:"containerName"`
		IsHub         bool   `json:"isHub"`
	} `json:"nodes"`
	GeneratedAt string `json:"generatedAt"`
}

// WriteNginxUICredentials writes NginxUI credentials and cluster info to a JSON file.
// If storagePath is provided (shared storage enabled), writes to storagePath/secrets/nginxui-credentials.json
// If storagePath is empty, writes to /root/.dscotctl/nginxui-credentials.json on the hub node
// keepalivedVIP is the virtual IP if keepalived is enabled (empty string if not)
// portainerEnabled indicates whether Portainer service is deployed
func WriteNginxUICredentials(ctx context.Context, sshPool *ssh.Pool, hubNode string, storagePath string, creds *NginxUICredentials, containers []NginxUIContainerInfo, secrets NginxUISecrets, keepalivedVIP string, portainerEnabled bool) error {
	log := logging.L().With("component", "nginxui")

	// Determine output path
	var credsPath string
	if storagePath != "" {
		// Shared storage - write to secrets folder
		credsPath = filepath.ToSlash(filepath.Join(storagePath, "secrets", "nginxui-credentials.json"))
	} else {
		// Local storage - write to root home
		credsPath = "/root/.dscotctl/nginxui-credentials.json"
	}

	// Create directory
	dir := filepath.ToSlash(filepath.Dir(credsPath))
	mkdirCmd := fmt.Sprintf("mkdir -p '%s'", dir)
	if _, stderr, err := sshPool.Run(ctx, hubNode, mkdirCmd); err != nil {
		return fmt.Errorf("failed to create credentials directory %s: %w (stderr: %s)", dir, err, stderr)
	}

	// Sort containers to identify hub (first alphabetically)
	sortedContainers := make([]NginxUIContainerInfo, len(containers))
	copy(sortedContainers, containers)
	for i := 0; i < len(sortedContainers)-1; i++ {
		for j := i + 1; j < len(sortedContainers); j++ {
			if sortedContainers[i].NodeHostname > sortedContainers[j].NodeHostname {
				sortedContainers[i], sortedContainers[j] = sortedContainers[j], sortedContainers[i]
			}
		}
	}

	// Build cluster info struct
	clusterInfo := NginxUIClusterInfo{
		VirtualIP:   keepalivedVIP,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if creds != nil {
		clusterInfo.Credentials.Username = creds.Username
		clusterInfo.Credentials.Password = creds.Password
	}
	clusterInfo.Secrets.NodeSecret = secrets.NodeSecret
	clusterInfo.Secrets.JWTSecret = secrets.JWTSecret
	clusterInfo.Secrets.CryptoSecret = secrets.CryptoSecret

	// Build access URLs for each node
	for _, container := range sortedContainers {
		nginxUIURL := fmt.Sprintf("http://%s/nginxui/", container.NodeHostname)
		clusterInfo.AccessURLs.NginxUI = append(clusterInfo.AccessURLs.NginxUI, nginxUIURL)

		if portainerEnabled {
			portainerURL := fmt.Sprintf("http://%s/portainer/", container.NodeHostname)
			clusterInfo.AccessURLs.Portainer = append(clusterInfo.AccessURLs.Portainer, portainerURL)
		}
	}

	// Add VIP-based URLs if keepalived is enabled
	if keepalivedVIP != "" {
		vipNginxUIURL := fmt.Sprintf("http://%s/nginxui/", keepalivedVIP)
		clusterInfo.AccessURLs.NginxUI = append([]string{vipNginxUIURL}, clusterInfo.AccessURLs.NginxUI...)

		if portainerEnabled {
			vipPortainerURL := fmt.Sprintf("http://%s/portainer/", keepalivedVIP)
			clusterInfo.AccessURLs.Portainer = append([]string{vipPortainerURL}, clusterInfo.AccessURLs.Portainer...)
		}
	}

	// Add node info
	for i, container := range sortedContainers {
		nodeInfo := struct {
			Hostname      string `json:"hostname"`
			ContainerID   string `json:"containerId"`
			ContainerName string `json:"containerName"`
			IsHub         bool   `json:"isHub"`
		}{
			Hostname:      container.NodeHostname,
			ContainerID:   container.ContainerID,
			ContainerName: container.ContainerHostname,
			IsHub:         i == 0, // First node (alphabetically) is the hub
		}
		clusterInfo.Nodes = append(clusterInfo.Nodes, nodeInfo)
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(clusterInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cluster info: %w", err)
	}

	// Write credentials file
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOF'\n%s\nEOF", credsPath, string(jsonBytes))
	if _, stderr, err := sshPool.Run(ctx, hubNode, writeCmd); err != nil {
		return fmt.Errorf("failed to write credentials file: %w (stderr: %s)", err, stderr)
	}

	log.Infow("NginxUI credentials written to file",
		"path", credsPath,
		"sharedStorage", storagePath != "",
		"nodes", len(containers),
	)

	// Log credentials prominently for operator reference
	log.Infow("========================================")
	log.Infow("=== NginxUI Admin Credentials ===")
	log.Infow(fmt.Sprintf("Username: %s", creds.Username))
	log.Infow(fmt.Sprintf("Password: %s", creds.Password))
	log.Infow(fmt.Sprintf("Credentials file: %s", credsPath))
	log.Infow("========================================")

	return nil
}

// ConfigureS3Proxy configures NginxUI to proxy S3 (RADOS Gateway) traffic.
// It reads the S3 credentials file from shared storage and creates:
// 1. An upstream block with all RGW endpoints for load balancing
// 2. A location block at /s3/ for HTTP S3 access
// 3. A TCP stream for direct S3 protocol access on the RGW port
// This should be called after NginxUI is deployed and running.
func ConfigureS3Proxy(ctx context.Context, sshPool *ssh.Pool, storagePath, s3CredentialsFile string, containers []NginxUIContainerInfo, rgwPort int) error {
	log := logging.L().With("component", "nginxui-s3")

	if s3CredentialsFile == "" {
		log.Infow("S3 credentials file not configured, skipping S3 proxy setup")
		return nil
	}

	if len(containers) == 0 {
		return fmt.Errorf("no NginxUI containers found for S3 proxy configuration")
	}

	// Sort containers to get consistent hub node
	sortedContainers := make([]NginxUIContainerInfo, len(containers))
	copy(sortedContainers, containers)
	for i := 0; i < len(sortedContainers)-1; i++ {
		for j := i + 1; j < len(sortedContainers); j++ {
			if sortedContainers[i].NodeHostname > sortedContainers[j].NodeHostname {
				sortedContainers[i], sortedContainers[j] = sortedContainers[j], sortedContainers[i]
			}
		}
	}

	hubContainer := sortedContainers[0]

	// Read S3 credentials file from shared storage
	log.Infow("reading S3 credentials file", "path", s3CredentialsFile, "node", hubContainer.NodeHostname)
	catCmd := fmt.Sprintf("cat '%s' 2>/dev/null", s3CredentialsFile)
	stdout, _, err := sshPool.Run(ctx, hubContainer.NodeHostname, catCmd)
	if err != nil || strings.TrimSpace(stdout) == "" {
		log.Infow("S3 credentials file not found or empty, skipping S3 proxy setup", "path", s3CredentialsFile)
		return nil
	}

	var s3Creds S3Credentials
	if err := json.Unmarshal([]byte(stdout), &s3Creds); err != nil {
		return fmt.Errorf("failed to parse S3 credentials file: %w", err)
	}

	if len(s3Creds.Endpoints) == 0 {
		log.Infow("no S3 endpoints found in credentials file, skipping S3 proxy setup")
		return nil
	}

	log.Infow("configuring S3 proxy for NginxUI",
		"endpoints", len(s3Creds.Endpoints),
		"rgwPort", rgwPort,
	)

	// Build upstream servers from endpoints (extract host:port from URLs)
	var upstreamServers []string
	for _, endpoint := range s3Creds.Endpoints {
		u, err := url.Parse(endpoint)
		if err != nil {
			log.Warnw("failed to parse endpoint URL", "endpoint", endpoint, "error", err)
			continue
		}
		upstreamServers = append(upstreamServers, u.Host)
	}

	if len(upstreamServers) == 0 {
		return fmt.Errorf("no valid S3 upstream servers extracted from endpoints")
	}

	// Generate upstream config for load balancing
	var upstreamLines []string
	for _, server := range upstreamServers {
		upstreamLines = append(upstreamLines, fmt.Sprintf("    server %s;", server))
	}
	upstreamConfig := strings.Join(upstreamLines, "\n")

	// Create S3 proxy site config
	s3SiteConfig := fmt.Sprintf(`# S3 RADOS Gateway Proxy
# Load-balanced S3 access via /s3/ path
# Generated by dscotctl
# Endpoints: %s

upstream s3_rados_gateway {
%s
}

server {
    listen 7480;
    listen [::]:7480;
    server_name _;

    # S3 endpoint - proxy to RADOS Gateway cluster
    location / {
        proxy_pass http://s3_rados_gateway;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        client_max_body_size 0;
    }
}
`, strings.Join(s3Creds.Endpoints, ", "), upstreamConfig)

	// Write config to all NginxUI nodes
	for _, container := range containers {
		nginxPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxUIDataDir, container.NodeHostname, "nginx"))
		s3ConfigPath := filepath.ToSlash(filepath.Join(nginxPath, "sites-available", "s3-gateway.conf"))
		s3SymlinkPath := filepath.ToSlash(filepath.Join(nginxPath, "sites-enabled", "s3-gateway.conf"))

		// Write site config
		writeCmd := fmt.Sprintf("cat > '%s' << 'EOF'\n%sEOF", s3ConfigPath, s3SiteConfig)
		if _, stderr, err := sshPool.Run(ctx, container.NodeHostname, writeCmd); err != nil {
			log.Warnw("failed to write S3 site config", "node", container.NodeHostname, "error", err, "stderr", stderr)
			continue
		}

		// Create symlink if not exists
		symlinkCmd := fmt.Sprintf("ln -sf '../sites-available/s3-gateway.conf' '%s' 2>/dev/null || true", s3SymlinkPath)
		if _, _, err := sshPool.Run(ctx, container.NodeHostname, symlinkCmd); err != nil {
			log.Warnw("failed to create S3 site symlink", "node", container.NodeHostname, "error", err)
		}

		log.Infow("S3 proxy config written", "node", container.NodeHostname, "config", s3ConfigPath)
	}

	// Reload nginx in all containers
	for _, container := range containers {
		reloadCmd := fmt.Sprintf("docker exec %s nginx -s reload 2>/dev/null || true", container.ContainerID)
		if _, _, err := sshPool.Run(ctx, container.NodeHostname, reloadCmd); err != nil {
			log.Warnw("failed to reload nginx", "node", container.NodeHostname, "error", err)
		}
	}

	log.Infow("✅ S3 proxy configured for NginxUI",
		"endpoints", len(s3Creds.Endpoints),
		"port", 7480,
		"nodes", len(containers),
	)

	return nil
}
