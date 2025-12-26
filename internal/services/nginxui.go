package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

// NginxUISecrets contains the generated secrets for NginxUI
type NginxUISecrets struct {
	NodeSecret   string
	JWTSecret    string
	CryptoSecret string
}

// NginxUIConfig contains NginxUI deployment configuration
type NginxUIConfig struct {
	Enabled            bool
	Secrets            NginxUISecrets
	ClusterNodes       []NginxUIClusterNode
	ClusterConfigINI   string
	StoragePath        string
	ServiceName        string
}

// NginxUIClusterNode represents a node in the NginxUI cluster
type NginxUIClusterNode struct {
	Hostname      string
	ContainerName string
	NodeLabel     string
}

const (
	// NginxUIServiceNamePattern matches NginxUI load balancer service names
	NginxUIServiceNamePattern = `(?i).*Load.*Balancer.*`
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
	cmd := fmt.Sprintf("docker node ls --filter 'node.label=%s=%s' --format '{{.Hostname}}'",
		NginxUILabelKey, NginxUILabelValue)

	log.Infow("discovering load balancer nodes", "command", cmd)

	stdout, stderr, err := sshPool.Run(ctx, primaryMaster, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w (stderr: %s)", err, stderr)
	}

	var nodes []NginxUIClusterNode
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		hostname := strings.TrimSpace(line)
		if hostname == "" {
			continue
		}
		nodes = append(nodes, NginxUIClusterNode{
			Hostname:      hostname,
			ContainerName: hostname, // Container hostname matches node hostname
			NodeLabel:     fmt.Sprintf("%s=%s", NginxUILabelKey, NginxUILabelValue),
		})
	}

	log.Infow("discovered load balancer nodes", "count", len(nodes), "nodes", nodes)
	return nodes, nil
}

// GenerateClusterConfig generates the NginxUI cluster configuration INI section
func GenerateClusterConfig(nodes []NginxUIClusterNode, nodeSecret string) string {
	if len(nodes) == 0 {
		return ""
	}

	var lines []string
	lines = append(lines, "[cluster]")

	for _, node := range nodes {
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

	return strings.Join(lines, "\n")
}

// WriteNginxUISecrets writes secrets to storage and logs them
func WriteNginxUISecrets(ctx context.Context, sshPool *ssh.Pool, targetNode string, storagePath string, secrets NginxUISecrets) error {
	log := logging.L().With("component", "nginxui")

	secretsDir := filepath.ToSlash(filepath.Join(storagePath, "data", NginxUIDataDir))
	secretsFile := filepath.ToSlash(filepath.Join(secretsDir, NginxUISecretsFileName))

	// Build secrets content
	content := fmt.Sprintf(`# NginxUI Secrets - Generated by dscotctl
# Keep this file secure!

NGINX_UI_NODE_SECRET=%s
NGINX_UI_APP_JWT_SECRET=%s
NGINX_UI_CRYPTO_SECRET=%s
`, secrets.NodeSecret, secrets.JWTSecret, secrets.CryptoSecret)

	// Create directory and write file
	cmd := fmt.Sprintf("mkdir -p '%s' && cat > '%s' << 'EOF'\n%s\nEOF && chmod 600 '%s'",
		secretsDir, secretsFile, content, secretsFile)

	log.Infow("writing NginxUI secrets to storage",
		"path", secretsFile,
		"host", targetNode,
	)

	if _, stderr, err := sshPool.Run(ctx, targetNode, cmd); err != nil {
		return fmt.Errorf("failed to write secrets: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✅ NginxUI secrets written to storage", "path", secretsFile)

	// Log the secrets for operator reference
	log.Infow("=== NginxUI Secrets (save these!) ===")
	log.Infow("NGINX_UI_NODE_SECRET", "value", secrets.NodeSecret)
	log.Infow("NGINX_UI_APP_JWT_SECRET", "value", secrets.JWTSecret)
	log.Infow("NGINX_UI_CRYPTO_SECRET", "value", secrets.CryptoSecret)

	return nil
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

	// Generate cluster configuration
	if len(nodes) > 0 {
		config.ClusterConfigINI = GenerateClusterConfig(nodes, secrets.NodeSecret)
		log.Infow("generated NginxUI cluster configuration",
			"nodeCount", len(nodes),
		)
		// Log the cluster config
		log.Infow("=== NginxUI Cluster Configuration ===")
		for _, line := range strings.Split(config.ClusterConfigINI, "\n") {
			if line != "" {
				log.Infow(line)
			}
		}
	}

	// Determine target node for writing secrets
	targetNode := primaryMaster
	if clusterInfo.DistributedStorageEnabled && len(clusterInfo.AllNodes) > 0 {
		targetNode = clusterInfo.AllNodes[0]
	}

	// Write secrets to storage
	if storagePath != "" {
		if err := WriteNginxUISecrets(ctx, sshPool, targetNode, storagePath, secrets); err != nil {
			log.Warnw("failed to write secrets to storage", "error", err)
			// Continue - secrets are logged anyway
		}
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

