package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

const (
	DefaultServicesDir = "services"
)

// DiscoverServices scans the services directory for YAML files and parses metadata
func DiscoverServices(servicesDir string) ([]ServiceMetadata, error) {
	log := logging.L().With("component", "services")

	// If servicesDir is empty, use default relative to binary
	if servicesDir == "" {
		exePath, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable path: %w", err)
		}
		binaryDir := filepath.Dir(exePath)
		servicesDir = filepath.Join(binaryDir, DefaultServicesDir)
	}

	log.Infow("scanning services directory", "path", servicesDir)

	// Check if directory exists
	if _, err := os.Stat(servicesDir); os.IsNotExist(err) {
		log.Warnw("services directory does not exist", "path", servicesDir)
		return []ServiceMetadata{}, nil
	}

	// Read directory
	entries, err := os.ReadDir(servicesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read services directory: %w", err)
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

		filePath := filepath.Join(servicesDir, fileName)
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

// DeployServices deploys all enabled services to the Docker Swarm cluster
func DeployServices(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, servicesDir string) (*DeploymentMetrics, error) {
	log := logging.L().With("component", "services")
	metrics := &DeploymentMetrics{
		StartTime: time.Now(),
	}

	// Discover services
	services, err := DiscoverServices(servicesDir)
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

		if err := deployService(ctx, sshPool, primaryMaster, svc); err != nil {
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

	return metrics, nil
}

// deployService deploys a single service to the Docker Swarm cluster
func deployService(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, svc ServiceMetadata) error {
	log := logging.L().With("component", "services", "service", svc.Name)

	// Read service file
	content, err := os.ReadFile(svc.FilePath)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	// Create temporary file on remote host
	remoteFile := fmt.Sprintf("/tmp/clusterctl-service-%s.yml", svc.Name)

	// Write content to remote file
	writeCmd := fmt.Sprintf("cat > %s << 'CLUSTERCTL_EOF'\n%s\nCLUSTERCTL_EOF", remoteFile, string(content))

	log.Infow("uploading service definition", "host", primaryMaster, "remoteFile", remoteFile, "size", len(content))

	if _, stderr, err := sshPool.Run(ctx, primaryMaster, writeCmd); err != nil {
		return fmt.Errorf("failed to upload service file: %w (stderr: %s)", err, stderr)
	}

	// Deploy using docker stack deploy with --prune to remove orphaned services
	deployCmd := fmt.Sprintf("docker stack deploy --prune -c %s %s", remoteFile, svc.Name)

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

	return nil
}

