package services

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"dscotctl/internal/logging"
	"dscotctl/internal/ssh"
)

// NginxConfig contains Nginx deployment configuration
type NginxConfig struct {
	Enabled     bool
	StoragePath string
	ServiceName string
}

const (
	// NginxServiceNamePattern matches Nginx service names
	NginxServiceNamePattern = `(?i)^nginx$`
	// NginxLabelKey is the Docker node label for load balancer nodes
	NginxLabelKey = "loadbalancer"
	// NginxLabelValue is the expected value for the load balancer label
	NginxLabelValue = "true"
	// NginxDataDir is the subdirectory for Nginx data
	NginxDataDir = "Nginx"
	// NginxConfDir is the subdirectory for Nginx configuration
	NginxConfDir = "conf"
)

// IsNginxService checks if a service matches the Nginx pattern (not NginxUI)
func IsNginxService(serviceName string) bool {
	pattern := regexp.MustCompile(NginxServiceNamePattern)
	return pattern.MatchString(serviceName)
}

// IsNginxEnabled checks if Nginx service is enabled in the discovered services
func IsNginxEnabled(services []ServiceMetadata) bool {
	for _, svc := range services {
		if svc.Enabled && IsNginxService(svc.Name) {
			return true
		}
	}
	return false
}

// GetNginxService returns the Nginx service metadata if found and enabled
func GetNginxService(services []ServiceMetadata) *ServiceMetadata {
	for i := range services {
		if services[i].Enabled && IsNginxService(services[i].Name) {
			return &services[i]
		}
	}
	return nil
}

// PrepareNginxDeployment prepares Nginx for deployment by creating config directories and base config
func PrepareNginxDeployment(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string) (*NginxConfig, error) {
	log := logging.L().With("component", "nginx")

	log.Infow("preparing Nginx deployment")

	config := &NginxConfig{
		Enabled:     true,
		StoragePath: storagePath,
		ServiceName: "Nginx_Nginx",
	}

	// Create directory structure on shared storage
	confPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, NginxConfDir))
	dirs := []string{
		confPath,
		filepath.ToSlash(filepath.Join(confPath, "conf.d")),
		filepath.ToSlash(filepath.Join(confPath, "sites-enabled")),
		filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, "ssl")),
	}

	for _, dir := range dirs {
		mkdirCmd := fmt.Sprintf("mkdir -p '%s'", dir)
		if _, stderr, err := sshPool.Run(ctx, primaryMaster, mkdirCmd); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w (stderr: %s)", dir, err, stderr)
		}
	}

	// Create base nginx.conf if it doesn't exist
	nginxConfPath := filepath.ToSlash(filepath.Join(confPath, "nginx.conf"))
	if err := createBaseNginxConfig(ctx, sshPool, primaryMaster, nginxConfPath); err != nil {
		return nil, fmt.Errorf("failed to create nginx.conf: %w", err)
	}

	// Create default server config
	defaultServerPath := filepath.ToSlash(filepath.Join(confPath, "conf.d", "default.conf"))
	if err := createDefaultServerConfig(ctx, sshPool, primaryMaster, defaultServerPath); err != nil {
		return nil, fmt.Errorf("failed to create default.conf: %w", err)
	}

	log.Infow("✅ Nginx deployment preparation complete", "confPath", confPath)
	return config, nil
}

// createBaseNginxConfig creates the base nginx.conf if it doesn't exist
func createBaseNginxConfig(ctx context.Context, sshPool *ssh.Pool, host string, configPath string) error {
	log := logging.L().With("component", "nginx")

	// Check if config already exists
	checkCmd := fmt.Sprintf("test -f '%s' && echo 'exists' || echo 'missing'", configPath)
	stdout, _, _ := sshPool.Run(ctx, host, checkCmd)
	if strings.TrimSpace(stdout) == "exists" {
		log.Infow("nginx.conf already exists, skipping creation", "path", configPath)
		return nil
	}

	nginxConf := `# Nginx configuration - managed by dscotctl
# This file is stored on shared storage and synced across all Nginx instances

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript 
               application/xml application/rss+xml application/atom+xml image/svg+xml;

    # Include additional configs
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
`

	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFNGINX'\n%sEOFNGINX", configPath, nginxConf)
	if _, stderr, err := sshPool.Run(ctx, host, writeCmd); err != nil {
		return fmt.Errorf("failed to write nginx.conf: %w (stderr: %s)", err, stderr)
	}

	log.Infow("created nginx.conf", "path", configPath)
	return nil
}

// createDefaultServerConfig creates a default server configuration
func createDefaultServerConfig(ctx context.Context, sshPool *ssh.Pool, host string, configPath string) error {
	log := logging.L().With("component", "nginx")

	// Check if config already exists
	checkCmd := fmt.Sprintf("test -f '%s' && echo 'exists' || echo 'missing'", configPath)
	stdout, _, _ := sshPool.Run(ctx, host, checkCmd)
	if strings.TrimSpace(stdout) == "exists" {
		log.Infow("default.conf already exists, skipping creation", "path", configPath)
		return nil
	}

	defaultConf := `# Default server configuration - managed by dscotctl
# Proxy rules will be added to this file or separate files in conf.d/

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Health check endpoint for Docker healthcheck
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Default location - can be customized
    location / {
        return 200 "Nginx is running\n";
        add_header Content-Type text/plain;
    }

    # Proxy locations will be added below by dscotctl
    # Example:
    # location /portainer/ {
    #     proxy_pass http://portainer:9000/;
    #     proxy_http_version 1.1;
    #     proxy_set_header Upgrade $http_upgrade;
    #     proxy_set_header Connection "upgrade";
    #     proxy_set_header Host $host;
    #     proxy_set_header X-Real-IP $remote_addr;
    #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    # }
}
`

	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFDEFAULT'\n%sEOFDEFAULT", configPath, defaultConf)
	if _, stderr, err := sshPool.Run(ctx, host, writeCmd); err != nil {
		return fmt.Errorf("failed to write default.conf: %w (stderr: %s)", err, stderr)
	}

	log.Infow("created default.conf", "path", configPath)
	return nil
}

// ProxyRule defines a reverse proxy rule for Nginx
type ProxyRule struct {
	Name        string // Rule name for identification
	Location    string // URL path (e.g., "/portainer/")
	Upstream    string // Upstream address (e.g., "portainer:9000")
	StripPrefix bool   // Whether to strip the location prefix when proxying
	WebSocket   bool   // Whether to enable WebSocket support
}

// AddProxyRule adds a proxy rule to the Nginx configuration
// This can be expanded later to support more complex proxy configurations
func AddProxyRule(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, rule ProxyRule) error {
	log := logging.L().With("component", "nginx", "rule", rule.Name)

	confPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, NginxConfDir, "conf.d"))
	ruleFile := filepath.ToSlash(filepath.Join(confPath, fmt.Sprintf("proxy-%s.conf", strings.ToLower(rule.Name))))

	// Build the proxy configuration
	var proxyConf strings.Builder
	proxyConf.WriteString(fmt.Sprintf("# Proxy rule: %s - managed by dscotctl\n", rule.Name))
	proxyConf.WriteString(fmt.Sprintf("# Generated for upstream: %s\n\n", rule.Upstream))

	// Upstream block
	upstreamName := fmt.Sprintf("%s_upstream", strings.ToLower(strings.ReplaceAll(rule.Name, "-", "_")))
	proxyConf.WriteString(fmt.Sprintf("upstream %s {\n", upstreamName))
	proxyConf.WriteString(fmt.Sprintf("    server %s;\n", rule.Upstream))
	proxyConf.WriteString("    keepalive 32;\n")
	proxyConf.WriteString("}\n\n")

	// Server block with location
	proxyConf.WriteString("server {\n")
	proxyConf.WriteString("    listen 80;\n")
	proxyConf.WriteString("    server_name _;\n\n")

	// Location block
	proxyConf.WriteString(fmt.Sprintf("    location %s {\n", rule.Location))
	if rule.StripPrefix {
		proxyConf.WriteString(fmt.Sprintf("        rewrite ^%s(.*)$ /$1 break;\n", strings.TrimSuffix(rule.Location, "/")))
	}
	proxyConf.WriteString(fmt.Sprintf("        proxy_pass http://%s;\n", upstreamName))
	proxyConf.WriteString("        proxy_http_version 1.1;\n")
	proxyConf.WriteString("        proxy_set_header Host $host;\n")
	proxyConf.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	proxyConf.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	proxyConf.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")

	if rule.WebSocket {
		proxyConf.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
		proxyConf.WriteString("        proxy_set_header Connection \"upgrade\";\n")
	}

	proxyConf.WriteString("    }\n")
	proxyConf.WriteString("}\n")

	// Write the config file
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFPROXY'\n%sEOFPROXY", ruleFile, proxyConf.String())
	if _, stderr, err := sshPool.Run(ctx, primaryMaster, writeCmd); err != nil {
		return fmt.Errorf("failed to write proxy rule: %w (stderr: %s)", err, stderr)
	}

	log.Infow("added proxy rule", "location", rule.Location, "upstream", rule.Upstream, "file", ruleFile)
	return nil
}

// ReloadNginx reloads Nginx configuration on all Nginx containers
func ReloadNginx(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, serviceName string) error {
	log := logging.L().With("component", "nginx")

	// Use docker service update --force to trigger a rolling restart
	// This is safer than trying to exec into containers
	updateCmd := fmt.Sprintf("docker service update --force %s 2>/dev/null || true", serviceName)
	if _, stderr, err := sshPool.Run(ctx, primaryMaster, updateCmd); err != nil {
		log.Warnw("failed to reload Nginx service", "error", err, "stderr", stderr)
		return err
	}

	log.Infow("✅ Nginx service reload triggered", "serviceName", serviceName)
	return nil
}

