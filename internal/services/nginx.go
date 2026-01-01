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
	// NginxLabelKey is the Docker node label for edge load balancer nodes
	NginxLabelKey = "EdgeLoadBalancer"
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
		ServiceName: "Nginx_EdgeLoadBalancer",
	}

	// Create directory structure on shared storage
	confPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, NginxConfDir))
	dirs := []string{
		confPath,
		filepath.ToSlash(filepath.Join(confPath, "conf.d")),
		filepath.ToSlash(filepath.Join(confPath, "sites-enabled")),
		filepath.ToSlash(filepath.Join(confPath, "stream.d")), // TCP/UDP stream configs
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

# TCP/UDP stream proxying (for agent tunnels, databases, etc.)
# Include stream configs if directory exists
include /etc/nginx/stream.d/*.conf;
`

	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFNGINX'\n%sEOFNGINX", configPath, nginxConf)
	if _, stderr, err := sshPool.Run(ctx, host, writeCmd); err != nil {
		return fmt.Errorf("failed to write nginx.conf: %w (stderr: %s)", err, stderr)
	}

	log.Infow("created nginx.conf", "path", configPath)
	return nil
}

// createDefaultServerConfig creates a minimal default server configuration
// This is a placeholder that gets overwritten by GenerateProxyRulesForServices with the full config
func createDefaultServerConfig(ctx context.Context, sshPool *ssh.Pool, host string, configPath string) error {
	log := logging.L().With("component", "nginx")

	// Always create/overwrite with a minimal config
	// The full config with proxy rules will be generated by GenerateProxyRulesForServices
	defaultConf := `# Default server configuration - managed by dscotctl
# This file is auto-generated and will be updated with proxy rules during deployment

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Docker embedded DNS resolver - allows Nginx to start even if upstreams don't exist yet
    resolver 127.0.0.11 valid=10s ipv6=off;
    resolver_timeout 5s;

    # Health check endpoint for Docker healthcheck
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Default location - returns welcome message
    location / {
        return 200 "Nginx EdgeLoadBalancer is running\n";
        add_header Content-Type text/plain;
    }

    # Proxy locations will be added by GenerateProxyRulesForServices
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

// GenerateProxyRulesForServices generates Nginx proxy configurations for enabled services with NGINX_PROXY: true
// Services are identified by their Docker Swarm service name pattern: StackName_ServiceName
// We use variable-based proxy_pass with resolver so Nginx can start even if upstreams haven't started yet.
func GenerateProxyRulesForServices(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, services []ServiceMetadata) error {
	log := logging.L().With("component", "nginx")

	var proxyServices []ServiceMetadata
	for _, svc := range services {
		// Skip disabled services, Nginx itself, and PortainerAgent
		if !svc.Enabled || IsNginxService(svc.Name) || svc.Name == "PortainerAgent" {
			continue
		}
		// Only include services with NGINX_PROXY: true
		if svc.NginxProxy {
			proxyServices = append(proxyServices, svc)
		}
	}

	if len(proxyServices) == 0 {
		log.Infow("no services require Nginx proxy rules")
		return nil
	}

	log.Infow("generating Nginx proxy rules for services", "count", len(proxyServices))

	// Write to default.conf - this is the single server block with health check + proxy rules
	// This replaces the placeholder created by createDefaultServerConfig
	confPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, NginxConfDir, "conf.d"))
	defaultConfigPath := filepath.ToSlash(filepath.Join(confPath, "default.conf"))

	var config strings.Builder
	config.WriteString("# Default server with proxy rules - auto-generated by dscotctl\n")
	config.WriteString("# Do not edit manually - regenerated on each deployment\n")
	config.WriteString("# Uses variable-based proxy_pass for graceful handling of missing upstreams\n\n")

	// Single server block with health check and all proxy locations
	config.WriteString("server {\n")
	config.WriteString("    listen 80 default_server;\n")
	config.WriteString("    listen [::]:80 default_server;\n")
	config.WriteString("    server_name _;\n\n")
	config.WriteString("    # Docker embedded DNS resolver - allows Nginx to start even if upstreams don't exist yet\n")
	config.WriteString("    resolver 127.0.0.11 valid=10s ipv6=off;\n")
	config.WriteString("    resolver_timeout 5s;\n\n")

	// Health check endpoint for Docker healthcheck
	config.WriteString("    # Health check endpoint for Docker healthcheck\n")
	config.WriteString("    location /health {\n")
	config.WriteString("        access_log off;\n")
	config.WriteString("        return 200 \"healthy\\n\";\n")
	config.WriteString("        add_header Content-Type text/plain;\n")
	config.WriteString("    }\n\n")

	// Add proxy rules for each service
	for _, svc := range proxyServices {
		// Docker Swarm service name format: StackName_ServiceName
		dockerServiceName := fmt.Sprintf("%s_%s", svc.Name, svc.Name)

		proxyPath := svc.NginxPath
		if !strings.HasSuffix(proxyPath, "/") {
			proxyPath += "/"
		}

		port := svc.NginxPort
		if port == 0 {
			port = 80
		}

		// Create a safe variable name (lowercase, underscores)
		varName := strings.ToLower(strings.ReplaceAll(svc.Name, "-", "_"))

		log.Infow("adding proxy rule",
			"service", svc.Name,
			"path", proxyPath,
			"upstream", fmt.Sprintf("%s:%d", dockerServiceName, port),
			"websocket", svc.NginxWebSocket,
		)

		config.WriteString(fmt.Sprintf("    # %s\n", svc.Name))
		config.WriteString(fmt.Sprintf("    location %s {\n", proxyPath))
		// Use variable-based proxy_pass so resolver is used at request time, not startup
		config.WriteString(fmt.Sprintf("        set $%s_backend \"%s:%d\";\n", varName, dockerServiceName, port))
		config.WriteString(fmt.Sprintf("        proxy_pass http://$%s_backend;\n", varName))
		config.WriteString("        proxy_http_version 1.1;\n")
		config.WriteString("        proxy_set_header Host $host;\n")
		config.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		config.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		config.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")
		// Handle upstream connection errors gracefully
		config.WriteString("        proxy_connect_timeout 5s;\n")
		config.WriteString("        proxy_next_upstream error timeout;\n")

		if svc.NginxWebSocket {
			config.WriteString("        proxy_set_header Upgrade $http_upgrade;\n")
			config.WriteString("        proxy_set_header Connection \"upgrade\";\n")
			config.WriteString("        proxy_read_timeout 86400;\n")
		}

		config.WriteString("    }\n\n")
	}

	// Default location - fallback for unmatched paths
	config.WriteString("    # Default location - fallback for unmatched paths\n")
	config.WriteString("    location / {\n")
	config.WriteString("        return 200 \"Nginx EdgeLoadBalancer is running\\n\";\n")
	config.WriteString("        add_header Content-Type text/plain;\n")
	config.WriteString("    }\n")

	config.WriteString("}\n")

	// Write the config file
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFDEFAULT'\n%sEOFDEFAULT", defaultConfigPath, config.String())
	if _, stderr, err := sshPool.Run(ctx, primaryMaster, writeCmd); err != nil {
		return fmt.Errorf("failed to write default.conf: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✅ generated Nginx default.conf with proxy rules", "file", defaultConfigPath, "services", len(proxyServices))

	// Generate TCP stream configs for services with NGINX_TCP_STREAM
	if err := generateTCPStreamConfigs(ctx, sshPool, primaryMaster, storagePath, services); err != nil {
		log.Warnw("failed to generate TCP stream configs", "error", err)
	}

	return nil
}

// generateTCPStreamConfigs generates Nginx stream configs for TCP/UDP proxying
// NGINX_TCP_STREAM format: backend_port:nginx_port (e.g., 8000:9001)
func generateTCPStreamConfigs(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, services []ServiceMetadata) error {
	log := logging.L().With("component", "nginx")
	var streamServices []ServiceMetadata
	for _, svc := range services {
		if !svc.Enabled || svc.NginxTCPStream == "" {
			continue
		}
		streamServices = append(streamServices, svc)
	}

	if len(streamServices) == 0 {
		return nil
	}

	streamPath := filepath.ToSlash(filepath.Join(storagePath, "data", NginxDataDir, NginxConfDir, "stream.d"))
	streamConfigPath := filepath.ToSlash(filepath.Join(streamPath, "services-stream.conf"))

	var streamConfig strings.Builder
	streamConfig.WriteString("# TCP stream proxy rules - auto-generated by dscotctl\n")
	streamConfig.WriteString("# Do not edit manually - regenerated on each deployment\n\n")
	streamConfig.WriteString("stream {\n")

	for _, svc := range streamServices {
		// Parse NGINX_TCP_STREAM: backend_port:nginx_port
		parts := strings.Split(svc.NginxTCPStream, ":")
		if len(parts) != 2 {
			log.Warnw("invalid NGINX_TCP_STREAM format, expected backend_port:nginx_port",
				"service", svc.Name,
				"value", svc.NginxTCPStream,
			)
			continue
		}

		backendPort := strings.TrimSpace(parts[0])
		nginxPort := strings.TrimSpace(parts[1])

		// Docker Swarm service name: StackName_ServiceName
		dockerServiceName := fmt.Sprintf("%s_%s", svc.Name, svc.Name)
		upstreamName := fmt.Sprintf("%s_tcp_upstream", strings.ToLower(strings.ReplaceAll(svc.Name, "-", "_")))

		log.Infow("adding TCP stream rule",
			"service", svc.Name,
			"backend", fmt.Sprintf("%s:%s", dockerServiceName, backendPort),
			"nginxPort", nginxPort,
		)

		streamConfig.WriteString(fmt.Sprintf("    # TCP stream for %s (backend port %s -> nginx port %s)\n", svc.Name, backendPort, nginxPort))
		streamConfig.WriteString(fmt.Sprintf("    upstream %s {\n", upstreamName))
		streamConfig.WriteString(fmt.Sprintf("        server %s:%s;\n", dockerServiceName, backendPort))
		streamConfig.WriteString("    }\n\n")
		streamConfig.WriteString(fmt.Sprintf("    server {\n"))
		streamConfig.WriteString(fmt.Sprintf("        listen %s;\n", nginxPort))
		streamConfig.WriteString(fmt.Sprintf("        proxy_pass %s;\n", upstreamName))
		streamConfig.WriteString("        proxy_connect_timeout 10s;\n")
		streamConfig.WriteString("        proxy_timeout 300s;\n")
		streamConfig.WriteString("    }\n\n")
	}

	streamConfig.WriteString("}\n")

	// Write the stream config file
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFSTREAM'\n%sEOFSTREAM", streamConfigPath, streamConfig.String())
	if _, stderr, err := sshPool.Run(ctx, primaryMaster, writeCmd); err != nil {
		return fmt.Errorf("failed to write stream config: %w (stderr: %s)", err, stderr)
	}

	log.Infow("✅ generated Nginx TCP stream rules", "file", streamConfigPath, "services", len(streamServices))
	return nil
}
