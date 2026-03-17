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
	// EdgeLoadBalancerServiceNamePattern matches EdgeLoadBalancer service names
	EdgeLoadBalancerServiceNamePattern = `(?i)^edgeloadbalancer$`
	// EdgeLoadBalancerMasterLabelKey is the Docker node label for the nginx-ui master node
	EdgeLoadBalancerMasterLabelKey = "EdgeLoadBalancerMaster"
	// EdgeLoadBalancerSlaveLabelKey is the Docker node label for nginx slave nodes
	EdgeLoadBalancerSlaveLabelKey = "EdgeLoadBalancerSlave"
	// EdgeLoadBalancerLabelValue is the expected value for the load balancer labels
	EdgeLoadBalancerLabelValue = "true"
	// EdgeLoadBalancerDataDir is the subdirectory for Nginx/EdgeLoadBalancer data
	EdgeLoadBalancerDataDir = "EdgeLoadBalancer"
	// EdgeLoadBalancerNginxDir is the subdirectory for Nginx configuration (maps to /etc/nginx)
	EdgeLoadBalancerNginxDir = "nginx"
	// EdgeLoadBalancerNginxUIDir is the subdirectory for nginx-ui application data
	EdgeLoadBalancerNginxUIDir = "nginx-ui"
)

// IsEdgeLoadBalancerService checks if a service is the EdgeLoadBalancer (Nginx)
func IsEdgeLoadBalancerService(serviceName string) bool {
	pattern := regexp.MustCompile(EdgeLoadBalancerServiceNamePattern)
	return pattern.MatchString(serviceName)
}

// IsEdgeLoadBalancerEnabled checks if EdgeLoadBalancer service is enabled in the discovered services
func IsEdgeLoadBalancerEnabled(services []ServiceMetadata) bool {
	for _, svc := range services {
		if svc.Enabled && IsEdgeLoadBalancerService(svc.Name) {
			return true
		}
	}
	return false
}

// GetEdgeLoadBalancerService returns the EdgeLoadBalancer service metadata if found and enabled
func GetEdgeLoadBalancerService(services []ServiceMetadata) *ServiceMetadata {
	for i := range services {
		if services[i].Enabled && IsEdgeLoadBalancerService(services[i].Name) {
			return &services[i]
		}
	}
	return nil
}

// PrepareEdgeLoadBalancerDeployment prepares EdgeLoadBalancer for deployment.
// In the Master/Slave architecture, nginx-ui (Master) initializes /etc/nginx with the standard
// nginx layout on first start. This function only creates supplementary files like SSL certificates.
// Directory creation is handled dynamically by parseBindMounts in services.go which parses the YAML.
func PrepareEdgeLoadBalancerDeployment(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string) (*NginxConfig, error) {
	log := logging.L().With("component", "edgeloadbalancer")

	log.Infow("preparing EdgeLoadBalancer Master/Slave deployment")

	config := &NginxConfig{
		Enabled:     true,
		StoragePath: storagePath,
		ServiceName: "EdgeLoadBalancer_EdgeLoadBalancerSlave",
	}

	// Pre-create the standard nginx directory structure on shared storage.
	// nginx-ui (Master) manages configs, but we ensure all directories exist so both
	// Master and Slave containers can start cleanly on first deployment.

	nginxPath := filepath.ToSlash(filepath.Join(storagePath, "data", EdgeLoadBalancerDataDir, EdgeLoadBalancerNginxDir))

	// Standard nginx directories
	nginxDirs := []string{
		nginxPath,                                    // /etc/nginx root
		filepath.ToSlash(filepath.Join(nginxPath, "conf.d")),          // http server configs
		filepath.ToSlash(filepath.Join(nginxPath, "sites-available")), // available site configs
		filepath.ToSlash(filepath.Join(nginxPath, "sites-enabled")),   // enabled site symlinks
		filepath.ToSlash(filepath.Join(nginxPath, "stream.d")),        // TCP/UDP stream configs
		filepath.ToSlash(filepath.Join(nginxPath, "ssl")),             // SSL certificates
		filepath.ToSlash(filepath.Join(nginxPath, "snippets")),        // reusable config snippets
		filepath.ToSlash(filepath.Join(nginxPath, "modules-enabled")), // dynamically loaded modules
	}

	for _, dir := range nginxDirs {
		if _, stderr, err := sshPool.Run(ctx, primaryMaster, fmt.Sprintf("mkdir -p '%s'", dir)); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w (stderr: %s)", dir, err, stderr)
		}
	}

	log.Infow("created nginx directory structure", "root", nginxPath)

	// Create default self-signed SSL certificate if it doesn't exist
	// nginx-ui can manage certs via its UI, but we provide a fallback for initial HTTPS
	sslPath := filepath.ToSlash(filepath.Join(nginxPath, "ssl"))
	if err := createDefaultSSLCertificate(ctx, sshPool, primaryMaster, sslPath); err != nil {
		log.Warnw("failed to create default SSL certificate", "error", err)
	}

	log.Infow("✅ EdgeLoadBalancer deployment preparation complete", "nginxPath", nginxPath)
	return config, nil
}

// createBaseNginxConfig creates the base nginx.conf if it doesn't exist
func createBaseNginxConfig(ctx context.Context, sshPool *ssh.Pool, host string, configPath string) error {
	log := logging.L().With("component", "nginx")

	// Ensure parent directory exists
	parentDir := filepath.ToSlash(filepath.Dir(configPath))
	if _, stderr, err := sshPool.Run(ctx, host, fmt.Sprintf("mkdir -p '%s'", parentDir)); err != nil {
		return fmt.Errorf("failed to create parent directory %s: %w (stderr: %s)", parentDir, err, stderr)
	}

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
    worker_connections 1024;
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

// createDefaultServerConfig creates a minimal default server configuration in sites-available/
// with a symlink in sites-enabled/. This is a placeholder that gets overwritten by
// GenerateProxyRulesForServices with the full config including proxy rules.
// nginxPath should be the root nginx directory on shared storage (e.g., .../EdgeLoadBalancer/nginx).
func createDefaultServerConfig(ctx context.Context, sshPool *ssh.Pool, host string, nginxPath string) error {
	log := logging.L().With("component", "nginx")

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

	if err := writeSiteConfig(ctx, sshPool, host, nginxPath, "default", defaultConf); err != nil {
		return fmt.Errorf("failed to write default site config: %w", err)
	}

	log.Infow("created default site config", "nginxPath", nginxPath)
	return nil
}

// createDefaultSSLCertificate creates a self-signed SSL certificate if one doesn't exist
// This provides a default certificate for HTTPS until proper certificates are configured
func createDefaultSSLCertificate(ctx context.Context, sshPool *ssh.Pool, host string, sslPath string) error {
	log := logging.L().With("component", "nginx")

	certFile := filepath.ToSlash(filepath.Join(sslPath, "default.crt"))
	keyFile := filepath.ToSlash(filepath.Join(sslPath, "default.key"))

	// Check if certificate already exists
	checkCmd := fmt.Sprintf("test -f '%s' && test -f '%s' && echo 'exists'", certFile, keyFile)
	stdout, _, _ := sshPool.Run(ctx, host, checkCmd)
	if strings.TrimSpace(stdout) == "exists" {
		log.Infow("default SSL certificate already exists", "cert", certFile)
		return nil
	}

	// Generate self-signed certificate valid for 10 years
	// Uses a wildcard CN and SAN to work with any hostname
	genCmd := fmt.Sprintf(`
		mkdir -p '%s'
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
			-keyout '%s' \
			-out '%s' \
			-subj '/C=US/ST=Default/L=Default/O=EdgeLoadBalancer/CN=localhost' \
			-addext 'subjectAltName=DNS:localhost,DNS:*.local,IP:127.0.0.1'
		chmod 644 '%s'
		chmod 600 '%s'
	`, sslPath, keyFile, certFile, certFile, keyFile)

	if _, stderr, err := sshPool.Run(ctx, host, genCmd); err != nil {
		return fmt.Errorf("failed to generate SSL certificate: %w (stderr: %s)", err, stderr)
	}

	log.Infow("created default self-signed SSL certificate", "cert", certFile, "key", keyFile)
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

// AddProxyRule adds a proxy rule to the Nginx configuration.
// The config is written to sites-available/ with a symlink in sites-enabled/ for nginx-ui compatibility.
func AddProxyRule(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, rule ProxyRule) error {
	log := logging.L().With("component", "nginx", "rule", rule.Name)

	nginxPath := filepath.ToSlash(filepath.Join(storagePath, "data", EdgeLoadBalancerDataDir, EdgeLoadBalancerNginxDir))
	siteName := fmt.Sprintf("proxy-%s", strings.ToLower(rule.Name))

	// Remove legacy conf.d version if it exists (migration from old layout)
	legacyFile := filepath.ToSlash(filepath.Join(nginxPath, "conf.d", fmt.Sprintf("proxy-%s.conf", strings.ToLower(rule.Name))))
	sshPool.Run(ctx, primaryMaster, fmt.Sprintf("rm -f '%s'", legacyFile)) //nolint:errcheck

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

	// Write to sites-available/ and create symlink in sites-enabled/
	if err := writeSiteConfig(ctx, sshPool, primaryMaster, nginxPath, siteName, proxyConf.String()); err != nil {
		return fmt.Errorf("failed to write proxy rule site config: %w", err)
	}

	log.Infow("added proxy rule", "location", rule.Location, "upstream", rule.Upstream, "site", siteName)
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

// createHtpasswdFile creates an htpasswd file for basic authentication
// credentials format: "user:password"
func createHtpasswdFile(ctx context.Context, sshPool *ssh.Pool, host string, authPath string, serviceName string, credentials string) error {
	log := logging.L().With("component", "nginx", "service", serviceName)

	// Parse credentials
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid credentials format, expected 'user:password'")
	}
	username := parts[0]
	password := parts[1]

	htpasswdFile := filepath.ToSlash(filepath.Join(authPath, fmt.Sprintf("%s.htpasswd", strings.ToLower(serviceName))))

	// Create htpasswd file using openssl for password hashing (apr1 format)
	// This is compatible with nginx auth_basic
	createCmd := fmt.Sprintf(`
		mkdir -p '%s'
		HASHED=$(openssl passwd -apr1 '%s')
		echo '%s:'"$HASHED" > '%s'
		chmod 644 '%s'
	`, authPath, password, username, htpasswdFile, htpasswdFile)

	if _, stderr, err := sshPool.Run(ctx, host, createCmd); err != nil {
		return fmt.Errorf("failed to create htpasswd file: %w (stderr: %s)", err, stderr)
	}

	log.Infow("created htpasswd file", "file", htpasswdFile, "user", username)
	return nil
}

// writeSiteConfig writes a config file to sites-available/ and creates a symlink in sites-enabled/.
// This follows the standard nginx pattern that nginx-ui expects for site management.
// The fileName should not include a path prefix (e.g., "default", "proxy-portainer").
func writeSiteConfig(ctx context.Context, sshPool *ssh.Pool, host string, nginxPath string, fileName string, content string) error {
	sitesAvailable := filepath.ToSlash(filepath.Join(nginxPath, "sites-available"))
	sitesEnabled := filepath.ToSlash(filepath.Join(nginxPath, "sites-enabled"))

	availablePath := filepath.ToSlash(filepath.Join(sitesAvailable, fileName))
	enabledPath := filepath.ToSlash(filepath.Join(sitesEnabled, fileName))

	// Write the config file to sites-available
	writeCmd := fmt.Sprintf("cat > '%s' << 'EOFSITECONF'\n%sEOFSITECONF", availablePath, content)
	if _, stderr, err := sshPool.Run(ctx, host, writeCmd); err != nil {
		return fmt.Errorf("failed to write site config %s: %w (stderr: %s)", availablePath, err, stderr)
	}

	// Create symlink in sites-enabled (remove existing first to handle updates)
	symlinkCmd := fmt.Sprintf("ln -sf '%s' '%s'", availablePath, enabledPath)
	if _, stderr, err := sshPool.Run(ctx, host, symlinkCmd); err != nil {
		return fmt.Errorf("failed to create symlink %s -> %s: %w (stderr: %s)", enabledPath, availablePath, err, stderr)
	}

	return nil
}

// removeSiteConfig removes a site config from sites-available and its symlink from sites-enabled.
func removeSiteConfig(ctx context.Context, sshPool *ssh.Pool, host string, nginxPath string, fileName string) {
	sitesAvailable := filepath.ToSlash(filepath.Join(nginxPath, "sites-available"))
	sitesEnabled := filepath.ToSlash(filepath.Join(nginxPath, "sites-enabled"))

	removeCmd := fmt.Sprintf("rm -f '%s' '%s'",
		filepath.ToSlash(filepath.Join(sitesEnabled, fileName)),
		filepath.ToSlash(filepath.Join(sitesAvailable, fileName)),
	)
	sshPool.Run(ctx, host, removeCmd) //nolint:errcheck // best-effort cleanup
}

// GenerateProxyRulesForServices generates Nginx proxy configurations for enabled services with NGINX_PROXY: true
// Services are identified by their Docker Swarm service name pattern: StackName_ServiceName
// Configs are written to sites-available/ with symlinks in sites-enabled/ for nginx-ui compatibility.
// We use variable-based proxy_pass with resolver so Nginx can start even if upstreams haven't started yet.
func GenerateProxyRulesForServices(ctx context.Context, sshPool *ssh.Pool, primaryMaster string, storagePath string, services []ServiceMetadata) error {
	log := logging.L().With("component", "nginx")

	var proxyServices []ServiceMetadata
	for _, svc := range services {
		// Skip disabled services and Nginx itself
		if !svc.Enabled || IsEdgeLoadBalancerService(svc.Name) {
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

	// Create htpasswd files for services with basic auth
	authPath := filepath.ToSlash(filepath.Join(storagePath, "data", EdgeLoadBalancerDataDir, EdgeLoadBalancerNginxDir, "auth"))
	for _, svc := range proxyServices {
		if svc.NginxBasicAuth != "" {
			if err := createHtpasswdFile(ctx, sshPool, primaryMaster, authPath, svc.Name, svc.NginxBasicAuth); err != nil {
				log.Warnw("failed to create htpasswd file", "service", svc.Name, "error", err)
			}
		}
	}

	// Base nginx path on shared storage
	nginxPath := filepath.ToSlash(filepath.Join(storagePath, "data", EdgeLoadBalancerDataDir, EdgeLoadBalancerNginxDir))

	// Remove legacy conf.d/default.conf if it exists (migration from old layout)
	legacyDefault := filepath.ToSlash(filepath.Join(nginxPath, "conf.d", "default.conf"))
	sshPool.Run(ctx, primaryMaster, fmt.Sprintf("rm -f '%s'", legacyDefault)) //nolint:errcheck

	// Build the default site config (HTTP redirect + HTTPS with all proxy locations)
	var config strings.Builder
	config.WriteString("# Default server with proxy rules - auto-generated by dscotctl\n")
	config.WriteString("# Do not edit manually - regenerated on each deployment\n")
	config.WriteString("# Uses variable-based proxy_pass for graceful handling of missing upstreams\n")
	config.WriteString("# All traffic served over HTTPS with self-signed certificate by default\n\n")

	// HTTP server block - redirect to HTTPS (except health check)
	config.WriteString("# HTTP server - redirects all traffic to HTTPS\n")
	config.WriteString("server {\n")
	config.WriteString("    listen 80 default_server;\n")
	config.WriteString("    listen [::]:80 default_server;\n")
	config.WriteString("    server_name _;\n\n")
	config.WriteString("    # Health check endpoint (available over HTTP for Docker healthcheck)\n")
	config.WriteString("    location /health {\n")
	config.WriteString("        access_log off;\n")
	config.WriteString("        return 200 \"healthy\\n\";\n")
	config.WriteString("        add_header Content-Type text/plain;\n")
	config.WriteString("    }\n\n")
	config.WriteString("    # ACME challenge for Let's Encrypt\n")
	config.WriteString("    location /.well-known/acme-challenge/ {\n")
	config.WriteString("        root /etc/nginx/acme-challenge;\n")
	config.WriteString("    }\n\n")
	config.WriteString("    # Redirect all other traffic to HTTPS\n")
	config.WriteString("    location / {\n")
	config.WriteString("        return 301 https://$host$request_uri;\n")
	config.WriteString("    }\n")
	config.WriteString("}\n\n")

	// HTTPS server block with SSL and all proxy locations
	config.WriteString("# HTTPS server with proxy rules\n")
	config.WriteString("server {\n")
	config.WriteString("    listen 443 ssl default_server;\n")
	config.WriteString("    listen [::]:443 ssl default_server;\n")
	config.WriteString("    server_name _;\n\n")
	config.WriteString("    # SSL configuration - uses default self-signed cert until replaced\n")
	config.WriteString("    ssl_certificate /etc/nginx/ssl/default.crt;\n")
	config.WriteString("    ssl_certificate_key /etc/nginx/ssl/default.key;\n")
	config.WriteString("    ssl_protocols TLSv1.2 TLSv1.3;\n")
	config.WriteString("    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n")
	config.WriteString("    ssl_prefer_server_ciphers off;\n")
	config.WriteString("    ssl_session_cache shared:SSL:10m;\n")
	config.WriteString("    ssl_session_timeout 1d;\n\n")
	config.WriteString("    # Docker embedded DNS resolver - allows Nginx to start even if upstreams don't exist yet\n")
	config.WriteString("    resolver 127.0.0.11 valid=10s ipv6=off;\n")
	config.WriteString("    resolver_timeout 5s;\n\n")

	// Health check endpoint for Docker healthcheck (also on HTTPS)
	config.WriteString("    # Health check endpoint\n")
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
			"basicAuth", svc.NginxBasicAuth != "",
			"stripPrefix", svc.NginxStripPrefix,
		)

		config.WriteString(fmt.Sprintf("    # %s\n", svc.Name))
		config.WriteString(fmt.Sprintf("    location %s {\n", proxyPath))

		// Add basic auth if configured
		if svc.NginxBasicAuth != "" {
			htpasswdPath := filepath.ToSlash(filepath.Join("/etc/nginx/auth", fmt.Sprintf("%s.htpasswd", strings.ToLower(svc.Name))))
			config.WriteString(fmt.Sprintf("        auth_basic \"%s\";\n", svc.Name))
			config.WriteString(fmt.Sprintf("        auth_basic_user_file %s;\n", htpasswdPath))
		}

		// Use variable-based proxy_pass so resolver is used at request time, not startup
		config.WriteString(fmt.Sprintf("        set $%s_backend \"%s:%d\";\n", varName, dockerServiceName, port))

		// Strip prefix if enabled (default: true)
		// Rewrites /path/foo -> /foo before proxying
		if svc.NginxStripPrefix {
			config.WriteString(fmt.Sprintf("        rewrite ^%s(.*)$ /$1 break;\n", strings.TrimSuffix(proxyPath, "/")))
		}

		config.WriteString(fmt.Sprintf("        proxy_pass http://$%s_backend;\n", varName))
		config.WriteString("        proxy_http_version 1.1;\n")
		config.WriteString("        proxy_set_header Host $host;\n")
		config.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
		config.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
		config.WriteString("        proxy_set_header X-Forwarded-Proto $scheme;\n")

		// Handle upstream connection errors gracefully
		config.WriteString("        proxy_connect_timeout 5s;\n")
		config.WriteString("        proxy_next_upstream error timeout;\n")

		// Rewrite absolute URLs in responses to include the proxy path prefix
		// This fixes links like href="/settings" -> href="/certmate/settings"
		if svc.NginxStripPrefix {
			pathPrefix := strings.TrimSuffix(proxyPath, "/")
			config.WriteString("        # Rewrite absolute URLs in responses\n")
			config.WriteString("        sub_filter_once off;\n")
			// text/html is included by default, don't duplicate it
			config.WriteString("        sub_filter_types application/javascript text/css application/json;\n")
			config.WriteString(fmt.Sprintf("        sub_filter 'href=\"/' 'href=\"%s/';\n", pathPrefix))
			config.WriteString(fmt.Sprintf("        sub_filter 'src=\"/' 'src=\"%s/';\n", pathPrefix))
			config.WriteString(fmt.Sprintf("        sub_filter 'action=\"/' 'action=\"%s/';\n", pathPrefix))
			config.WriteString(fmt.Sprintf("        sub_filter 'url(/' 'url(%s/';\n", pathPrefix))
			// Also handle redirects
			config.WriteString("        proxy_redirect / " + proxyPath + ";\n")
		}

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

	// Write to sites-available/default and create symlink in sites-enabled/
	if err := writeSiteConfig(ctx, sshPool, primaryMaster, nginxPath, "default", config.String()); err != nil {
		return fmt.Errorf("failed to write default site config: %w", err)
	}

	log.Infow("✅ generated Nginx default site with proxy rules", "services", len(proxyServices))

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

	streamPath := filepath.ToSlash(filepath.Join(storagePath, "data", EdgeLoadBalancerDataDir, EdgeLoadBalancerNginxDir, "stream.d"))
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
