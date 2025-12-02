package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"clusterctl/internal/controller"
	"clusterctl/internal/ipdetect"
	"clusterctl/internal/logging"
	"clusterctl/internal/overlay"
	"clusterctl/internal/swarm"
)

type JoinOptions struct {
	MasterAddr       string
	Role             string
	IPOverride       string
	HostnameOverride string
	OverlayProvider  string
	OverlayConfig    string
	EnableStorage    bool
	UseIPAddress     bool // If true, use IP address instead of hostname for Swarm identity
}

type ResetOptions struct {
	MasterAddr       string
	Role             string
	HostnameOverride string
	OverlayProvider  string
	OverlayConfig    string
	StorageMount     string
	Deregister       bool
	CleanupOverlay   bool
	CleanupStorage   bool
}


// Join implements the node-side behaviour for `clusterctl node join`.
//
// It is designed to be idempotent: repeated joins with the same parameters
// converge the node onto the same desired state.
func Join(ctx context.Context, opts JoinOptions) error {
	if err := validateJoinOptions(opts); err != nil {
		return err
	}

	addr, hostname, err := detectIdentity(ctx, opts)
	if err != nil {
		return err
	}

	reg := controller.NodeRegistration{
		Hostname:       hostname,
		Role:           opts.Role,
		IP:             addr,
		OS:             runtime.GOOS,
		CPU:            runtime.NumCPU(),
		MemoryMB:       memoryMB(),
		DockerVersion:  dockerVersion(ctx),
		StorageEnabled: opts.EnableStorage,
	}

	// Resolve the address to an IP for logging purposes.
	resolvedIP := addr
	if ips, err := net.LookupIP(addr); err == nil && len(ips) > 0 {
		resolvedIP = ips[0].String()
	}

	log := logging.L().With(
		"component", "nodeagent",
		"master", opts.MasterAddr,
		"role", opts.Role,
		"hostname", reg.Hostname,
		"ip", reg.IP,
	)
	log.Infow(fmt.Sprintf("starting node join: sending to controller hostname=%s address=%s resolvedIP=%s role=%s storageEnabled=%t", reg.Hostname, reg.IP, resolvedIP, reg.Role, reg.StorageEnabled))

	backoff := time.Second
	var lastResp *controller.NodeResponse
	var prevResp *controller.NodeResponse

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		resp, err := registerOnce(ctx, opts.MasterAddr, reg)
		if err != nil {
			log.Warnw("registration attempt failed", "err", err)
		} else {
			// Only log if response has changed.
			if prevResp == nil || hasNodeResponseChanged(prevResp, resp) {
				if resp.Status == controller.StatusReady {
					log.Infow("controller signalled ready")
				} else if resp.Status == controller.StatusWaiting {
					log.Infow("controller signalled waiting, backing off")
				}
			}

			lastResp = resp
			prevResp = resp

			if resp.Status == controller.StatusReady {
				break
			} else if resp.Status == controller.StatusWaiting {
				// Continue waiting
			} else {
				return errors.New("nodeagent: unknown status from controller")
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < 30*time.Second {
			backoff *= 2
		}
	}

	if lastResp == nil {
		return errors.New("nodeagent: no response from controller")
	}

	log.Infow(fmt.Sprintf(
		"controller response: status=%s swarmRole=%s managerAddr=%s hasJoinToken=%t storageEnabled=%t storageReady=%t hasSSHKey=%t",
		lastResp.Status,
		lastResp.SwarmRole,
		lastResp.SwarmManagerAddr,
		lastResp.SwarmJoinToken != "",
		lastResp.StorageEnabled,
		lastResp.StorageReady,
		lastResp.SSHPublicKey != "",
	))

	// Install SSH public key for remote orchestration
	if lastResp.SSHPublicKey != "" {
		if err := installSSHKey(ctx, lastResp.SSHPublicKey); err != nil {
			log.Warnw("failed to install SSH public key (non-fatal)", "err", err)
			// Non-fatal; controller can still orchestrate if SSH is already configured
		} else {
			log.Infow("SSH public key installed successfully for remote orchestration")
		}
	}

	if err := overlay.EnsureConnected(ctx, opts.OverlayProvider, opts.OverlayConfig); err != nil {
		log.Warnw("overlay convergence failed", "err", err)
		return err
	}

	// NOTE: Swarm and distributed storage setup is now orchestrated by the controller via SSH.
	// Nodes no longer perform local convergence. They just wait for the controller
	// to complete orchestration and then verify the setup.

	log.Infow("waiting for controller to orchestrate distributed storage and Swarm setup via SSH...")

	// Only proceed if the controller says we're ready.
	// Managers may get StatusWaiting if storage is not ready yet.
	if lastResp.Status == controller.StatusWaiting {
		log.Infow("controller says to wait (storage not ready yet); node join will retry")
		return nil
	}

	if lastResp.StorageEnabled {
		log.Infow("distributed storage enabled for this node")
		// Storage verification is handled by the controller via SSH
	} else {
		log.Infow("distributed storage not enabled for this node by controller")
	}

	log.Infow("node join completed")
	return nil
}

// Reset implements the node-side behaviour for `clusterctl node reset`.
//
// By default it leaves overlay connectivity and storage mounts in place so
// they can be reused. When the corresponding cleanup flags are set it will
// also tear down overlay connectivity and storage mounts, and it always
// attempts to leave the Swarm and optionally deregister from the controller.
func Reset(ctx context.Context, opts ResetOptions) error {
	log := logging.L().With(
		"component", "nodeagent",
		"master", opts.MasterAddr,
		"role", opts.Role,
	)
	log.Infow("starting node reset")

	if opts.CleanupOverlay {
		if err := overlay.Teardown(ctx, opts.OverlayProvider, opts.OverlayConfig); err != nil {
			log.Warnw("overlay teardown failed", "err", err)
			return err
		}
	} else {
		log.Infow("overlay teardown skipped; cleanupOverlay=false")
	}

	if opts.CleanupStorage {
		// Storage cleanup is handled by the controller via SSH
		log.Infow("storage cleanup requested; will be handled by controller")
	} else {
		log.Infow("storage teardown skipped; cleanupStorage=false")
	}

	if err := swarm.Leave(ctx, true); err != nil {
		log.Warnw("swarm leave failed", "err", err)
		return err
	}

	if opts.Deregister {
		if opts.MasterAddr == "" {
			return errors.New("master address is required when deregistering")
		}

		hostname := opts.HostnameOverride
		if hostname == "" {
			var err error
			hostname, err = os.Hostname()
			if err != nil {
				return err
			}
		}

		role := opts.Role
		if role == "" {
			role = "worker"
		}

		reg := controller.NodeRegistration{
			Hostname: hostname,
			Role:     role,
			OS:       runtime.GOOS,
			Action:   "deregister",
		}

		if _, err := registerOnce(ctx, opts.MasterAddr, reg); err != nil {
			log.Warnw("deregistration failed", "err", err)
			return err
		}
	}

	log.Infow("node reset completed")
	return nil
}


func validateJoinOptions(opts JoinOptions) error {
	if opts.MasterAddr == "" {
		return errors.New("master address is required")
	}
	if opts.Role == "" {
		opts.Role = "worker"
	}
	if opts.Role != "manager" && opts.Role != "worker" {
		return errors.New("role must be 'manager' or 'worker'")
	}
	return nil
}

// detectIdentity returns the address (typically an overlay hostname/FQDN or
// IP) and hostname that should be used when registering the node with the
// controller. The address is what Swarm will ultimately use to talk to
// this node.
func detectIdentity(ctx context.Context, opts JoinOptions) (addr string, hostname string, err error) {
	// Hostname first: honour explicit override, otherwise fall back to os.Hostname.
	if opts.HostnameOverride != "" {
		hostname = opts.HostnameOverride
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			return "", "", err
		}
	}

	// Address: prefer explicit override, otherwise ask overlay provider (if any)
	// for a stable hostname/FQDN. If that fails, fall back to the detected
	// primary IP.
	if opts.IPOverride != "" {
		addr = opts.IPOverride
		return addr, hostname, nil
	}

	// If UseIPAddress is true, skip hostname detection and use IP directly.
	if opts.UseIPAddress {
		ip, ierr := ipdetect.DetectPrimary()
		if ierr != nil {
			return "", "", ierr
		}
		addr = ip.String()
		return addr, hostname, nil
	}

	// Try overlay-specific hostname where possible (default behavior).
	overlayName := strings.ToLower(strings.TrimSpace(opts.OverlayProvider))
	switch overlayName {
	case "netbird":
		if h, herr := overlay.NetbirdHostname(ctx); herr == nil && h != "" {
			addr = h
			return addr, hostname, nil
		}
	case "tailscale":
		if h, herr := overlay.TailscaleHostname(ctx); herr == nil && h != "" {
			addr = h
			return addr, hostname, nil
		}
	}

	// Fallback: primary IP as before.
	ip, ierr := ipdetect.DetectPrimary()
	if ierr != nil {
		return "", "", ierr
	}
	addr = ip.String()
	return addr, hostname, nil
}

func registerOnce(ctx context.Context, master string, reg controller.NodeRegistration) (*controller.NodeResponse, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", master)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(&reg); err != nil {
		return nil, err
	}

	var resp controller.NodeResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func convergeSwarm(ctx context.Context, opts JoinOptions, resp *controller.NodeResponse) error {
	active, err := swarm.IsActive(ctx)
	if err != nil {
		return err
	}
	if active {
		logging.L().Infow("swarm already active on this node; skipping swarm convergence")
		return nil
	}

	role := resp.SwarmRole
	if role == "" {
		role = opts.Role
	}

	managerAddr := resp.SwarmManagerAddr
	if managerAddr == "" {
		return fmt.Errorf("nodeagent: controller did not provide SwarmManagerAddr; cannot join swarm (role=%s)", role)
	}

	if resp.SwarmJoinToken == "" {
		return fmt.Errorf("nodeagent: missing swarm join token for role=%s", role)
	}

	logging.L().Infow(fmt.Sprintf("joining swarm as %s using manager %s and token %s", role, managerAddr, resp.SwarmJoinToken))

	if err := swarm.Join(ctx, resp.SwarmJoinToken, managerAddr); err != nil {
		return err
	}

	if info, err := swarm.Status(ctx); err == nil {
		logging.L().Infow(fmt.Sprintf("swarm info after join: localState=%s nodeID=%s addr=%s manager=%t clusterID=%s", info.LocalState, info.NodeID, info.NodeAddr, info.Manager, info.ClusterID))
	}

	return nil
}


func dockerVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func memoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	// Look for a line like: "MemTotal:       16367440 kB"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		return kb / 1024
	}
	return 0
}

// hasNodeResponseChanged checks if the response has changed in any meaningful way.
func hasNodeResponseChanged(old, new *controller.NodeResponse) bool {
	if old == nil || new == nil {
		return true
	}
	if old.Status != new.Status {
		return true
	}
	if old.SwarmJoinToken != new.SwarmJoinToken {
		return true
	}
	if old.StorageEnabled != new.StorageEnabled {
		return true
	}
	if old.StorageReady != new.StorageReady {
		return true
	}
	return false
}

// installSSHKey installs the controller's SSH public key to ~/.ssh/authorized_keys
// for remote orchestration.
func installSSHKey(ctx context.Context, publicKey string) error {
	if publicKey == "" {
		return errors.New("ssh public key is empty")
	}

	// Get current user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	sshDir := homeDir + "/.ssh"
	authorizedKeysPath := sshDir + "/authorized_keys"

	// Create .ssh directory if it doesn't exist
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Read existing authorized_keys file
	existingKeys := ""
	if data, err := os.ReadFile(authorizedKeysPath); err == nil {
		existingKeys = string(data)
	}

	// Check if key already exists
	if strings.Contains(existingKeys, strings.TrimSpace(publicKey)) {
		logging.L().Infow("SSH public key already exists in authorized_keys")
		return nil
	}

	// Append the new key
	f, err := os.OpenFile(authorizedKeysPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open authorized_keys: %w", err)
	}
	defer f.Close()

	// Ensure there's a newline before the key if the file is not empty
	if existingKeys != "" && !strings.HasSuffix(existingKeys, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return fmt.Errorf("failed to write newline: %w", err)
		}
	}

	if _, err := f.WriteString(strings.TrimSpace(publicKey) + "\n"); err != nil {
		return fmt.Errorf("failed to write SSH public key: %w", err)
	}

	logging.L().Infow(fmt.Sprintf("SSH public key added to %s", authorizedKeysPath))
	return nil
}
