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
	"clusterctl/internal/deps"
	"clusterctl/internal/gluster"
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
	EnableGluster    bool
}

type ResetOptions struct {
	MasterAddr        string
	Role              string
	HostnameOverride  string
	OverlayProvider   string
	OverlayConfig     string
	GlusterMount      string
	Deregister        bool
	CleanupOverlay    bool
	CleanupGlusterfs  bool
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
		GlusterCapable: opts.EnableGluster,
	}

	log := logging.L().With(
		"component", "nodeagent",
		"master", opts.MasterAddr,
		"role", opts.Role,
		"hostname", reg.Hostname,
		"ip", reg.IP,
	)
	log.Infow("starting node join")

	backoff := time.Second
	var lastResp *controller.NodeResponse

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		resp, err := registerOnce(ctx, opts.MasterAddr, reg)
		if err != nil {
			log.Warnw("registration attempt failed", "err", err)
		} else {
			lastResp = resp
			if resp.Status == controller.StatusReady {
				log.Infow("controller signalled ready")
				break
			} else if resp.Status == controller.StatusWaiting {
				log.Infow("controller signalled waiting, backing off")
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
		"controller response: status=%s swarmRole=%s managerAddr=%s hasJoinToken=%t glusterEnabled=%t glusterVolume=%s glusterMount=%s glusterBrick=%s",
		lastResp.Status,
		lastResp.SwarmRole,
		lastResp.SwarmManagerAddr,
		lastResp.SwarmJoinToken != "",
		lastResp.GlusterEnabled,
		lastResp.GlusterVolume,
		lastResp.GlusterMount,
		lastResp.GlusterBrick,
	))

	if err := overlay.EnsureConnected(ctx, opts.OverlayProvider, opts.OverlayConfig); err != nil {
		log.Warnw("overlay convergence failed", "err", err)
		return err
	}

	if err := convergeSwarm(ctx, opts, lastResp); err != nil {
		log.Warnw("swarm convergence failed", "err", err)
		return err
	}

	if lastResp.GlusterEnabled {
		if err := convergeGluster(ctx, opts, lastResp, log); err != nil {
			log.Warnw("gluster convergence failed", "err", err)
			return err
		}
	} else {
		log.Infow("gluster not enabled for this node by controller")
	}

	log.Infow("node join completed")
	return nil
}

// Reset implements the node-side behaviour for `clusterctl node reset`.
//
// By default it leaves overlay connectivity and GlusterFS mounts in place so
// they can be reused. When the corresponding cleanup flags are set it will
// also tear down overlay connectivity and GlusterFS mounts, and it always
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

	if opts.CleanupGlusterfs {
		if err := gluster.Teardown(ctx, opts.GlusterMount); err != nil {
			log.Warnw("gluster teardown failed", "err", err)
			return err
		}
	} else {
		log.Infow("gluster teardown skipped; cleanupGlusterfs=false")
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
// controller. The address is what Swarm/gluster will ultimately use to talk to
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

	// Try overlay-specific hostname where possible.
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
		managerAddr = opts.MasterAddr
	}

	if resp.SwarmJoinToken == "" || managerAddr == "" {
		return fmt.Errorf("nodeagent: missing swarm join token or manager address for role=%s (managerAddr=%q)", role, managerAddr)
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

func convergeGluster(ctx context.Context, opts JoinOptions, resp *controller.NodeResponse, log *logging.Logger) error {
	if opts.Role == "worker" {
		// Workers host bricks.
		if resp.GlusterOrchestrator {
			// This worker is the orchestrator.
			log.Infow("this worker is the gluster orchestrator", "workers", len(resp.GlusterWorkerNodes))
			if err := gluster.Orchestrate(ctx, resp.GlusterVolume, resp.GlusterBrick, resp.GlusterMount, resp.GlusterWorkerNodes); err != nil {
				return fmt.Errorf("gluster orchestration failed: %w", err)
			}

			// Signal controller that GlusterFS is ready.
			if err := signalGlusterReady(ctx, opts.MasterAddr); err != nil {
				log.Warnw("failed to signal gluster ready to controller", "err", err)
				// Non-fatal; continue.
			}

			log.Infow("gluster orchestration completed and signaled to controller")
		} else {
			// Non-orchestrator worker: ensure brick, wait for ready, then mount.
			log.Infow("this worker is not the orchestrator; ensuring brick and waiting for volume readiness")
			if err := gluster.Ensure(ctx, "", "", resp.GlusterBrick); err != nil {
				return fmt.Errorf("gluster brick ensure failed: %w", err)
			}

			// Wait for volume to be ready (poll controller or wait for GlusterReady).
			if err := waitForGlusterReady(ctx, opts, log); err != nil {
				return fmt.Errorf("gluster wait for ready failed: %w", err)
			}

			// Mount and add to fstab.
			if err := gluster.Ensure(ctx, resp.GlusterVolume, resp.GlusterMount, ""); err != nil {
				return fmt.Errorf("gluster mount failed: %w", err)
			}
			if err := gluster.AddToFstab(resp.GlusterVolume, resp.GlusterMount); err != nil {
				return fmt.Errorf("gluster fstab add failed: %w", err)
			}

			log.Infow("gluster converged on worker", "volume", resp.GlusterVolume, "mount", resp.GlusterMount)
		}
	} else if opts.Role == "manager" {
		// Managers mount only (no brick).
		log.Infow("this manager will mount gluster volume (no brick)")

		// GlusterReady should already be true if we got here (controller gates StatusReady).
		// Install client-only.
		if err := deps.EnsureGlusterClient(ctx); err != nil {
			return fmt.Errorf("gluster client install failed: %w", err)
		}

		// Mount and add to fstab.
		if err := gluster.Ensure(ctx, resp.GlusterVolume, resp.GlusterMount, ""); err != nil {
			return fmt.Errorf("gluster mount failed: %w", err)
		}
		if err := gluster.AddToFstab(resp.GlusterVolume, resp.GlusterMount); err != nil {
			return fmt.Errorf("gluster fstab add failed: %w", err)
		}

		log.Infow("gluster converged on manager", "volume", resp.GlusterVolume, "mount", resp.GlusterMount)
	}

	return nil
}

func waitForGlusterReady(ctx context.Context, opts JoinOptions, log *logging.Logger) error {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Re-register to check GlusterReady status.
		hostname, err := os.Hostname()
		if err != nil {
			return err
		}

		reg := controller.NodeRegistration{
			Hostname:       hostname,
			Role:           opts.Role,
			OS:             runtime.GOOS,
			GlusterCapable: opts.EnableGluster,
		}

		resp, err := registerOnce(ctx, opts.MasterAddr, reg)
		if err != nil {
			log.Warnw("gluster ready check registration failed", "err", err)
		} else if resp.GlusterReady {
			log.Infow("gluster volume is ready")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < 10*time.Second {
			backoff += time.Second
		}
	}
}

func signalGlusterReady(ctx context.Context, masterAddr string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}

	reg := controller.NodeRegistration{
		Hostname: hostname,
		Role:     "worker",
		OS:       runtime.GOOS,
		Action:   "gluster-ready",
	}

	_, err = registerOnce(ctx, masterAddr, reg)
	return err
}

