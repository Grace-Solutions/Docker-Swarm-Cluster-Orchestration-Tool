package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"clusterctl/internal/logging"
	"clusterctl/internal/swarm"
)

// Serve starts the controller TCP server and blocks until the context is
// cancelled or a fatal error occurs.
func Serve(ctx context.Context, opts ServeOptions) error {
	if opts.StateDir == "" {
		return errors.New("controller: state dir must be set")
	}
	if opts.ListenAddr == "" {
		return errors.New("controller: listen address must be set")
	}

	store, err := newFileStore(opts.StateDir)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", opts.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log := logging.L().With(
		"component", "controller",
		"listen", opts.ListenAddr,
		"stateDir", opts.StateDir,
	)
	log.Infow(fmt.Sprintf("controller listening on %s (stateDir=%s)", opts.ListenAddr, opts.StateDir))

	var wg sync.WaitGroup

	// Stop accepting new connections when the context is cancelled.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				log.Warnw("temporary accept error", "err", err)
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return err
		}

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			if err := handleConn(ctx, c, store, opts); err != nil {
				log.Warnw(fmt.Sprintf("connection handler error from %s: %v", c.RemoteAddr().String(), err))
			}
		}(conn)
	}

	wg.Wait()
	log.Infow("controller stopped")
	return nil
}

func handleConn(ctx context.Context, conn net.Conn, store *fileStore, opts ServeOptions) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Wrap the connection in a buffered reader so we can safely peek at the first
	// byte. This lets us detect non-JSON/TLS-like connections (for example,
	// health checks or processes speaking TLS to this plain-text port) and avoid
	// noisy JSON parse errors.
	br := bufio.NewReader(conn)
	b, err := br.Peek(1)
	if err != nil {
		return err
	}

	// 0x16 is the first byte of a TLS ClientHello in all common TLS versions.
	// If we see this, it is almost certainly a TLS client speaking to our
	// plain-text JSON protocol. Log once per connection and ignore it.
	if len(b) == 1 && b[0] == 0x16 {
		logging.L().Infow(fmt.Sprintf("ignoring non-JSON/TLS-like connection from %s", conn.RemoteAddr().String()))
		return nil
	}

	dec := json.NewDecoder(br)
	var reg NodeRegistration
	if err := dec.Decode(&reg); err != nil {
		return err
	}

	reg.Timestamp = time.Now().UTC()
	action := reg.Action
	if action == "" {
		action = "register"
	}

	var (
		state clusterState
		aerr  error
	)

	switch action {
	case "register":
		state, aerr = store.addRegistration(reg)
	case "deregister":
		state, aerr = store.removeRegistration(reg.Hostname, reg.Role)
	case "gluster-ready":
		// Orchestrator signals that GlusterFS volume is ready.
		// Do NOT call addRegistration here, as the reg may have incomplete fields
		// (e.g., missing IP) and would overwrite the existing worker registration.
		state, aerr = store.setGlusterReady(true)
		if aerr == nil {
			logging.L().Infow("gluster volume marked ready by orchestrator", "hostname", reg.Hostname)
		}
	case "check-status":
		// Node is polling for status (e.g., GlusterReady) without updating its registration.
		// Just return the current state without modifying it.
		state = store.getState()
	default:
		return errors.New("controller: unknown action")
	}
	if aerr != nil {
		return aerr
	}

	managers, workers := countRoles(state.Nodes)

	// Ensure SwarmManagerAddr includes port :2377.
	// If AdvertiseAddr is not set, we cannot provide a Swarm manager address,
	// so leave it empty and let the client handle the fallback.
	swarmManagerAddr := opts.AdvertiseAddr
	if swarmManagerAddr != "" {
		if !strings.Contains(swarmManagerAddr, ":") {
			swarmManagerAddr = swarmManagerAddr + ":2377"
		}
	}

	resp := NodeResponse{
		SwarmManagerAddr: swarmManagerAddr,
		SwarmRole:        reg.Role,
	}

	if action == "deregister" {
		resp.Status = StatusReady
	} else if !opts.WaitForMinimum {
		resp.Status = StatusReady
	} else {
		// MinManagers and MinWorkers include the primary master in the count.
		// The primary master is always a manager but is not in state.Nodes.
		// So we add +1 to the manager count to include the primary master.
		totalManagers := managers + 1 // +1 for primary master
		if totalManagers >= opts.MinManagers && workers >= opts.MinWorkers {
			resp.Status = StatusReady
		} else {
			resp.Status = StatusWaiting
		}
	}

	if action == "register" && resp.Status == StatusReady && (reg.Role == "manager" || reg.Role == "worker") {
		if token, err := swarm.JoinToken(ctx, reg.Role); err != nil {
			logging.L().Infow(fmt.Sprintf("failed to fetch swarm join token for role=%s: %v", reg.Role, err))
		} else {
			resp.SwarmJoinToken = token
			logging.L().Infow(fmt.Sprintf("issued swarm join token for hostname=%s role=%s token=%s", reg.Hostname, reg.Role, token))
		}
	}

	glusterForNode := false
	if reg.GlusterCapable && state.GlusterEnabled {
		// Always populate GlusterFS fields for capable nodes (both register and check-status).
		resp.GlusterEnabled = true
		resp.GlusterVolume = state.GlusterVolume
		resp.GlusterMount = state.GlusterMount
		resp.GlusterReady = state.GlusterReady

		if reg.Role == "worker" {
			// Workers host bricks.
			resp.GlusterBrick = state.GlusterBrick

			// Only assign orchestrator on initial registration, not on status checks.
			if action == "register" {
				// Assign orchestrator if not yet assigned.
				if state.GlusterOrchestratorHostname == "" {
					if _, err := store.setGlusterOrchestrator(reg.Hostname); err != nil {
						logging.L().Warnw("failed to assign gluster orchestrator", "hostname", reg.Hostname, "err", err)
					} else {
						state.GlusterOrchestratorHostname = reg.Hostname
						logging.L().Infow("assigned gluster orchestrator", "hostname", reg.Hostname)
					}
				}
			}

			// If this worker is the orchestrator, send the list of all gluster workers.
			if state.GlusterOrchestratorHostname == reg.Hostname {
				resp.GlusterOrchestrator = true
				glusterWorkers := store.getGlusterWorkers()

				// Build detailed log of workers
				var workerDetails []string
				for _, w := range glusterWorkers {
					if w.IP != "" {
						resp.GlusterWorkerNodes = append(resp.GlusterWorkerNodes, w.IP)
						workerDetails = append(workerDetails, fmt.Sprintf("hostname=%s ip=%s", w.Hostname, w.IP))
					} else {
						logging.L().Warnw(fmt.Sprintf("skipping worker with empty IP: hostname=%s role=%s", w.Hostname, w.Role))
					}
				}

				if action == "register" {
					logging.L().Infow(fmt.Sprintf("orchestrator assigned worker list: count=%d details=[%s]",
						len(resp.GlusterWorkerNodes),
						strings.Join(workerDetails, ", ")))
				}
			}

			glusterForNode = true
		} else if reg.Role == "manager" {
			// Managers mount only; they must wait for GlusterReady.
			if !state.GlusterReady {
				resp.Status = StatusWaiting
				if action == "register" {
					logging.L().Infow("manager waiting for gluster readiness", "hostname", reg.Hostname)
				}
			}
			glusterForNode = true
		}
	}

	// Handle Portainer deployment assignment (worker nodes only).
	if reg.DeployPortainer && reg.Role == "worker" {
		// Only assign deployer on initial registration, not on status checks.
		if action == "register" {
			// Assign Portainer deployer if not yet assigned.
			if state.PortainerDeployerHostname == "" {
				if _, err := store.setPortainerDeployer(reg.Hostname); err != nil {
					logging.L().Warnw("failed to assign portainer deployer", "hostname", reg.Hostname, "err", err)
				} else {
					state.PortainerDeployerHostname = reg.Hostname
					logging.L().Infow("assigned portainer deployer", "hostname", reg.Hostname)
				}
			}
		}

		// Always tell the assigned deployer to deploy (both register and check-status).
		if state.PortainerDeployerHostname == reg.Hostname {
			resp.DeployPortainer = true
			if action == "register" {
				logging.L().Infow("worker assigned to deploy Portainer", "hostname", reg.Hostname)
			}
		} else if action == "register" {
			logging.L().Infow("worker requested Portainer deployment but another worker already claimed it", "hostname", reg.Hostname, "deployer", state.PortainerDeployerHostname)
		}
	}

	// Calculate total counts including the primary master for logging.
	totalManagers := managers + 1 // +1 for primary master

	// For logging: if this is a check-status action, the incoming reg has minimal fields.
	// Look up the stored registration to get the actual IP address.
	sentAddress := reg.IP
	resolvedIP := reg.IP
	if action == "check-status" {
		// Find the stored registration for this node.
		for _, n := range state.Nodes {
			if n.Hostname == reg.Hostname && n.Role == reg.Role {
				sentAddress = n.IP
				resolvedIP = n.IP
				break
			}
		}
	}

	// Resolve the address to an IP for logging purposes.
	if sentAddress != "" {
		if ips, err := net.LookupIP(sentAddress); err == nil && len(ips) > 0 {
			resolvedIP = ips[0].String()
		}
	}

	logging.L().Infow(fmt.Sprintf(
		"handled node registration: hostname=%s sentAddress=%s resolvedIP=%s role=%s action=%s status=%s managers=%d workers=%d glusterClusterEnabled=%t glusterForNode=%t glusterVolume=%s glusterMount=%s glusterBrick=%s glusterOrchestrator=%t glusterReady=%t deployPortainer=%t portainerDeployer=%s",
		reg.Hostname,
		sentAddress,
		resolvedIP,
		reg.Role,
		action,
		resp.Status,
		totalManagers,
		workers,
		state.GlusterEnabled,
		glusterForNode,
		resp.GlusterVolume,
		resp.GlusterMount,
		resp.GlusterBrick,
		resp.GlusterOrchestrator,
		resp.GlusterReady,
		resp.DeployPortainer,
		state.PortainerDeployerHostname,
	))

	enc := json.NewEncoder(conn)
	return enc.Encode(&resp)
}

func countRoles(nodes []NodeRegistration) (managers, workers int) {
	for _, n := range nodes {
		switch n.Role {
		case "manager":
			managers++
		case "worker":
			workers++
		}
	}
	return managers, workers
}

