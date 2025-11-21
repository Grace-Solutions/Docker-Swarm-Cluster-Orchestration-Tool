package controller

import (
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

	dec := json.NewDecoder(conn)
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
		state, aerr = store.setGlusterReady(true)
		if aerr == nil {
			logging.L().Infow("gluster volume marked ready by orchestrator", "hostname", reg.Hostname)
		}
	default:
		return errors.New("controller: unknown action")
	}
	if aerr != nil {
		return aerr
	}

	managers, workers := countRoles(state.Nodes)

	// Ensure SwarmManagerAddr includes port :2377
	swarmManagerAddr := opts.AdvertiseAddr
	if swarmManagerAddr != "" && !strings.Contains(swarmManagerAddr, ":") {
		swarmManagerAddr = swarmManagerAddr + ":2377"
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
		// MinManagers and MinWorkers count ADDITIONAL nodes beyond the primary master.
		// The primary master is always a manager but is not counted in state.Nodes.
		// So we need: (managers + 1) >= opts.MinManagers to account for the primary.
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
	if reg.GlusterCapable && state.GlusterEnabled && action == "register" {
		resp.GlusterEnabled = true
		resp.GlusterVolume = state.GlusterVolume
		resp.GlusterMount = state.GlusterMount
		resp.GlusterReady = state.GlusterReady

		if reg.Role == "worker" {
			// Workers host bricks.
			resp.GlusterBrick = state.GlusterBrick

			// Assign orchestrator if not yet assigned.
			if state.GlusterOrchestratorHostname == "" {
				if _, err := store.setGlusterOrchestrator(reg.Hostname); err != nil {
					logging.L().Warnw("failed to assign gluster orchestrator", "hostname", reg.Hostname, "err", err)
				} else {
					state.GlusterOrchestratorHostname = reg.Hostname
					logging.L().Infow("assigned gluster orchestrator", "hostname", reg.Hostname)
				}
			}

			// If this worker is the orchestrator, send the list of all gluster workers.
			if state.GlusterOrchestratorHostname == reg.Hostname {
				resp.GlusterOrchestrator = true
				glusterWorkers := store.getGlusterWorkers()
				for _, w := range glusterWorkers {
					resp.GlusterWorkerNodes = append(resp.GlusterWorkerNodes, w.IP)
				}
			}

			glusterForNode = true
		} else if reg.Role == "manager" {
			// Managers mount only; they must wait for GlusterReady.
			if !state.GlusterReady {
				resp.Status = StatusWaiting
				logging.L().Infow("manager waiting for gluster readiness", "hostname", reg.Hostname)
			}
			glusterForNode = true
		}
	}

	logging.L().Infow(fmt.Sprintf(
		"handled node registration: hostname=%s role=%s ip=%s action=%s status=%s managers=%d workers=%d glusterClusterEnabled=%t glusterForNode=%t glusterVolume=%s glusterMount=%s glusterBrick=%s glusterOrchestrator=%t glusterReady=%t",
		reg.Hostname,
		reg.Role,
		reg.IP,
		action,
		resp.Status,
		managers,
		workers,
		state.GlusterEnabled,
		glusterForNode,
		resp.GlusterVolume,
		resp.GlusterMount,
		resp.GlusterBrick,
		resp.GlusterOrchestrator,
		resp.GlusterReady,
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

