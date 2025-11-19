package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	log.Infow("controller listening")

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
				log.Warnw("connection handler error", "remote", c.RemoteAddr().String(), "err", err)
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
	default:
		return errors.New("controller: unknown action")
	}
	if aerr != nil {
		return aerr
	}

	managers, workers := countRoles(state.Nodes)

	resp := NodeResponse{
		SwarmManagerAddr: opts.AdvertiseAddr,
		SwarmRole:        reg.Role,
	}

	if action == "deregister" {
		resp.Status = StatusReady
	} else if !opts.WaitForMinimum {
		resp.Status = StatusReady
	} else if managers >= opts.MinManagers && workers >= opts.MinWorkers {
		resp.Status = StatusReady
	} else {
		resp.Status = StatusWaiting
	}

	if action == "register" && resp.Status == StatusReady && (reg.Role == "manager" || reg.Role == "worker") {
		if token, err := swarm.JoinToken(ctx, reg.Role); err != nil {
			logging.L().Infow(fmt.Sprintf("failed to fetch swarm join token for role=%s: %v", reg.Role, err))
		} else {
			resp.SwarmJoinToken = token
			logging.L().Infow(fmt.Sprintf("issued swarm join token for role=%s", reg.Role))
		}
	}

	glusterForNode := false
	if reg.GlusterCapable && state.GlusterEnabled {
		resp.GlusterEnabled = true
		resp.GlusterVolume = state.GlusterVolume
		resp.GlusterMount = state.GlusterMount
		resp.GlusterBrick = state.GlusterBrick
		glusterForNode = true
	}

	logging.L().Infow(fmt.Sprintf(
		"handled node registration: hostname=%s role=%s ip=%s action=%s status=%s managers=%d workers=%d glusterClusterEnabled=%t glusterForNode=%t glusterVolume=%s glusterMount=%s glusterBrick=%s",
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

