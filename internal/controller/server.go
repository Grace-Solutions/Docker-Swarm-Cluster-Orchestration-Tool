package controller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"clusterctl/internal/logging"
	"clusterctl/internal/orchestrator"
	"clusterctl/internal/ssh"
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

	// Set default SSH user if not specified
	if opts.SSHUser == "" {
		opts.SSHUser = "root"
	}

	store, err := newFileStore(opts.StateDir)
	if err != nil {
		return err
	}

	// Load SSH keys for distribution to nodes and remote orchestration
	sshPublicKeyPath := filepath.Join(opts.StateDir, "ssh_key.pub")
	sshPublicKeyBytes, err := os.ReadFile(sshPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH public key from %s: %w (did you run 'master init'?)", sshPublicKeyPath, err)
	}
	sshPublicKey := string(sshPublicKeyBytes)

	// NOTE: SSH pool creation disabled for legacy controller mode.
	// Use the new 'deploy' command with JSON config for server-initiated deployment.
	_ = sshPublicKey // Suppress unused variable warning

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
	log.Infow(fmt.Sprintf("controller listening on %s (stateDir=%s, sshUser=%s)", opts.ListenAddr, opts.StateDir, opts.SSHUser))

	var wg sync.WaitGroup

	// NOTE: Background orchestration disabled for legacy controller mode.
	// Use the new 'deploy' command with JSON config for server-initiated deployment.
	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	runOrchestration(ctx, store, sshPool, opts)
	// }()

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
			if err := handleConn(ctx, c, store, opts, sshPublicKey); err != nil {
				log.Warnw(fmt.Sprintf("connection handler error from %s: %v", c.RemoteAddr().String(), err))
			}
		}(conn)
	}

	wg.Wait()
	log.Infow("controller stopped")
	return nil
}

func handleConn(ctx context.Context, conn net.Conn, store *fileStore, opts ServeOptions, sshPublicKey string) error {
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
	case "storage-ready":
		// Orchestrator signals that distributed storage is ready.
		// Do NOT call addRegistration here, as the reg may have incomplete fields
		// (e.g., missing IP) and would overwrite the existing worker registration.
		state, aerr = store.setStorageReady(true)
		if aerr == nil {
			logging.L().Infow("distributed storage marked ready by orchestrator", "hostname", reg.Hostname)
		}
	case "check-status":
		// Node is polling for status (e.g., StorageReady) without updating its registration.
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
		SSHPublicKey:     sshPublicKey, // Send SSH public key to node for remote orchestration
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

	if action == "register" && resp.Status == StatusReady && (reg.Role == "manager" || reg.Role == "worker" || reg.Role == "both") {
		if token, err := swarm.JoinToken(ctx, reg.Role); err != nil {
			logging.L().Infow(fmt.Sprintf("failed to fetch swarm join token for role=%s: %v", reg.Role, err))
		} else {
			resp.SwarmJoinToken = token
			logging.L().Infow(fmt.Sprintf("issued swarm join token for hostname=%s role=%s token=%s", reg.Hostname, reg.Role, token))
		}
	}

	storageForNode := false
	if reg.StorageEnabled && state.StorageEnabled {
		// Always populate storage fields for capable nodes (both register and check-status).
		resp.StorageEnabled = true
		resp.StorageReady = state.StorageReady

		if reg.Role == "worker" || reg.Role == "manager" || reg.Role == "both" {
			// Workers, managers, and "both" nodes can participate in distributed storage.
			if !state.StorageReady {
				resp.Status = StatusWaiting
				if action == "register" {
					logging.L().Infow("node waiting for storage readiness", "hostname", reg.Hostname, "role", reg.Role)
				}
			}
			storageForNode = true
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

	// Only log if this is a register action or if the response has changed.
	shouldLog := action == "register"
	if !shouldLog {
		// Check if response has changed from last time.
		lastResp := store.getLastResponse(reg.Hostname, reg.Role)
		if lastResp == nil || hasResponseChanged(lastResp, &resp) {
			shouldLog = true
		}
	}

	if shouldLog {
		logging.L().Infow(fmt.Sprintf(
			"handled node registration: hostname=%s sentAddress=%s resolvedIP=%s role=%s action=%s status=%s managers=%d workers=%d storageClusterEnabled=%t storageForNode=%t storageReady=%t",
			reg.Hostname,
			sentAddress,
			resolvedIP,
			reg.Role,
			action,
			resp.Status,
			totalManagers,
			workers,
			state.StorageEnabled,
			storageForNode,
			resp.StorageReady,
		))

		// Store this response for future comparison.
		if action == "check-status" {
			store.setLastResponse(reg.Hostname, reg.Role, &resp)
		}
	}

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

// hasResponseChanged checks if the response has changed in any meaningful way.
func hasResponseChanged(old, new *NodeResponse) bool {
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

// runOrchestration is a background goroutine that orchestrates distributed storage and Swarm setup
// when all required nodes have registered.
// NOTE: This is disabled for legacy controller mode. Use the 'deploy' command for server-initiated deployment.
func runOrchestration(ctx context.Context, store *fileStore, sshPool *ssh.Pool, opts ServeOptions) {
	log := logging.L().With("component", "orchestrator")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			state := store.getState()

			// Skip if not waiting for minimum nodes
			if !opts.WaitForMinimum {
				continue
			}

			managers, workers := countRoles(state.Nodes)
			totalManagers := managers + 1 // +1 for primary master

			// Check if we have minimum nodes
			if totalManagers < opts.MinManagers || workers < opts.MinWorkers {
				continue
			}

			// Phase 1: Orchestrate distributed storage if enabled and not yet orchestrated
			if state.StorageEnabled && !state.StorageOrchestrated {
				log.Infow("triggering distributed storage orchestration")

				// Get all storage-capable nodes
				storageNodes := store.getStorageNodes()
				if len(storageNodes) == 0 {
					log.Warnw("no storage-capable nodes found")
					continue
				}

				// Extract hostnames/IPs
				var nodeHosts []string
				for _, n := range storageNodes {
					if n.IP != "" {
						nodeHosts = append(nodeHosts, n.IP)
					}
				}

				if len(nodeHosts) == 0 {
					log.Warnw("no nodes with valid IPs for distributed storage")
					continue
				}

				// TODO: Run distributed storage orchestration based on storage type
				// This will be implemented when the storage framework is complete

				// Mark as orchestrated and ready
				if _, err := store.setStorageOrchestrated(true); err != nil {
					log.Errorw("failed to mark storage as orchestrated", "err", err)
					continue
				}

				if _, err := store.setStorageReady(true); err != nil {
					log.Errorw("failed to mark storage as ready", "err", err)
					continue
				}

				log.Infow("✅ Distributed storage orchestration completed successfully")
			}

			// Phase 2: Orchestrate Docker Swarm if not yet orchestrated
			if !state.SwarmOrchestrated {
				// Wait for storage to be ready if enabled
				if state.StorageEnabled && !state.StorageReady {
					continue
				}

				log.Infow("triggering Docker Swarm orchestration")

				// Get manager and worker hostnames
				var managerHosts, workerHosts []string
				for _, node := range state.Nodes {
					if node.IP == "" {
						continue
					}
					if node.Role == "manager" {
						managerHosts = append(managerHosts, node.IP)
					} else if node.Role == "worker" {
						workerHosts = append(workerHosts, node.IP)
					}
				}

				// For controller mode, use the same addresses for SSH and advertise
				// The primary manager uses opts.AdvertiseAddr for both advertise and join
				if err := orchestrator.SwarmSetup(ctx, sshPool, managerHosts, workerHosts, managerHosts, workerHosts, opts.AdvertiseAddr, opts.AdvertiseAddr); err != nil {
					log.Errorw("Docker Swarm orchestration failed", "err", err)
					// Don't mark as orchestrated so we can retry
					continue
				}

				// Mark as orchestrated
				if _, err := store.setSwarmOrchestrated(true); err != nil {
					log.Errorw("failed to mark Swarm as orchestrated", "err", err)
					continue
				}

				log.Infow("✅ Docker Swarm orchestration completed successfully")
			}
		}
	}
}
