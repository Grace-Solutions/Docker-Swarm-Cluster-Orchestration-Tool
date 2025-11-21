package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"clusterctl/internal/logging"
)

type ServeOptions struct {
	ListenAddr     string
	StateDir       string
	AdvertiseAddr  string
	MinManagers    int
	MinWorkers     int
	WaitForMinimum bool
}

type MasterInitOptions struct {
	StateDir      string
	EnableGluster bool
}

type MasterResetOptions struct {
	StateDir        string
	CleanupStateDir bool
}

type NodeRegistration struct {
	Hostname        string    `json:"hostname"`
	Role            string    `json:"role"`
	IP              string    `json:"ip"`
	OS              string    `json:"os"`
	CPU             int       `json:"cpu"`
	MemoryMB        int       `json:"memoryMb"`
	DockerVersion   string    `json:"dockerVersion"`
	GlusterCapable  bool      `json:"glusterCapable"`
	DeployPortainer bool      `json:"deployPortainer,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	// Action controls how the controller treats this registration. If empty or
	// "register", the node is upserted into state. If "deregister", the node
	// is removed from state. If "gluster-ready", the orchestrator signals that
	// the GlusterFS volume is ready for mounting.
	Action string `json:"action,omitempty"`
}

type NodeResponseStatus string

const (
	StatusReady   NodeResponseStatus = "ready"
	StatusWaiting NodeResponseStatus = "waiting"
)

type NodeResponse struct {
	Status              NodeResponseStatus `json:"status"`
	SwarmRole           string             `json:"swarmRole"`
	SwarmJoinToken      string             `json:"swarmJoinToken"`
	SwarmManagerAddr    string             `json:"swarmManagerAddr"`
	OverlayType         string             `json:"overlayType"`
	OverlayPayload      string             `json:"overlayPayload"`
	GlusterEnabled      bool               `json:"glusterEnabled"`
	GlusterVolume       string             `json:"glusterVolume"`
	GlusterMount        string             `json:"glusterMount"`
	GlusterBrick        string             `json:"glusterBrick"`
	GlusterOrchestrator bool               `json:"glusterOrchestrator"`
	GlusterWorkerNodes  []string           `json:"glusterWorkerNodes,omitempty"`
	GlusterReady        bool               `json:"glusterReady"`
	DeployPortainer     bool               `json:"deployPortainer"`
}

// MasterInit prepares a host as the initial Swarm manager and optional GlusterFS brick.
//
// It ensures the controller state directory exists and, when requested, records
// cluster-wide GlusterFS configuration that will be sent to Gluster-capable
// nodes as they join.
//
// MasterInit clears any existing node registrations to ensure a clean start.
func MasterInit(ctx context.Context, opts MasterInitOptions) error {
	_ = ctx // reserved for potential future orchestration work

	if opts.StateDir == "" {
		return errors.New("controller: state dir must be set")
	}

	store, err := newFileStore(opts.StateDir)
	if err != nil {
		return err
	}

	// Clear any existing node registrations to start fresh.
	if _, err := store.reset(); err != nil {
		return err
	}

	if opts.EnableGluster {
		volume, mount, brick := deriveGlusterDefaults(opts.StateDir)
		if _, err := store.setGlusterConfig(true, volume, mount, brick); err != nil {
			return err
		}

		logging.L().Infow(fmt.Sprintf(
			"master init complete with GlusterFS enabled: stateDir=%s volume=%s mount=%s brick=%s",
			opts.StateDir, volume, mount, brick,
		))
		return nil
	}

	logging.L().Infow(fmt.Sprintf("master init complete: stateDir=%s glusterEnabled=%t", opts.StateDir, false))
	return nil
}

// MasterReset clears the controller's persisted state. It is safe to run
// multiple times; after reset the controller behaves as if no nodes have
// registered yet. When CleanupStateDir is true, the entire state directory
// (including the on-disk state file) is removed so a fresh cluster can be
// bootstrapped.
func MasterReset(ctx context.Context, opts MasterResetOptions) error {
	_ = ctx // reserved for potential future orchestration work

	if opts.StateDir == "" {
		return errors.New("controller: state dir must be set")
	}

	if opts.CleanupStateDir {
		if err := os.RemoveAll(opts.StateDir); err != nil && !os.IsNotExist(err) {
			return err
		}
		logging.L().Infow(fmt.Sprintf("master reset complete; state dir removed: %s", opts.StateDir))
		return nil
	}

	store, err := newFileStore(opts.StateDir)
	if err != nil {
		return err
	}

	if _, err := store.reset(); err != nil {
		return err
	}

	logging.L().Infow("master reset complete", "stateDir", opts.StateDir)
	return nil
}

func deriveGlusterDefaults(stateDir string) (volume, mount, brick string) {
	mount = stateDir

	parent := filepath.Dir(stateDir)
	brick = filepath.Join(parent, "brick")

	volume = filepath.Base(parent)
	if volume == "" || volume == "." || volume == string(filepath.Separator) {
		volume = "gv0"
	}

	return volume, mount, brick
}
