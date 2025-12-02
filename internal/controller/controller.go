package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"clusterctl/internal/logging"
	"clusterctl/internal/ssh"
)

type ServeOptions struct {
	ListenAddr     string
	StateDir       string
	AdvertiseAddr  string
	MinManagers    int
	MinWorkers     int
	WaitForMinimum bool
	SSHUser        string // SSH username for remote orchestration (default: "root")
	KeepSSHKeys    bool   // Keep SSH keys after successful setup (default: false, opt-out)
}

type MasterInitOptions struct {
	StateDir       string
	EnableStorage  bool
	StorageType    string // "microceph"
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
	GlusterCapable  bool      `json:"glusterCapable"`  // Deprecated: use StorageEnabled
	StorageEnabled  bool      `json:"storageEnabled"`  // Node participates in distributed storage
	DeployPortainer bool      `json:"deployPortainer,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	// Action controls how the controller treats this registration. If empty or
	// "register", the node is upserted into state. If "deregister", the node
	// is removed from state. If "storage-ready", the orchestrator signals that
	// the storage cluster is ready for use.
	Action string `json:"action,omitempty"`
}

type NodeResponseStatus string

const (
	StatusReady   NodeResponseStatus = "ready"
	StatusWaiting NodeResponseStatus = "waiting"
)

type NodeResponse struct {
	Status           NodeResponseStatus `json:"status"`
	SwarmRole        string             `json:"swarmRole"`
	SwarmJoinToken   string             `json:"swarmJoinToken"`
	SwarmManagerAddr string             `json:"swarmManagerAddr"`
	OverlayType      string             `json:"overlayType"`
	OverlayPayload   string             `json:"overlayPayload"`
	StorageEnabled   bool               `json:"storageEnabled"`
	StorageType      string             `json:"storageType"`                   // "microceph"
	StorageReady     bool               `json:"storageReady"`
	StorageNodes     []string           `json:"storageNodes,omitempty"`
	DeployPortainer  bool               `json:"deployPortainer"`
	SSHPublicKey     string             `json:"sshPublicKey,omitempty"`        // SSH public key for remote orchestration
}

// MasterInit prepares a host as the initial Swarm manager and optional distributed storage.
//
// It ensures the controller state directory exists and, when requested, records
// cluster-wide storage configuration that will be sent to storage-enabled
// nodes as they join.
//
// MasterInit clears any existing node registrations to ensure a clean start.
// It also generates an SSH keypair for remote orchestration.
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

	// Generate SSH keypair for remote orchestration
	logging.L().Infow("generating SSH keypair for remote orchestration")
	keypair, err := ssh.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate SSH keypair: %w", err)
	}

	// Save SSH keys to state directory
	privateKeyPath := filepath.Join(opts.StateDir, "ssh_key")
	publicKeyPath := filepath.Join(opts.StateDir, "ssh_key.pub")

	if err := os.WriteFile(privateKeyPath, keypair.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write SSH private key: %w", err)
	}

	if err := os.WriteFile(publicKeyPath, keypair.PublicKey, 0644); err != nil {
		return fmt.Errorf("failed to write SSH public key: %w", err)
	}

	logging.L().Infow(fmt.Sprintf("SSH keypair generated: %s, %s", privateKeyPath, publicKeyPath))

	if opts.EnableStorage {
		storageType := opts.StorageType
		if storageType == "" {
			storageType = "microceph"
		}
		if _, err := store.setStorageConfig(true, storageType); err != nil {
			return err
		}

		logging.L().Infow(fmt.Sprintf(
			"master init complete with distributed storage enabled: stateDir=%s storageType=%s",
			opts.StateDir, storageType,
		))
		return nil
	}

	logging.L().Infow(fmt.Sprintf("master init complete: stateDir=%s storageEnabled=%t", opts.StateDir, false))
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
