package controller

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"clusterctl/internal/logging"
)

// clusterState is the on-disk representation of controller state.
// It includes node registrations and cluster-wide configuration.
type clusterState struct {
	Nodes                     []NodeRegistration `json:"nodes"`
	StorageEnabled            bool               `json:"storageEnabled"`
	StorageType               string             `json:"storageType"`                           // "microceph"
	StorageOrchestrated       bool               `json:"storageOrchestrated"`                   // True if controller has orchestrated storage setup via SSH
	StorageReady              bool               `json:"storageReady"`                          // True if storage cluster is ready for use
	SwarmOrchestrated         bool               `json:"swarmOrchestrated"`                     // True if controller has orchestrated Swarm setup via SSH
	PortainerDeployerHostname string             `json:"portainerDeployerHostname,omitempty"`
}

// fileStore is a simple JSON-backed state store stored under the configured
// state directory. It is safe for concurrent use by multiple goroutines.
type fileStore struct {
	path          string
	mu            sync.Mutex
	state         clusterState
	lastResponses map[string]*NodeResponse // key: "hostname:role"
}

func newFileStore(stateDir string) (*fileStore, error) {
	if stateDir == "" {
		return nil, errors.New("controller: state dir must be set")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}

	s := &fileStore{
		path:          filepath.Join(stateDir, "state.json"),
		lastResponses: make(map[string]*NodeResponse),
	}
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *fileStore) loadLocked() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.state = clusterState{}
			return nil
		}
		return err
	}
	if len(data) == 0 {
		s.state = clusterState{}
		return nil
	}

	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}

	logging.L().Infow("loaded controller state", "path", s.path, "nodes", len(s.state.Nodes))
	return nil
}

// addRegistration upserts the given registration and persists the updated
// state to disk. It returns the updated state snapshot.
func (s *fileStore) addRegistration(reg NodeRegistration) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := false
	for i := range s.state.Nodes {
		n := &s.state.Nodes[i]
		if n.Hostname == reg.Hostname && n.Role == reg.Role {
			*n = reg
			updated = true
			break
		}
	}
	if !updated {
		s.state.Nodes = append(s.state.Nodes, reg)
	}

	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

func (s *fileStore) removeRegistration(hostname, role string) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	for i, n := range s.state.Nodes {
		if n.Hostname == hostname && n.Role == role {
			idx = i
			break
		}
	}
	if idx == -1 {
		// Nothing to remove; treat as converged.
		return s.state, nil
	}

	s.state.Nodes = append(s.state.Nodes[:idx], s.state.Nodes[idx+1:]...)

	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

func (s *fileStore) reset() (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = clusterState{}
	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

func (s *fileStore) setStorageConfig(enabled bool, storageType string) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.StorageEnabled = enabled
	s.state.StorageType = storageType

	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

func (s *fileStore) saveLocked() error {
	data, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}

	logging.L().Infow("persisted controller state", "path", s.path, "nodes", len(s.state.Nodes))
	return nil
}

// getState returns a snapshot of the current cluster state without modifying it.
func (s *fileStore) getState() clusterState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// getStorageNodes returns all registered nodes that have storage enabled.
func (s *fileStore) getStorageNodes() []NodeRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()

	var storageNodes []NodeRegistration
	for _, n := range s.state.Nodes {
		// Check StorageEnabled first, fall back to deprecated GlusterCapable for migration
		if n.StorageEnabled || n.GlusterCapable {
			storageNodes = append(storageNodes, n)
		}
	}
	return storageNodes
}

// setStorageReady marks distributed storage as ready and persists state.
func (s *fileStore) setStorageReady(ready bool) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.StorageReady = ready
	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

// setPortainerDeployer assigns the Portainer deployer hostname and persists state.
func (s *fileStore) setPortainerDeployer(hostname string) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.PortainerDeployerHostname = hostname
	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

// getLastResponse retrieves the last response sent to a node (for change detection).
// Returns nil if no previous response exists.
func (s *fileStore) getLastResponse(hostname, role string) *NodeResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hostname + ":" + role
	return s.lastResponses[key]
}

// setLastResponse stores the last response sent to a node (for change detection).
func (s *fileStore) setLastResponse(hostname, role string, resp *NodeResponse) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hostname + ":" + role
	// Make a copy to avoid mutation issues.
	respCopy := *resp
	s.lastResponses[key] = &respCopy
}

// setStorageOrchestrated marks distributed storage as orchestrated by the controller.
func (s *fileStore) setStorageOrchestrated(orchestrated bool) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.StorageOrchestrated = orchestrated
	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

// setSwarmOrchestrated marks Docker Swarm as orchestrated by the controller.
func (s *fileStore) setSwarmOrchestrated(orchestrated bool) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.SwarmOrchestrated = orchestrated
	if err := s.saveLocked(); err != nil {
		return clusterState{}, err
	}
	return s.state, nil
}

