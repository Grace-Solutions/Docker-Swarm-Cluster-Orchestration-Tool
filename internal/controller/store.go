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
// It includes node registrations and cluster-wide GlusterFS configuration.
type clusterState struct {
	Nodes          []NodeRegistration `json:"nodes"`
	GlusterEnabled bool               `json:"glusterEnabled"`
	GlusterVolume  string             `json:"glusterVolume"`
	GlusterMount   string             `json:"glusterMount"`
	GlusterBrick   string             `json:"glusterBrick"`
}

// fileStore is a simple JSON-backed state store stored under the configured
// state directory. It is safe for concurrent use by multiple goroutines.
type fileStore struct {
	path  string
	mu    sync.Mutex
	state clusterState
}

func newFileStore(stateDir string) (*fileStore, error) {
	if stateDir == "" {
		return nil, errors.New("controller: state dir must be set")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}

	s := &fileStore{path: filepath.Join(stateDir, "state.json")}
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

func (s *fileStore) setGlusterConfig(enabled bool, volume, mount, brick string) (clusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state.GlusterEnabled = enabled
	s.state.GlusterVolume = volume
	s.state.GlusterMount = mount
	s.state.GlusterBrick = brick

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

