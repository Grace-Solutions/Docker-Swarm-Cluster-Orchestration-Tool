package swarm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"clusterctl/internal/deps"
	"clusterctl/internal/logging"
)

// IsActive reports whether this node is already part of a Swarm cluster.
// It is implemented in terms of `docker info` and is safe to call repeatedly.
func IsActive(ctx context.Context) (bool, error) {
	if err := deps.EnsureDockerWithCompose(ctx); err != nil {
		return false, err
	}

	cmd := exec.CommandContext(ctx, "docker", "info", "--format", "{{.Swarm.LocalNodeState}}")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	state := strings.TrimSpace(string(out))
	return state == "active", nil
}

// Init initialises a new Swarm on this node if one is not already active.
// If the node is already part of a Swarm, Init is a no-op.
func Init(ctx context.Context, advertiseAddr string) error {
	active, err := IsActive(ctx)
	if err == nil && active {
		return nil
	}

	args := []string{"swarm", "init"}
	if advertiseAddr != "" {
		args = append(args, "--advertise-addr", advertiseAddr)
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swarm: init failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("swarm initialised", "advertiseAddr", advertiseAddr)
	return nil
}

// Join joins an existing Swarm using the provided token and manager address.
// If the node is already part of a Swarm, Join is a no-op.
func Join(ctx context.Context, token, managerAddr string) error {
	if token == "" || managerAddr == "" {
		return errors.New("swarm: token and manager address are required")
	}

	active, err := IsActive(ctx)
	if err == nil && active {
		// Already part of a Swarm; treat as converged.
		return nil
	}

	args := []string{"swarm", "join", "--token", token, managerAddr}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swarm: join failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("swarm joined", "managerAddr", managerAddr)
	return nil
}

// JoinToken returns the join token for the given role ("manager", "worker", or "both").
// "both" returns the manager token since those nodes join as managers.
// It must be called on a Swarm manager node.
func JoinToken(ctx context.Context, role string) (string, error) {
	// Normalize role: "both" nodes join as managers
	tokenRole := role
	if role == "both" {
		tokenRole = "manager"
	}

	if tokenRole != "manager" && tokenRole != "worker" {
		return "", fmt.Errorf("swarm: invalid role %q", role)
	}

	if err := deps.EnsureDockerWithCompose(ctx); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "docker", "swarm", "join-token", "-q", tokenRole)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", errors.New("swarm: empty join token")
	}
	return token, nil
}


// Info returns a summary of the local node's Swarm state based on `docker info`.
// It is safe to call repeatedly and is best-effort only; callers should tolerate
// errors.
type Info struct {
	LocalState string
	NodeID     string
	NodeAddr   string
	Manager    bool
	ClusterID  string
}

// Status queries Docker for the local Swarm state.
func Status(ctx context.Context) (*Info, error) {
	if err := deps.EnsureDockerWithCompose(ctx); err != nil {
		return nil, err
	}

	// Use a pipe-separated format for easy parsing.
	format := "{{.Swarm.LocalNodeState}}|{{.Swarm.NodeID}}|{{.Swarm.NodeAddr}}|{{.Swarm.ControlAvailable}}|{{.Swarm.Cluster.ID}}"
	cmd := exec.CommandContext(ctx, "docker", "info", "--format", format)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) != 5 {
		return nil, fmt.Errorf("swarm: unexpected docker info format: %q", strings.TrimSpace(string(out)))
	}

	info := &Info{
		LocalState: parts[0],
		NodeID:     parts[1],
		NodeAddr:   parts[2],
		Manager:    strings.EqualFold(parts[3], "true"),
		ClusterID:  parts[4],
	}
	return info, nil
}

// Leave leaves the current Swarm cluster. If the node is not part of a Swarm
// the operation is treated as a no-op.
func Leave(ctx context.Context, force bool) error {
	active, err := IsActive(ctx)
	if err == nil && !active {
		return nil
	}

	args := []string{"swarm", "leave"}
	if force {
		args = append(args, "--force")
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swarm: leave failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	logging.L().Infow("swarm left", "force", force)
	return nil
}

// NetworkSpec describes the desired shape of a Swarm overlay network.
type NetworkSpec struct {
	Name     string
	Subnet   string
	Gateway  string
	Internal bool // If true, network is internal-only (no external access)
}

const (
	DefaultInternalNetworkName = "DOCKER-SWARM-CLUSTER-INTERNAL-COMMUNICATION"
	DefaultExternalNetworkName = "DOCKER-SWARM-CLUSTER-EXTERNAL-INGRESS"
)

// EnsureOverlayNetwork ensures an attachable overlay network with the given
// IPAM configuration exists. If the network already exists it is left as-is.
func EnsureOverlayNetwork(ctx context.Context, spec NetworkSpec) error {
	if spec.Name == "" {
		return errors.New("swarm: network name is required")
	}

	if err := deps.EnsureDockerWithCompose(ctx); err != nil {
		return err
	}

	// Fast-path: if the network exists, leave it alone.
	inspectCmd := exec.CommandContext(ctx, "docker", "network", "inspect", spec.Name, "--format", "{{.Name}}")
	out, err := inspectCmd.Output()
	if err == nil && strings.TrimSpace(string(out)) == spec.Name {
		logging.L().Infow("swarm overlay network already present", "name", spec.Name)
		return nil
	}

	args := []string{"network", "create", "--driver", "overlay", "--attachable"}
	if spec.Internal {
		args = append(args, "--internal")
	}
	if spec.Subnet != "" {
		args = append(args, "--subnet", spec.Subnet)
	}
	if spec.Gateway != "" {
		args = append(args, "--gateway", spec.Gateway)
	}
	args = append(args, spec.Name)

	// Log the command before execution
	logging.L().Infow("creating Docker overlay network", "command", fmt.Sprintf("docker %s", strings.Join(args, " ")))

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swarm: network create %s failed: %w (output: %s)", spec.Name, err, strings.TrimSpace(string(out)))
	}

	internalStr := "external"
	if spec.Internal {
		internalStr = "internal-only"
	}
	logging.L().Infow("✅ swarm overlay network created", "name", spec.Name, "subnet", spec.Subnet, "gateway", spec.Gateway, "type", internalStr)
	return nil
}

// EnsureDefaultNetworks ensures the default internal and external overlay
// networks exist on the primary manager. It is safe to call multiple times.
func EnsureDefaultNetworks(ctx context.Context) error {
	internal := NetworkSpec{
		Name:     DefaultInternalNetworkName,
		Subnet:   "172.17.16.0/20",
		Gateway:  "172.17.16.1",
		Internal: true, // Internal-only network (no external access)
	}
	if err := EnsureOverlayNetwork(ctx, internal); err != nil {
		return err
	}

	external := NetworkSpec{
		Name:     DefaultExternalNetworkName,
		Subnet:   "172.17.32.0/20",
		Gateway:  "172.17.32.1",
		Internal: false, // External-facing network
	}
	if err := EnsureOverlayNetwork(ctx, external); err != nil {
		return err
	}

	return nil
}


