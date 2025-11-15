package swarm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"clusterctl/internal/logging"
)

// IsActive reports whether this node is already part of a Swarm cluster.
// It is implemented in terms of `docker info` and is safe to call repeatedly.
func IsActive(ctx context.Context) (bool, error) {
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

// JoinToken returns the join token for the given role ("manager" or
// "worker"). It must be called on a Swarm manager node.
func JoinToken(ctx context.Context, role string) (string, error) {
	if role != "manager" && role != "worker" {
		return "", fmt.Errorf("swarm: invalid role %q", role)
	}

	cmd := exec.CommandContext(ctx, "docker", "swarm", "join-token", "-q", role)
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

