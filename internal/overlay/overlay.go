package overlay

import (
	"context"
	"fmt"
	"strings"

	"clusterctl/internal/logging"
)

// Provider represents an overlay connectivity provider (Netbird, Tailscale,
// WireGuard, or "none"). Implementations must be idempotent: calling
// EnsureConnected or Teardown multiple times should be safe.
type Provider interface {
	EnsureConnected(ctx context.Context, configPath string) error
	Teardown(ctx context.Context, configPath string) error
}

// EnsureConnected selects the appropriate provider by name and ensures overlay
// connectivity based on the supplied configuration path.
func EnsureConnected(ctx context.Context, name, configPath string) error {
	prov, err := providerFor(name)
	if err != nil {
		return err
	}

	log := logging.L().With(
		"component", "overlay",
		"provider", name,
		"config", configPath,
	)
	log.Infow("ensuring overlay connectivity")
	return prov.EnsureConnected(ctx, configPath)
}

// Teardown selects the appropriate provider by name and tears down overlay
// connectivity, if any.
func Teardown(ctx context.Context, name, configPath string) error {
	prov, err := providerFor(name)
	if err != nil {
		return err
	}

	log := logging.L().With(
		"component", "overlay",
		"provider", name,
		"config", configPath,
	)
	log.Infow("tearing down overlay connectivity")
	return prov.Teardown(ctx, configPath)
}

func providerFor(name string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "none":
		return &noneProvider{}, nil
	case "netbird", "tailscale", "wireguard":
		// These providers will be implemented in later iterations based on the
		// concrete CLI/API usage in the environment. For now we return an
		// explicit error rather than guessing behaviour.
		return nil, fmt.Errorf("overlay: provider %q is not yet implemented", name)
	default:
		return nil, fmt.Errorf("overlay: unknown provider %q", name)
	}
}

type noneProvider struct{}

func (p *noneProvider) EnsureConnected(ctx context.Context, configPath string) error {
	_ = ctx
	_ = configPath
	// No overlay requested; nothing to do.
	return nil
}

func (p *noneProvider) Teardown(ctx context.Context, configPath string) error {
	_ = ctx
	_ = configPath
	// No overlay requested; nothing to do.
	return nil
}

