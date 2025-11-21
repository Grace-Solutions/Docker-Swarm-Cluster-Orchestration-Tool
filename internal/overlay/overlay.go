package overlay

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"clusterctl/internal/deps"
	"clusterctl/internal/logging"
)

// errString makes it easy to log an error value that may be nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Provider represents an overlay connectivity provider (Netbird, Tailscale,
// WireGuard, or "none"). Implementations must be idempotent: calling
// EnsureConnected or Teardown multiple times should be safe.
//
// The config string is provider-specific and is typically used for secrets or
// flags (for example, a Netbird setup key or a Tailscale auth key). It must
// not be interpreted as a path; callers are free to manage files themselves
// if they wish.
type Provider interface {
	EnsureConnected(ctx context.Context, config string) error
	Teardown(ctx context.Context, config string) error
}

// NetbirdHostname returns the FQDN assigned to this node by Netbird, if
// available, by parsing the output of `netbird status`.
func NetbirdHostname(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("netbird"); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "netbird", "status")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("overlay: netbird status failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FQDN:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				fqdn := strings.TrimSpace(parts[1])
				if fqdn != "" {
					return fqdn, nil
				}
			}
		}
	}

	return "", fmt.Errorf("overlay: netbird FQDN not found in status output")
}

// TailscaleHostname returns the DNSName assigned to this node by Tailscale, if
// available, by parsing the JSON output of `tailscale status --json`.
func TailscaleHostname(ctx context.Context) (string, error) {
	if _, err := exec.LookPath("tailscale"); err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "tailscale", "status", "--json")
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("overlay: tailscale status --json failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	// We avoid a full JSON dependency and instead do a minimal search for
	// '"Self"' then the first '"DNSName"' that follows.
	text := string(out)
	selfIdx := strings.Index(text, "\"Self\"")
	if selfIdx == -1 {
		return "", fmt.Errorf("overlay: tailscale Self section not found in status output")
	}

	sub := text[selfIdx:]
	key := "\"DNSName\""
	kidx := strings.Index(sub, key)
	if kidx == -1 {
		return "", fmt.Errorf("overlay: tailscale DNSName not found in Self section")
	}

	rest := sub[kidx+len(key):]
	// Expect something like: : "hostname.example.",
	colIdx := strings.Index(rest, ":")
	if colIdx == -1 {
		return "", fmt.Errorf("overlay: malformed DNSName entry in tailscale status output")
	}

	rest = rest[colIdx+1:]
	// Trim spaces and any leading quotes, then read until the next quote.
	rest = strings.TrimSpace(rest)
	if !strings.HasPrefix(rest, "\"") {
		return "", fmt.Errorf("overlay: unexpected tailscale DNSName format")
	}

	rest = rest[1:]
	endIdx := strings.Index(rest, "\"")
	if endIdx == -1 {
		return "", fmt.Errorf("overlay: unterminated tailscale DNSName value")
	}

	dnsName := strings.TrimSpace(rest[:endIdx])
	if dnsName == "" {
		return "", fmt.Errorf("overlay: empty tailscale DNSName value")
	}

	return dnsName, nil
}

// EnsureConnected selects the appropriate provider by name and ensures overlay
// connectivity based on the supplied configuration string.
func EnsureConnected(ctx context.Context, name, config string) error {
	prov, err := providerFor(name)
	if err != nil {
		return err
	}

	log := logging.L().With(
		"component", "overlay",
		"provider", name,
		"config_provided", config != "",
	)
	log.Infow("ensuring overlay connectivity")
	return prov.EnsureConnected(ctx, config)
}

// Teardown selects the appropriate provider by name and tears down overlay
// connectivity, if any.
func Teardown(ctx context.Context, name, config string) error {
	prov, err := providerFor(name)
	if err != nil {
		return err
	}

	log := logging.L().With(
		"component", "overlay",
		"provider", name,
		"config_provided", config != "",
	)
	log.Infow("tearing down overlay connectivity")
	return prov.Teardown(ctx, config)
}

func providerFor(name string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "none":
		return &noneProvider{}, nil
	case "netbird":
		return &netbirdProvider{}, nil
	case "tailscale":
		return &tailscaleProvider{}, nil
	case "wireguard":
		return &wireguardProvider{}, nil
	default:
		return nil, fmt.Errorf("overlay: unknown provider %q", name)
	}
}

type noneProvider struct{}

func (p *noneProvider) EnsureConnected(ctx context.Context, config string) error {
	_ = ctx
	_ = config
	// No overlay requested; nothing to do.
	return nil
}

func (p *noneProvider) Teardown(ctx context.Context, config string) error {
	_ = ctx
	_ = config
	// No overlay requested; nothing to do.
	return nil
}

type netbirdProvider struct{}

func (p *netbirdProvider) EnsureConnected(ctx context.Context, config string) error {
	if err := deps.EnsureNetbird(ctx); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "netbird", "up")
	env := os.Environ()
	if config != "" {
		// Netbird supports NB_SETUP_KEY for initial onboarding.
		env = append(env, "NB_SETUP_KEY="+config)
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: netbird up failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	fqdn, herr := NetbirdHostname(ctx)
	logging.L().Infow("netbird overlay ensured", "config_provided", config != "", "fqdn", fqdn, "hostname_lookup_error", errString(herr))
	return nil
}

func (p *netbirdProvider) Teardown(ctx context.Context, config string) error {
	// If netbird is not installed, there is nothing to tear down.
	if _, err := exec.LookPath("netbird"); err != nil {
		logging.L().Infow("netbird CLI not found during teardown; skipping", "err", err)
		return nil
	}

	cmd := exec.CommandContext(ctx, "netbird", "down")
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: netbird down failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("netbird overlay torn down")
	return nil
}

type tailscaleProvider struct{}

func (p *tailscaleProvider) EnsureConnected(ctx context.Context, config string) error {
	if err := deps.EnsureTailscale(ctx); err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "tailscale", "up")
	env := os.Environ()
	if config != "" {
		// Tailscale supports TS_AUTHKEY for non-interactive authentication.
		env = append(env, "TS_AUTHKEY="+config)
	}
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: tailscale up failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	dnsName, herr := TailscaleHostname(ctx)
	logging.L().Infow("tailscale overlay ensured", "config_provided", config != "", "dns_name", dnsName, "hostname_lookup_error", errString(herr))
	return nil
}

func (p *tailscaleProvider) Teardown(ctx context.Context, config string) error {
	// If tailscale is not installed, there is nothing to tear down.
	if _, err := exec.LookPath("tailscale"); err != nil {
		logging.L().Infow("tailscale CLI not found during teardown; skipping", "err", err)
		return nil
	}

	cmd := exec.CommandContext(ctx, "tailscale", "down")
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: tailscale down failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("tailscale overlay torn down")
	return nil
}

type wireguardProvider struct{}

func (p *wireguardProvider) EnsureConnected(ctx context.Context, config string) error {
	if err := deps.EnsureWireGuard(ctx); err != nil {
		return err
	}

	iface, arg := wireguardInterfaceAndArg(config)

	// If the interface is already up, wg show <iface> should succeed.
	checkCmd := exec.CommandContext(ctx, "wg", "show", iface)
	if err := checkCmd.Run(); err == nil {
		logging.L().Infow("wireguard interface already up", "interface", iface)
		return nil
	}

	cmd := exec.CommandContext(ctx, "wg-quick", "up", arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: wg-quick up failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("wireguard overlay ensured", "interface", iface, "config", arg)
	return nil
}

func (p *wireguardProvider) Teardown(ctx context.Context, config string) error {
	if _, err := exec.LookPath("wg"); err != nil {
		logging.L().Infow("wireguard CLI not found during teardown; skipping", "err", err)
		return nil
	}
	if _, err := exec.LookPath("wg-quick"); err != nil {
		logging.L().Infow("wg-quick CLI not found during teardown; skipping", "err", err)
		return nil
	}

	iface, arg := wireguardInterfaceAndArg(config)

	// If the interface is not up, treating this as a no-op keeps teardown idempotent.
	checkCmd := exec.CommandContext(ctx, "wg", "show", iface)
	if err := checkCmd.Run(); err != nil {
		return nil
	}

	cmd := exec.CommandContext(ctx, "wg-quick", "down", arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("overlay: wg-quick down failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	logging.L().Infow("wireguard overlay torn down", "interface", iface, "config", arg)
	return nil
}

func wireguardInterfaceAndArg(config string) (iface, arg string) {
	if config == "" {
		// Default wg-quick interface.
		return "wg0", "wg0"
	}

	// If the string looks like a path (contains a path separator or ends in .conf),
	// treat it as a wg-quick config file; otherwise treat it as an interface name.
	if strings.Contains(config, "/") || strings.Contains(config, "\\") || strings.HasSuffix(config, ".conf") {
		base := filepath.Base(config)
		iface = strings.TrimSuffix(base, filepath.Ext(base))
		if iface == "" {
			iface = "wg0"
		}
		return iface, config
	}

	return config, config
}
