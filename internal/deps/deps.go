package deps

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"clusterctl/internal/logging"
)

// EnsureDocker makes sure the Docker CLI is available. If it is missing, a best-effort
// installation is attempted using the official get.docker.com convenience script.
func EnsureDocker(ctx context.Context) error {
	if _, err := exec.LookPath("docker"); err == nil {
		return nil
	}

	logging.L().Infow("docker CLI not found; attempting installation via get.docker.com script")
	if err := runInstallScript(ctx, "docker", "curl -fsSL https://get.docker.com | sh"); err != nil {
		return err
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("deps: docker installation did not make 'docker' available on PATH: %w", err)
	}

	return nil
}

// EnsureDockerWithCompose ensures Docker is installed and that at least one of
// `docker-compose` or `docker compose` is available. When only the plugin form
// is available, a small shim for `docker-compose` is created on best-effort
// basis so existing tooling continues to work.
func EnsureDockerWithCompose(ctx context.Context) error {
	if err := EnsureDocker(ctx); err != nil {
		return err
	}

	if path, err := exec.LookPath("docker-compose"); err == nil {
		logging.L().Infow("docker-compose binary found", "path", path)
		return nil
	}

	// Fallback to Docker CLI plugin: `docker compose`.
	cmd := exec.CommandContext(ctx, "docker", "compose", "version")
	if err := cmd.Run(); err != nil {
		logging.L().Infow("docker compose plugin not available; attempting to (re)install docker for compose support")
		if err := runInstallScript(ctx, "docker", "curl -fsSL https://get.docker.com | sh"); err != nil {
			return fmt.Errorf("deps: docker compose not available and docker install script failed: %w", err)
		}
		cmd = exec.CommandContext(ctx, "docker", "compose", "version")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("deps: docker compose is still not available; please install Docker Compose")
		}
	}

	// At this point `docker compose` works. Create a `docker-compose` wrapper on
	// a best-effort basis so both forms are available.
	if _, err := exec.LookPath("docker-compose"); err != nil {
		const wrapperPath = "/usr/local/bin/docker-compose"
		wrapper := "#!/bin/sh\nexec docker compose \"$@\"\n"
		if writeErr := os.WriteFile(wrapperPath, []byte(wrapper), 0o755); writeErr != nil {
			logging.L().Warnw("failed to create docker-compose wrapper script", "path", wrapperPath, "err", writeErr)
		} else {
			logging.L().Infow("created docker-compose wrapper script", "path", wrapperPath)
		}
	}

	return nil
}

// EnsureNetbird ensures the Netbird CLI is installed. If missing, it is
// installed using the official convenience script.
func EnsureNetbird(ctx context.Context) error {
	if _, err := exec.LookPath("netbird"); err == nil {
		return nil
	}

	logging.L().Infow("netbird CLI not found; attempting installation via get.netbird.io script")
	if err := runInstallScript(ctx, "netbird", "curl -fsSL https://get.netbird.io | sh"); err != nil {
		return err
	}

	if _, err := exec.LookPath("netbird"); err != nil {
		return fmt.Errorf("deps: netbird installation did not make 'netbird' available on PATH: %w", err)
	}

	return nil
}

// EnsureTailscale ensures the Tailscale CLI is installed. If missing, it is
// installed using the official convenience script.
func EnsureTailscale(ctx context.Context) error {
	if _, err := exec.LookPath("tailscale"); err == nil {
		return nil
	}

	logging.L().Infow("tailscale CLI not found; attempting installation via tailscale.com/install.sh script")
	if err := runInstallScript(ctx, "tailscale", "curl -fsSL https://tailscale.com/install.sh | sh"); err != nil {
		return err
	}

	if _, err := exec.LookPath("tailscale"); err != nil {
		return fmt.Errorf("deps: tailscale installation did not make 'tailscale' available on PATH: %w", err)
	}

	return nil
}

// EnsureWireGuard ensures WireGuard tools (wg and wg-quick) are installed.
// A best-effort installation is attempted using the system's package manager
// when possible (apt, dnf, yum, zypper, pacman, apk). Systems without one of
// these package managers will receive a clear error message.
func EnsureWireGuard(ctx context.Context) error {
	if _, err := exec.LookPath("wg"); err == nil {
		if _, err := exec.LookPath("wg-quick"); err == nil {
			return nil
		}
	}

	var (
		script  string
		manager string
	)

	if _, err := exec.LookPath("apt-get"); err == nil {
		manager = "apt-get"
		script = "apt-get update && apt-get install -y wireguard wireguard-tools"
	} else if _, err := exec.LookPath("dnf"); err == nil {
		manager = "dnf"
		script = "dnf install -y wireguard-tools"
	} else if _, err := exec.LookPath("yum"); err == nil {
		manager = "yum"
		script = "yum install -y wireguard-tools"
	} else if _, err := exec.LookPath("zypper"); err == nil {
		manager = "zypper"
		script = "zypper --non-interactive install wireguard-tools"
	} else if _, err := exec.LookPath("pacman"); err == nil {
		manager = "pacman"
		script = "pacman -Sy --noconfirm wireguard-tools"
	} else if _, err := exec.LookPath("apk"); err == nil {
		manager = "apk"
		script = "apk add --no-cache wireguard-tools"
	} else {
		return fmt.Errorf("deps: wireguard tools not found and automatic installation is not implemented for this OS; install 'wireguard' and 'wireguard-tools' manually")
	}

	logging.L().Infow("wireguard tools not found; attempting installation via package manager", "manager", manager)
	if err := runInstallScript(ctx, "wireguard", script); err != nil {
		return err
	}

	if _, err := exec.LookPath("wg"); err != nil {
		return fmt.Errorf("deps: wireguard installation did not make 'wg' available on PATH: %w", err)
	}
	if _, err := exec.LookPath("wg-quick"); err != nil {
		return fmt.Errorf("deps: wireguard installation did not make 'wg-quick' available on PATH: %w", err)
	}

	return nil
}

// EnsureGluster ensures the GlusterFS server and client components are
// installed. This is for worker nodes that will host bricks.
// A best-effort installation is attempted using the system's package manager.
func EnsureGluster(ctx context.Context) error {
	if _, err := exec.LookPath("gluster"); err == nil {
		return nil
	}

	var (
		script  string
		manager string
	)

	if _, err := exec.LookPath("apt-get"); err == nil {
		manager = "apt-get"
		script = "apt-get update && apt-get install -y glusterfs-server glusterfs-client && systemctl enable --now glusterd || service glusterd start || true"
	} else if _, err := exec.LookPath("dnf"); err == nil {
		manager = "dnf"
		script = "dnf install -y glusterfs glusterfs-fuse"
	} else if _, err := exec.LookPath("yum"); err == nil {
		manager = "yum"
		script = "yum install -y glusterfs glusterfs-fuse"
	} else if _, err := exec.LookPath("zypper"); err == nil {
		manager = "zypper"
		script = "zypper --non-interactive install glusterfs glusterfs-fuse"
	} else if _, err := exec.LookPath("pacman"); err == nil {
		manager = "pacman"
		script = "pacman -Sy --noconfirm glusterfs"
	} else if _, err := exec.LookPath("apk"); err == nil {
		manager = "apk"
		script = "apk add --no-cache glusterfs"
	} else {
		return fmt.Errorf("deps: gluster CLI not found and automatic installation is not implemented for this OS; install the GlusterFS client manually")
	}

	logging.L().Infow("gluster CLI not found; attempting installation via package manager", "manager", manager)
	if err := runInstallScript(ctx, "gluster", script); err != nil {
		return err
	}

	if _, err := exec.LookPath("gluster"); err != nil {
		// On some systems the Gluster CLI lives in sbin directories that are not
		// always present in PATH for non-login shells. As a best-effort, search
		// a few common locations and, if found, append them to PATH so subsequent
		// commands can locate `gluster`.
		fallbackDirs := []string{"/usr/sbin", "/usr/local/sbin", "/sbin"}
		for _, dir := range fallbackDirs {
			candidate := dir + string(os.PathSeparator) + "gluster"
			if st, statErr := os.Stat(candidate); statErr == nil && !st.IsDir() {
				pathEnv := os.Getenv("PATH")
				if !strings.Contains(pathEnv, dir) {
					_ = os.Setenv("PATH", pathEnv+string(os.PathListSeparator)+dir)
				}
				// Re-check with the updated PATH.
				if _, lookErr := exec.LookPath("gluster"); lookErr == nil {
					logging.L().Infow(fmt.Sprintf("gluster CLI found at %s after PATH adjustment", candidate))
					return nil
				}
			}
		}
		return fmt.Errorf("deps: gluster installation did not make 'gluster' available on PATH: %w", err)
	}

	return nil
}

// EnsureGlusterClient ensures only the GlusterFS client components are installed.
// This is for manager nodes that will mount volumes but not host bricks.
// A best-effort installation is attempted using the system's package manager.
func EnsureGlusterClient(ctx context.Context) error {
	// Check if mount.glusterfs is available (the actual client binary).
	if _, err := exec.LookPath("mount.glusterfs"); err == nil {
		return nil
	}

	var (
		script  string
		manager string
	)

	if _, err := exec.LookPath("apt-get"); err == nil {
		manager = "apt-get"
		script = "apt-get update && apt-get install -y glusterfs-client"
	} else if _, err := exec.LookPath("dnf"); err == nil {
		manager = "dnf"
		script = "dnf install -y glusterfs-fuse"
	} else if _, err := exec.LookPath("yum"); err == nil {
		manager = "yum"
		script = "yum install -y glusterfs-fuse"
	} else if _, err := exec.LookPath("zypper"); err == nil {
		manager = "zypper"
		script = "zypper --non-interactive install glusterfs-fuse"
	} else if _, err := exec.LookPath("pacman"); err == nil {
		manager = "pacman"
		script = "pacman -Sy --noconfirm glusterfs"
	} else if _, err := exec.LookPath("apk"); err == nil {
		manager = "apk"
		script = "apk add --no-cache glusterfs"
	} else {
		return fmt.Errorf("deps: glusterfs client not found and automatic installation is not implemented for this OS; install the GlusterFS client manually")
	}

	logging.L().Infow("glusterfs client not found; attempting installation via package manager", "manager", manager)
	if err := runInstallScript(ctx, "glusterfs-client", script); err != nil {
		return err
	}

	if _, err := exec.LookPath("mount.glusterfs"); err != nil {
		return fmt.Errorf("deps: glusterfs client installation did not make 'mount.glusterfs' available on PATH: %w", err)
	}

	return nil
}

// runInstallScript executes the given shell snippet via `sh -c` and returns a
// wrapped error including a small portion of stdout/stderr on failure.
func runInstallScript(ctx context.Context, name, script string) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Env = os.Environ()

	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("deps: failed to install %s: %w (output: %s)", name, err, trimmed)
		}
		return fmt.Errorf("deps: failed to install %s: %w", name, err)
	}

	logging.L().Infow("dependency installation completed", "name", name)
	return nil
}

