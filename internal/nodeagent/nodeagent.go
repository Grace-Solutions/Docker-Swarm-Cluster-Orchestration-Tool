package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"clusterctl/internal/controller"
	"clusterctl/internal/ipdetect"
	"clusterctl/internal/logging"
)

type JoinOptions struct {
	MasterAddr       string
	Role             string
	IPOverride       string
	HostnameOverride string
	OverlayProvider  string
	OverlayConfig    string
	EnableGluster    bool
}

// Join implements the node-side behaviour for `clusterctl node join`.
//
// It is designed to be idempotent: repeated joins with the same parameters
// converge the node onto the same desired state.
func Join(ctx context.Context, opts JoinOptions) error {
	if err := validateJoinOptions(opts); err != nil {
		return err
	}

	ip, hostname, err := detectIdentity(opts)
	if err != nil {
		return err
	}

	reg := controller.NodeRegistration{
		Hostname:       hostname,
		Role:           opts.Role,
		IP:             ip,
		OS:             runtime.GOOS,
		CPU:            runtime.NumCPU(),
		MemoryMB:       memoryMB(),
		DockerVersion:  dockerVersion(ctx),
		GlusterCapable: opts.EnableGluster,
	}

	log := logging.L().With(
		"component", "nodeagent",
		"master", opts.MasterAddr,
		"role", opts.Role,
		"hostname", reg.Hostname,
		"ip", reg.IP,
	)
	log.Infow("starting node join")

	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		resp, err := registerOnce(ctx, opts.MasterAddr, reg)
		if err != nil {
			log.Warnw("registration attempt failed", "err", err)
		} else if resp.Status == controller.StatusReady {
			log.Infow("controller signalled ready")
			break
		} else if resp.Status == controller.StatusWaiting {
			log.Infow("controller signalled waiting, backing off")
		} else {
			return errors.New("nodeagent: unknown status from controller")
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		if backoff < 30*time.Second {
			backoff *= 2
		}
	}

	// TODO: apply overlay, Swarm, and GlusterFS instructions once the
	// corresponding packages are implemented. These operations must be
	// idempotent so repeated joins converge cleanly.
	log.Infow("node join completed (converge steps pending)")
	return nil
}

func validateJoinOptions(opts JoinOptions) error {
	if opts.MasterAddr == "" {
		return errors.New("master address is required")
	}
	if opts.Role == "" {
		opts.Role = "worker"
	}
	if opts.Role != "manager" && opts.Role != "worker" {
		return errors.New("role must be 'manager' or 'worker'")
	}
	return nil
}

func detectIdentity(opts JoinOptions) (ip string, hostname string, err error) {
	if opts.IPOverride != "" {
		ip = opts.IPOverride
	} else {
		addr, err := ipdetect.DetectPrimary()
		if err != nil {
			return "", "", err
		}
		ip = addr.String()
	}

	if opts.HostnameOverride != "" {
		hostname = opts.HostnameOverride
	} else {
		hostname, err = os.Hostname()
		if err != nil {
			return "", "", err
		}
	}

	return ip, hostname, nil
}

func registerOnce(ctx context.Context, master string, reg controller.NodeRegistration) (*controller.NodeResponse, error) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", master)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(&reg); err != nil {
		return nil, err
	}

	var resp controller.NodeResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func dockerVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func memoryMB() int {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	// Look for a line like: "MemTotal:       16367440 kB"
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		return kb / 1024
	}
	return 0
}

