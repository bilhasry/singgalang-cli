package ops

import (
	"fmt"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/docker"
	"github.com/bilhasry/singgalang-cli/internal/firewall"
	"github.com/bilhasry/singgalang-cli/internal/nginx"
	"github.com/bilhasry/singgalang-cli/internal/state"
)

// PortActionInput describes opening or closing a firewall port.
type PortActionInput struct {
	Port   int    `json:"port" jsonschema:"port number between 1 and 65535"`
	Proto  string `json:"proto,omitempty" jsonschema:"protocol, tcp (default) or udp"`
	From   string `json:"from,omitempty" jsonschema:"optional source CIDR to restrict, e.g. 10.0.0.0/8"`
	Force  bool   `json:"force,omitempty" jsonschema:"required to close a port singgalang did not open"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done"`
}

// PortActionResult reports an open/close outcome.
type PortActionResult struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Action  string   `json:"action"`
	Plan    []string `json:"plan,omitempty"`
	Applied bool     `json:"applied"`
	Noop    bool     `json:"noop,omitempty"`
	Message string   `json:"message,omitempty"`
}

// OpenPort adds a ufw allow rule, tracking ownership in state.
func (o *Ops) OpenPort(in PortActionInput) (*PortActionResult, error) {
	if in.Port <= 0 || in.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	proto := normalizeProto(in.Proto)
	if !firewall.Available(o.Runner) {
		return nil, fmt.Errorf("ufw not found — install ufw first")
	}

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}

	res := &PortActionResult{Port: in.Port, Proto: proto, Action: "open"}
	target := fmt.Sprintf("%d/%s", in.Port, proto)
	if in.From != "" {
		target = fmt.Sprintf("from %s to any port %d proto %s", in.From, in.Port, proto)
	}
	res.Plan = append(res.Plan, "ufw allow "+target)

	if in.DryRun {
		return res, nil
	}

	rules, err := firewall.Status(o.Runner)
	if err != nil {
		return nil, err
	}
	if firewall.Has(rules, in.Port, proto) {
		st.TrackPort(in.Port, proto, in.From, false)
		if err := st.Save(); err != nil {
			return nil, err
		}
		res.Noop = true
		res.Message = fmt.Sprintf("port %d/%s is already allowed", in.Port, proto)
		return res, nil
	}

	if err := firewall.Open(in.Port, proto, in.From, o.Runner); err != nil {
		return nil, err
	}
	st.TrackPort(in.Port, proto, in.From, true)
	if err := st.Save(); err != nil {
		return nil, err
	}
	res.Applied = true
	return res, nil
}

// ClosePort removes a ufw allow rule. Rules singgalang did not open require
// Force.
func (o *Ops) ClosePort(in PortActionInput) (*PortActionResult, error) {
	if in.Port <= 0 || in.Port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}
	proto := normalizeProto(in.Proto)
	if !firewall.Available(o.Runner) {
		return nil, fmt.Errorf("ufw not found — install ufw first")
	}

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	tracked := st.OwnedPort(in.Port, proto)
	if tracked == nil || !tracked.Owned {
		if !in.Force {
			return nil, fmt.Errorf("port %d/%s was not opened by singgalang — set force to close it anyway", in.Port, proto)
		}
	}

	res := &PortActionResult{Port: in.Port, Proto: proto, Action: "close"}
	target := fmt.Sprintf("%d/%s", in.Port, proto)
	if in.From != "" {
		target = fmt.Sprintf("from %s to any port %d proto %s", in.From, in.Port, proto)
	}
	res.Plan = append(res.Plan, "ufw --force delete allow "+target)

	if in.DryRun {
		return res, nil
	}

	rules, err := firewall.Status(o.Runner)
	if err != nil {
		return nil, err
	}
	if !firewall.Has(rules, in.Port, proto) {
		st.UntrackPort(in.Port, proto)
		if err := st.Save(); err != nil {
			return nil, err
		}
		res.Noop = true
		res.Message = fmt.Sprintf("port %d/%s is not open", in.Port, proto)
		return res, nil
	}

	from := in.From
	if tracked != nil && tracked.From != "" {
		from = tracked.From
	}
	if err := firewall.Close(in.Port, proto, from, o.Runner); err != nil {
		return nil, err
	}
	st.UntrackPort(in.Port, proto)
	if err := st.Save(); err != nil {
		return nil, err
	}
	res.Applied = true
	return res, nil
}

// FWRule is one firewall rule as reported by ListPorts.
type FWRule struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Action  string `json:"action"`
	From    string `json:"from"`
	Managed string `json:"managed"` // "singgalang", "existed" or ""
}

// DockerPort is one Docker-published port as reported by ListPorts.
type DockerPort struct {
	Container     string `json:"container"`
	Bind          string `json:"bind"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`
	Risk          string `json:"risk"`
}

// PortsReport is the combined firewall + docker port listing.
type PortsReport struct {
	FirewallActive bool         `json:"firewall_active"`
	FirewallRules  []FWRule     `json:"firewall_rules"`
	DockerPorts    []DockerPort `json:"docker_ports"`
	Warnings       []string     `json:"warnings,omitempty"`
}

// ListPorts reports ufw rules (marking singgalang-managed ones) and
// Docker-published ports, warning about ufw bypass.
func (o *Ops) ListPorts() (*PortsReport, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	res := &PortsReport{FirewallRules: []FWRule{}, DockerPorts: []DockerPort{}}

	if firewall.Available(o.Runner) {
		active, err := firewall.Active(o.Runner)
		if err == nil {
			res.FirewallActive = active
			if active {
				rules, err := firewall.Status(o.Runner)
				if err != nil {
					return nil, err
				}
				for _, r := range rules {
					managed := ""
					if p := st.OwnedPort(r.Port, r.Proto); p != nil {
						if p.Owned {
							managed = "singgalang"
						} else {
							managed = "existed"
						}
					}
					res.FirewallRules = append(res.FirewallRules, FWRule{
						Port: r.Port, Proto: r.Proto, Action: r.Action,
						From: r.From, Managed: managed,
					})
				}
			}
		}
	}

	if docker.Available(o.Runner) {
		containers, err := docker.ListRunning(o.Runner)
		if err == nil {
			anyExposed := false
			for _, c := range containers {
				for _, b := range c.Bindings {
					bind := fmt.Sprintf("%s:%d", hostIPOrAll(b.HostIP), b.HostPort)
					risk := "loopback only"
					if b.Exposed() {
						risk = "EXPOSED — bypasses ufw"
						anyExposed = true
					}
					res.DockerPorts = append(res.DockerPorts, DockerPort{
						Container: c.Name, Bind: bind,
						ContainerPort: b.ContainerPort, Proto: b.Proto, Risk: risk,
					})
				}
			}
			if anyExposed {
				res.Warnings = append(res.Warnings,
					"Docker-published ports on 0.0.0.0 bypass ufw entirely — ufw rules cannot block them; bind sensitive ports to loopback instead, e.g. -p 127.0.0.1:3000:3000")
			}
		}
	}
	return res, nil
}

// ReloadResult reports a validate+reload run.
type ReloadResult struct {
	Mode    string   `json:"mode"`
	Plan    []string `json:"plan,omitempty"`
	Applied bool     `json:"applied"`
}

// PlanReload reports the reload plan and current nginx mode without
// validating or reloading.
func (o *Ops) PlanReload() (*ReloadResult, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	mgr, err := managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}
	return &ReloadResult{Mode: string(mgr.Mode())}, nil
}

// Reload validates the nginx config and reloads it.
func (o *Ops) Reload() (*ReloadResult, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	mgr, err := managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}
	res := &ReloadResult{Mode: string(mgr.Mode())}
	res.Plan = append(res.Plan, "nginx -t (validate)", fmt.Sprintf("reload nginx (%s mode)", mgr.Mode()))
	if err := mgr.Validate(); err != nil {
		return res, fmt.Errorf("config invalid:\n%w", err)
	}
	if err := mgr.Reload(); err != nil {
		return res, err
	}
	res.Applied = true
	return res, nil
}

// InitInput configures initial singgalang state.
type InitInput struct {
	NginxMode     string `json:"nginx_mode,omitempty" jsonschema:"nginx mode: auto (default), host or docker"`
	Email         string `json:"email,omitempty" jsonschema:"Let's Encrypt registration email"`
	Webroot       string `json:"webroot,omitempty" jsonschema:"ACME webroot directory (default /var/www/certbot)"`
	ContainerName string `json:"container_name,omitempty" jsonschema:"nginx container name for docker mode (default singgalang-nginx)"`
	DryRun        bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done"`
}

// InitResult reports environment detection and setup.
type InitResult struct {
	Env     EnvReport `json:"env"`
	Plan    []string  `json:"plan,omitempty"`
	Applied bool      `json:"applied"`
	Started string    `json:"docker_start_hint,omitempty"`
}

// Init detects the environment, resolves the nginx mode and writes state.
func (o *Ops) Init(in InitInput) (*InitResult, error) {
	env := o.Detect()

	mode := in.NginxMode
	if mode == "" || mode == "auto" {
		mode = env.NginxMode
	}
	if mode != state.ModeHost && mode != state.ModeDocker {
		return nil, fmt.Errorf("unknown nginx mode %q (want host or docker)", mode)
	}

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	st.NginxMode = mode
	st.Initialised = true
	if in.Email != "" {
		st.CertEmail = in.Email
	}
	if in.Webroot != "" {
		st.Webroot = in.Webroot
	}
	if in.ContainerName != "" {
		st.Docker.ContainerName = in.ContainerName
	}

	res := &InitResult{Env: env}
	if mode == state.ModeDocker {
		m := nginx.NewDocker(st, o.Runner)
		res.Plan = append(res.Plan, fmt.Sprintf("create managed config dir %s with nginx.conf and docker-compose.yaml", st.Docker.ConfDir))
		res.Started = fmt.Sprintf("cd %s && docker compose up -d", st.Docker.ConfDir)
		if in.DryRun {
			return res, nil
		}
		if err := m.EnsureLayout(st); err != nil {
			return nil, err
		}
	} else if in.DryRun {
		res.Plan = append(res.Plan, "use host nginx config under /etc/nginx")
		return res, nil
	}

	if err := st.Save(); err != nil {
		return nil, err
	}
	res.Applied = true
	return res, nil
}

func normalizeProto(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "tcp"
	}
	return p
}

func hostIPOrAll(ip string) string {
	if ip == "" {
		return "0.0.0.0"
	}
	return ip
}
