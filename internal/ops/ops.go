// Package ops contains singgalang's core operations, shared by the CLI and
// the MCP server. Functions here are non-interactive: they never prompt and
// never re-exec via sudo. Instead they report what they need (plan,
// NeedsRoot) and perform the mutation when asked.
package ops

import (
	"fmt"
	"strings"
	"sync"

	"github.com/bilhasry/singgalang-cli/internal/nginx"
	"github.com/bilhasry/singgalang-cli/internal/state"
	"github.com/bilhasry/singgalang-cli/internal/system"
)

// mutateMu serializes mutating operations so concurrent MCP tool calls
// cannot interleave state read/modify/write cycles.
var mutateMu sync.Mutex

// NeedsRootError reports that an operation requires root privileges.
type NeedsRootError struct{ Op string }

func (e *NeedsRootError) Error() string {
	return fmt.Sprintf("%s requires root privileges — run singgalang with sudo, or run the MCP server as root", e.Op)
}

// AmbiguousError reports that a container publishes several ports and the
// caller must pick one explicitly.
type AmbiguousError struct {
	Container  string
	Candidates []ContainerPort
}

func (e *AmbiguousError) Error() string {
	var opts []string
	for _, c := range e.Candidates {
		opts = append(opts, fmt.Sprintf("127.0.0.1:%d", c.HostPort))
	}
	return fmt.Sprintf("container %q publishes several ports (%s); specify proxy explicitly with one of these targets", e.Container, strings.Join(opts, ", "))
}

// ContainerPort is one published port discovered on a container.
type ContainerPort struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`
	Exposed       bool   `json:"exposed"`
}

// Ops bundles the dependencies for operations. The zero value is not
// usable; call New.
type Ops struct {
	Runner system.Runner
}

// New builds an Ops using the default process runner.
func New() *Ops { return &Ops{Runner: system.Default} }

// StateDir returns the state directory, honouring any --state-dir override
// applied by the CLI.
func StateDir() string { return state.Dir() }

// managerFor resolves the nginx manager, auto-detecting the mode when unset.
func managerFor(st *state.State, r system.Runner) (nginx.Manager, error) {
	mode := st.NginxMode
	if mode == "" {
		mode = string(nginx.DetectMode(r))
		st.NginxMode = mode
	}
	return nginx.New(mode, st, r)
}

// requireRoot returns a NeedsRootError when the process is not root.
func requireRoot(op string) error {
	if !system.IsRoot() {
		return &NeedsRootError{Op: op}
	}
	return nil
}

// --- environment ---

// EnvReport summarizes the detected environment.
type EnvReport struct {
	OS           string `json:"os"`
	OSPretty     string `json:"os_pretty"`
	NginxBinary  string `json:"nginx_binary,omitempty"`
	NginxConfDir bool   `json:"nginx_conf_dir"`
	Docker       string `json:"docker,omitempty"`
	Certbot      string `json:"certbot,omitempty"`
	Ufw          string `json:"ufw,omitempty"`
	Systemctl    string `json:"systemctl,omitempty"`
	NginxMode    string `json:"nginx_mode"`
	StateDir     string `json:"state_dir"`
	IsRoot       bool   `json:"is_root"`
}

// Detect inspects the environment and reports it.
func (o *Ops) Detect() EnvReport {
	env := system.Detect(o.Runner)
	st, _ := state.Load()
	mode := st.NginxMode
	if mode == "" {
		mode = string(nginx.DetectMode(o.Runner))
	}
	return EnvReport{
		OS:           env.OSName,
		OSPretty:     env.OSPretty,
		NginxBinary:  env.NginxBinary,
		NginxConfDir: env.NginxConfDir,
		Docker:       env.Docker,
		Certbot:      env.Certbot,
		Ufw:          env.Ufw,
		Systemctl:    env.Systemctl,
		NginxMode:    mode,
		StateDir:     state.Dir(),
		IsRoot:       system.IsRoot(),
	}
}
