// Package state persists singgalang's manifest: configured sites, nginx
// mode, and which firewall ports the CLI itself opened.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Site kinds.
const (
	KindProxy  = "proxy"
	KindStatic = "static"
)

// Nginx modes.
const (
	ModeHost   = "host"
	ModeDocker = "docker"
)

// Defaults.
const (
	DefaultWebroot   = "/var/www/certbot"
	DefaultCertsDir  = "/etc/letsencrypt"
	DefaultContainer = "singgalang-nginx"
)

// Site is one virtual host managed by singgalang.
type Site struct {
	Domain    string `json:"domain"`
	Kind      string `json:"kind"`
	Target    string `json:"target"`
	Container string `json:"container,omitempty"`
	SSL       bool   `json:"ssl"`
	Enabled   bool   `json:"enabled"`
	Webroot   string `json:"webroot,omitempty"`
}

// Port tracks a firewall rule, including whether singgalang opened it.
type Port struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	From     string `json:"from,omitempty"`
	Owned    bool   `json:"owned"`
}

// DockerCfg describes the managed nginx container (docker mode).
type DockerCfg struct {
	ContainerName string `json:"container_name"`
	ConfDir       string `json:"conf_dir"`
}

// State is the on-disk manifest.
type State struct {
	Initialised bool             `json:"initialised"`
	NginxMode   string           `json:"nginx_mode"`
	CertEmail   string           `json:"cert_email,omitempty"`
	Webroot     string           `json:"webroot"`
	CertsDir    string           `json:"certs_dir"`
	Docker      DockerCfg        `json:"docker"`
	Sites       map[string]*Site `json:"sites"`
	Ports       map[string]*Port `json:"ports"`
}

var dirOverride string

// SetDir overrides the state directory (used for --state-dir).
func SetDir(dir string) { dirOverride = dir }

// Dir returns the singgalang state directory.
func Dir() string {
	if dirOverride != "" {
		return dirOverride
	}
	if v := os.Getenv("SINGGALANG_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".singgalang"
	}
	return filepath.Join(home, ".singgalang")
}

// Path returns the manifest file path.
func Path() string {
	return filepath.Join(Dir(), "state.json")
}

// NginxConfDir returns the managed nginx config dir (docker mode).
func NginxConfDir() string {
	return filepath.Join(Dir(), "nginx")
}

// Load reads the manifest, returning a default state when absent.
func Load() (*State, error) {
	data, err := os.ReadFile(Path())
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", Path(), err)
	}
	if s.Sites == nil {
		s.Sites = map[string]*Site{}
	}
	if s.Ports == nil {
		s.Ports = map[string]*Port{}
	}
	if s.Webroot == "" {
		s.Webroot = DefaultWebroot
	}
	if s.CertsDir == "" {
		s.CertsDir = DefaultCertsDir
	}
	if s.Docker.ContainerName == "" {
		s.Docker.ContainerName = DefaultContainer
	}
	if s.Docker.ConfDir == "" {
		s.Docker.ConfDir = NginxConfDir()
	}
	return &s, nil
}

// Default returns a fresh default state.
func Default() *State {
	return &State{
		Sites:    map[string]*Site{},
		Ports:    map[string]*Port{},
		Webroot:  DefaultWebroot,
		CertsDir: DefaultCertsDir,
		Docker: DockerCfg{
			ContainerName: DefaultContainer,
			ConfDir:       NginxConfDir(),
		},
	}
}

// Save writes the manifest atomically.
func (s *State) Save() error {
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	tmp := Path() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	if err := os.Rename(tmp, Path()); err != nil {
		return fmt.Errorf("committing state: %w", err)
	}
	return nil
}

// PortKey builds the map key for a firewall port.
func PortKey(port int, proto string) string {
	return strconv.Itoa(port) + "/" + proto
}

// OwnedPort returns the tracked port entry, or nil.
func (s *State) OwnedPort(port int, proto string) *Port {
	return s.Ports[PortKey(port, proto)]
}

// TrackPort records a firewall rule in the manifest.
func (s *State) TrackPort(port int, proto, from string, owned bool) {
	key := PortKey(port, proto)
	existing, ok := s.Ports[key]
	if ok {
		existing.Owned = existing.Owned || owned
		return
	}
	s.Ports[key] = &Port{Port: port, Protocol: proto, From: from, Owned: owned}
}

// UntrackPort removes a firewall rule from the manifest.
func (s *State) UntrackPort(port int, proto string) {
	delete(s.Ports, PortKey(port, proto))
}
