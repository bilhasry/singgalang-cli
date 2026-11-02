// Package nginx renders site configs and manages them for both host and
// Docker nginx installations.
package nginx

import (
	"fmt"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/state"
	"github.com/bilhasry/singgalang-cli/internal/system"
)

// Mode identifies where nginx runs.
type Mode string

const (
	ModeHost   Mode = state.ModeHost
	ModeDocker Mode = state.ModeDocker
)

// SiteSpec describes a site to render into an nginx server block.
type SiteSpec struct {
	Domain   string
	Kind     string // "proxy" or "static"
	Target   string // host:port for proxy, filesystem path for static
	SSL      bool
	Webroot  string
	CertPath string
	KeyPath  string
}

// SiteFile is a singgalang-managed config file on disk.
type SiteFile struct {
	Domain  string
	Path    string
	Enabled bool
}

// Manager writes, validates and reloads site configs for one nginx mode.
type Manager interface {
	Mode() Mode
	SitePath(domain string) string
	AddSite(spec SiteSpec) (string, error)
	RemoveSite(domain string) error
	Enable(domain string) error
	Disable(domain string) error
	Validate() error
	Reload() error
	ListSites() ([]SiteFile, error)
}

// New builds the manager for the given mode. Empty mode auto-detects.
func New(mode string, st *state.State, r system.Runner) (Manager, error) {
	if mode == "" {
		mode = string(DetectMode(r))
	}
	switch Mode(mode) {
	case ModeHost:
		return NewHost(r)
	case ModeDocker:
		return NewDocker(st, r), nil
	}
	return nil, fmt.Errorf("unknown nginx mode %q (want %s or %s)", mode, ModeHost, ModeDocker)
}

// DetectMode prefers host nginx when its binary exists, otherwise
// Docker when the docker CLI is available.
func DetectMode(r system.Runner) Mode {
	if _, err := r.LookPath("nginx"); err == nil {
		return ModeHost
	}
	if _, err := r.LookPath("docker"); err == nil {
		return ModeDocker
	}
	return ModeHost
}

// FileName returns the managed config file name for a domain.
func FileName(domain string) string {
	return "singgalang-" + domain + ".conf"
}

// DomainFromFileName is the inverse of FileName.
func DomainFromFileName(name string) string {
	d := strings.TrimSuffix(name, ".disabled")
	d = strings.TrimSuffix(d, ".conf")
	return strings.TrimPrefix(d, "singgalang-")
}
