package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/state"
	"github.com/bilhasry/singgalang-cli/internal/system"
)

// DockerManager manages a managed conf dir on the host that is mounted
// into an nginx container.
type DockerManager struct {
	r         system.Runner
	confDir   string
	sitesDir  string
	container string
}

// NewDocker builds the docker-mode manager from state.
func NewDocker(st *state.State, r system.Runner) *DockerManager {
	confDir := st.Docker.ConfDir
	if confDir == "" {
		confDir = state.NginxConfDir()
	}
	return &DockerManager{
		r:         r,
		confDir:   confDir,
		sitesDir:  filepath.Join(confDir, "sites-enabled"),
		container: st.Docker.ContainerName,
	}
}

func (m *DockerManager) Mode() Mode { return ModeDocker }

// ConfDir is the managed config directory.
func (m *DockerManager) ConfDir() string { return m.confDir }

// Container is the nginx container name.
func (m *DockerManager) Container() string { return m.container }

// EnsureLayout creates the managed dir tree, nginx.conf and compose file.
func (m *DockerManager) EnsureLayout(st *state.State) error {
	if err := os.MkdirAll(m.sitesDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", m.sitesDir, err)
	}
	conf, err := RenderNginxConf()
	if err != nil {
		return err
	}
	if _, err := writeFile(filepath.Join(m.confDir, "nginx.conf"), []byte(conf)); err != nil {
		return err
	}
	compose, err := RenderCompose(ComposeData{
		ContainerName: m.container,
		ConfDir:       m.confDir,
		Webroot:       st.Webroot,
		CertsDir:      st.CertsDir,
	})
	if err != nil {
		return err
	}
	if _, err := writeFile(filepath.Join(m.confDir, "docker-compose.yaml"), []byte(compose)); err != nil {
		return err
	}
	return nil
}

func (m *DockerManager) SitePath(domain string) string {
	return filepath.Join(m.sitesDir, FileName(domain))
}

func (m *DockerManager) AddSite(spec SiteSpec) (string, error) {
	content, err := Render(spec)
	if err != nil {
		return "", err
	}
	path := m.SitePath(spec.Domain)
	restore, err := writeFile(path, []byte(content))
	if err != nil {
		return "", err
	}
	if err := m.Validate(); err != nil {
		restore()
		return path, fmt.Errorf("nginx config rejected, reverted %s:\n%w", path, err)
	}
	return path, nil
}

func (m *DockerManager) RemoveSite(domain string) error {
	path := m.SitePath(domain)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = os.Remove(strings.TrimSuffix(path, ".conf") + ".conf.disabled")
	if err := m.Validate(); err != nil {
		return fmt.Errorf("nginx config invalid after removal:\n%w", err)
	}
	return nil
}

func (m *DockerManager) Enable(domain string) error {
	path := m.SitePath(domain)
	disabled := strings.TrimSuffix(path, ".conf") + ".conf.disabled"
	if _, err := os.Stat(disabled); err == nil {
		if err := os.Rename(disabled, path); err != nil {
			return err
		}
	}
	return m.Validate()
}

func (m *DockerManager) Disable(domain string) error {
	path := m.SitePath(domain)
	disabled := strings.TrimSuffix(path, ".conf") + ".conf.disabled"
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, disabled); err != nil {
			return err
		}
	}
	return m.Validate()
}

func (m *DockerManager) Validate() error {
	if _, err := m.r.LookPath("docker"); err != nil {
		return fmt.Errorf("docker CLI not found")
	}
	_, err := m.r.Run("docker", "exec", m.container, "nginx", "-t")
	if err != nil {
		if strings.Contains(err.Error(), "No such container") || strings.Contains(err.Error(), "container not running") {
			return fmt.Errorf("nginx container %q is not running — start it with:\n  cd %s && docker compose up -d", m.container, m.confDir)
		}
		return err
	}
	return nil
}

func (m *DockerManager) Reload() error {
	_, err := m.r.Run("docker", "exec", m.container, "nginx", "-s", "reload")
	if err != nil {
		return fmt.Errorf("reloading nginx container failed: %w", err)
	}
	return nil
}

func (m *DockerManager) ListSites() ([]SiteFile, error) {
	var out []SiteFile
	matches, err := filepath.Glob(filepath.Join(m.sitesDir, "singgalang-*.conf"))
	if err != nil {
		return nil, err
	}
	for _, p := range matches {
		out = append(out, SiteFile{Domain: DomainFromFileName(filepath.Base(p)), Path: p, Enabled: true})
	}
	dismatches, _ := filepath.Glob(filepath.Join(m.sitesDir, "singgalang-*.conf.disabled"))
	for _, p := range dismatches {
		out = append(out, SiteFile{Domain: DomainFromFileName(filepath.Base(p)), Path: p, Enabled: false})
	}
	return out, nil
}
