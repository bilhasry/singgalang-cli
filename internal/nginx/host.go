package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/system"
)

// HostManager manages configs under /etc/nginx on the host.
type HostManager struct {
	r            system.Runner
	root         string
	availableDir string // set when sites-available/sites-enabled pattern is used
	enabledDir   string
	confDir      string // set when only conf.d exists
}

// NewHost detects the host nginx layout.
func NewHost(r system.Runner) (*HostManager, error) {
	root := "/etc/nginx"
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("nginx config directory %s not found — is nginx installed? (run 'singgalang init' to see what was detected)", root)
	}
	m := &HostManager{r: r, root: root}
	avail := filepath.Join(root, "sites-available")
	enabled := filepath.Join(root, "sites-enabled")
	if isDir(avail) && isDir(enabled) {
		m.availableDir = avail
		m.enabledDir = enabled
	} else {
		m.confDir = filepath.Join(root, "conf.d")
	}
	return m, nil
}

func (m *HostManager) Mode() Mode { return ModeHost }

// primaryDir is where site configs live (available dir, or conf.d).
func (m *HostManager) primaryDir() string {
	if m.availableDir != "" {
		return m.availableDir
	}
	return m.confDir
}

func (m *HostManager) SitePath(domain string) string {
	return filepath.Join(m.primaryDir(), FileName(domain))
}

// AddSite writes the rendered config and validates it, rolling back on
// validation failure. The site starts enabled.
func (m *HostManager) AddSite(spec SiteSpec) (string, error) {
	content, err := Render(spec)
	if err != nil {
		return "", err
	}
	path := m.SitePath(spec.Domain)
	restore, err := writeFile(path, []byte(content))
	if err != nil {
		return "", err
	}
	if m.availableDir != "" {
		if err := m.link(spec.Domain); err != nil {
			restore()
			return "", err
		}
	}
	if err := m.Validate(); err != nil {
		restore()
		return path, fmt.Errorf("nginx config rejected, reverted %s:\n%w", path, err)
	}
	return path, nil
}

func (m *HostManager) RemoveSite(domain string) error {
	path := m.SitePath(domain)
	if m.availableDir != "" {
		_ = os.Remove(filepath.Join(m.enabledDir, FileName(domain)))
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	// conf.d mode: also drop a disabled variant if present.
	if m.availableDir == "" {
		_ = os.Remove(strings.TrimSuffix(path, ".conf") + ".conf.disabled")
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("nginx config invalid after removal:\n%w", err)
	}
	return nil
}

func (m *HostManager) Enable(domain string) error {
	if m.availableDir != "" {
		return m.link(domain)
	}
	path := m.SitePath(domain)
	disabled := strings.TrimSuffix(path, ".conf") + ".conf.disabled"
	if _, err := os.Stat(disabled); err == nil {
		if err := os.Rename(disabled, path); err != nil {
			return err
		}
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("nginx config invalid after enable:\n%w", err)
	}
	return nil
}

func (m *HostManager) Disable(domain string) error {
	if m.availableDir != "" {
		if err := os.Remove(filepath.Join(m.enabledDir, FileName(domain))); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := m.Validate(); err != nil {
			return fmt.Errorf("nginx config invalid after disable:\n%w", err)
		}
		return nil
	}
	path := m.SitePath(domain)
	disabled := strings.TrimSuffix(path, ".conf") + ".conf.disabled"
	if _, err := os.Stat(path); err == nil {
		if err := os.Rename(path, disabled); err != nil {
			return err
		}
	}
	if err := m.Validate(); err != nil {
		return fmt.Errorf("nginx config invalid after disable:\n%w", err)
	}
	return nil
}

// link symlinks sites-available/<file> into sites-enabled.
func (m *HostManager) link(domain string) error {
	name := FileName(domain)
	target := filepath.Join(m.availableDir, name)
	link := filepath.Join(m.enabledDir, name)
	_ = os.Remove(link)
	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("enabling %s: %w", domain, err)
	}
	return nil
}

func (m *HostManager) Validate() error {
	_, err := m.r.Run("nginx", "-t")
	if err != nil {
		return err
	}
	return nil
}

func (m *HostManager) Reload() error {
	if _, err := m.r.LookPath("systemctl"); err == nil {
		if _, err := m.r.Run("systemctl", "reload", "nginx"); err == nil {
			return nil
		}
	}
	if _, err := m.r.Run("nginx", "-s", "reload"); err != nil {
		return fmt.Errorf("reloading nginx failed: %w", err)
	}
	return nil
}

func (m *HostManager) ListSites() ([]SiteFile, error) {
	var out []SiteFile
	pattern := filepath.Join(m.primaryDir(), "singgalang-*.conf")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	for _, p := range matches {
		name := filepath.Base(p)
		enabled := true
		if m.availableDir != "" {
			_, err := os.Lstat(filepath.Join(m.enabledDir, name))
			enabled = err == nil
		}
		out = append(out, SiteFile{Domain: DomainFromFileName(name), Path: p, Enabled: enabled})
	}
	if m.availableDir == "" {
		// disabled variants: singgalang-x.conf.disabled
		dispattern := filepath.Join(m.primaryDir(), "singgalang-*.conf.disabled")
		dismatches, _ := filepath.Glob(dispattern)
		for _, p := range dismatches {
			name := strings.TrimSuffix(filepath.Base(p), ".disabled")
			out = append(out, SiteFile{Domain: DomainFromFileName(name), Path: p, Enabled: false})
		}
	}
	return out, nil
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// writeFile writes data to path and returns a restore func that puts the
// previous content back (or removes the file if it did not exist).
func writeFile(path string, data []byte) (func(), error) {
	old, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	restore := func() {
		if existed {
			_ = os.WriteFile(path, old, 0o644)
		} else {
			_ = os.Remove(path)
		}
	}
	return restore, nil
}
