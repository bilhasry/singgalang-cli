package ops

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/docker"
	"github.com/bilhasry/singgalang-cli/internal/firewall"
	"github.com/bilhasry/singgalang-cli/internal/nginx"
	"github.com/bilhasry/singgalang-cli/internal/state"
)

// SiteAddInput describes a site to create. Exactly one of Proxy, Root or
// Container must be set.
type SiteAddInput struct {
	Domain    string `json:"domain" jsonschema:"fully-qualified domain name for the site, e.g. api.example.com"`
	Proxy     string `json:"proxy,omitempty" jsonschema:"reverse proxy target as [host:]port (e.g. 3000 or 127.0.0.1:3000)"`
	Root      string `json:"root,omitempty" jsonschema:"absolute directory path to serve static files from"`
	Container string `json:"container,omitempty" jsonschema:"docker container name whose published loopback port will be discovered as the proxy target"`
	DryRun    bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done without changing anything"`
}

// SiteAddResult reports the outcome of adding a site.
type SiteAddResult struct {
	Domain     string   `json:"domain"`
	Kind       string   `json:"kind"`
	Target     string   `json:"target"`
	ConfigPath string   `json:"config_path"`
	Config     string   `json:"config,omitempty"`
	Plan       []string `json:"plan,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	NeedsRoot  bool     `json:"needs_root,omitempty"`
	Applied    bool     `json:"applied"`
	Reloaded   bool     `json:"reloaded"`
}

// AddSite validates input, renders the config, and (unless DryRun) writes,
// validates, opens the firewall, updates state and reloads nginx. The whole
// mutation cycle runs under the operation lock.
func (o *Ops) AddSite(in SiteAddInput) (*SiteAddResult, error) {
	targets := 0
	for _, t := range []string{in.Proxy, in.Root, in.Container} {
		if t != "" {
			targets++
		}
	}
	if targets != 1 {
		return nil, fmt.Errorf("specify exactly one of proxy, root or container")
	}
	if in.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	var (
		kind      = state.KindProxy
		target    string
		container string
		warnings  []string
		err       error
	)

	switch {
	case in.Root != "":
		kind = state.KindStatic
		if !strings.HasPrefix(in.Root, "/") {
			return nil, fmt.Errorf("root must be an absolute path")
		}
		target = in.Root
	case in.Container != "":
		cp, warns, cerr := o.discoverContainer(in.Container)
		if cerr != nil {
			return nil, cerr
		}
		target = fmt.Sprintf("127.0.0.1:%d", cp.HostPort)
		container = in.Container
		warnings = append(warnings, warns...)
	default:
		target, err = NormalizeProxy(in.Proxy)
		if err != nil {
			return nil, err
		}
	}

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	if _, exists := st.Sites[in.Domain]; exists {
		return nil, fmt.Errorf("site %s already exists (remove it first)", in.Domain)
	}
	mgr, err := managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}

	spec := nginx.SiteSpec{Domain: in.Domain, Kind: kind, Target: target, Webroot: st.Webroot}
	content, err := nginx.Render(spec)
	if err != nil {
		return nil, err
	}

	fw := firewall.Available(o.Runner)
	res := &SiteAddResult{
		Domain:     in.Domain,
		Kind:       kind,
		Target:     target,
		ConfigPath: mgr.SitePath(in.Domain),
		Config:     content,
		Warnings:   warnings,
	}
	res.Plan = append(res.Plan, fmt.Sprintf("write nginx config %s", res.ConfigPath))
	if kind == state.KindProxy {
		res.Plan = append(res.Plan, fmt.Sprintf("reverse proxy %s → http://%s", in.Domain, target))
	} else {
		res.Plan = append(res.Plan, fmt.Sprintf("serve static files %s → %s", in.Domain, target))
	}
	res.Plan = append(res.Plan, "validate config (nginx -t) and reload nginx")
	if fw {
		res.Plan = append(res.Plan, "open firewall port 80/tcp (HTTP)")
	}
	// Host nginx mode writes under /etc/nginx; ufw rules need root regardless
	// of mode. Docker mode writes under the state dir (no root for the config).
	res.NeedsRoot = mgr.Mode() == nginx.ModeHost || fw

	if in.DryRun {
		return res, nil
	}

	if _, err := mgr.AddSite(spec); err != nil {
		return nil, err
	}
	if fw {
		if err := o.openPortIfNeeded(st, 80, "tcp", ""); err != nil {
			warnings = append(warnings, fmt.Sprintf("firewall: %v", err))
		}
	} else {
		warnings = append(warnings, "ufw not found, skipped firewall setup")
	}
	res.Warnings = warnings

	st.Sites[in.Domain] = &state.Site{
		Domain: in.Domain, Kind: kind, Target: target,
		Container: container, Enabled: true, Webroot: st.Webroot,
	}
	if err := st.Save(); err != nil {
		return nil, err
	}
	if err := mgr.Reload(); err != nil {
		return res, fmt.Errorf("config written and validated, but reload failed: %w", err)
	}
	res.Applied = true
	res.Reloaded = true
	return res, nil
}

// SiteInfo is a site as reported by ListSites.
type SiteInfo struct {
	Domain  string `json:"domain"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	SSL     bool   `json:"ssl"`
	Enabled bool   `json:"enabled"`
}

// ListSites returns sites, optionally filtered by domain.
func (o *Ops) ListSites(domain string) ([]SiteInfo, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	mgr, err := managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}
	files, ferr := mgr.ListSites()

	out := []SiteInfo{}
	for _, site := range st.Sites {
		if domain != "" && site.Domain != domain {
			continue
		}
		enabled := site.Enabled
		if ferr == nil {
			if f, ok := findFile(files, site.Domain); ok {
				enabled = f.Enabled
			}
		}
		out = append(out, SiteInfo{
			Domain: site.Domain, Kind: site.Kind, Target: site.Target,
			SSL: site.SSL, Enabled: enabled,
		})
	}
	return out, nil
}

// SiteActionResult reports removal or enable/disable.
type SiteActionResult struct {
	Domain      string   `json:"domain"`
	Action      string   `json:"action"`
	Plan        []string `json:"plan,omitempty"`
	Applied     bool     `json:"applied"`
	Reloaded    bool     `json:"reloaded"`
	ClosedPorts []int    `json:"closed_ports,omitempty"`
}

// RemoveSite deletes a site; when it was the last site, closes ports that
// singgalang itself opened.
func (o *Ops) RemoveSite(domain string, dryRun bool) (*SiteActionResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	var (
		st       *state.State
		mgr      nginx.Manager
		lastSite bool
		owned    []*state.Port
	)

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	if _, ok := st.Sites[domain]; !ok {
		return nil, fmt.Errorf("site %s is not managed by singgalang", domain)
	}
	lastSite = len(st.Sites) == 1
	owned = ownedFirewallPorts(st)
	mgr, err = managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}

	res := &SiteActionResult{Domain: domain, Action: "remove"}
	res.Plan = append(res.Plan, fmt.Sprintf("delete nginx config %s", mgr.SitePath(domain)))
	res.Plan = append(res.Plan, "validate config (nginx -t) and reload nginx")
	if lastSite {
		for _, p := range owned {
			res.Plan = append(res.Plan, fmt.Sprintf("close firewall port %d/%s (last site, opened by singgalang)", p.Port, p.Protocol))
		}
	}
	if dryRun {
		return res, nil
	}

	if err := mgr.RemoveSite(domain); err != nil {
		return nil, err
	}
	if lastSite && firewall.Available(o.Runner) {
		for _, p := range owned {
			if err := firewall.Close(p.Port, p.Protocol, p.From, o.Runner); err != nil {
				continue
			}
			st.UntrackPort(p.Port, p.Protocol)
			res.ClosedPorts = append(res.ClosedPorts, p.Port)
		}
	}
	delete(st.Sites, domain)
	if err := st.Save(); err != nil {
		return nil, err
	}
	if err := mgr.Reload(); err != nil {
		return res, fmt.Errorf("config removed and validated, but reload failed: %w", err)
	}
	res.Applied = true
	res.Reloaded = true
	return res, nil
}

// ToggleSite enables or disables a site.
func (o *Ops) ToggleSite(domain string, enable, dryRun bool) (*SiteActionResult, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	verb := "disable"
	if enable {
		verb = "enable"
	}
	var mgr nginx.Manager

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	if _, ok := st.Sites[domain]; !ok {
		return nil, fmt.Errorf("site %s is not managed by singgalang", domain)
	}
	mgr, err = managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}

	res := &SiteActionResult{Domain: domain, Action: verb}
	res.Plan = append(res.Plan, fmt.Sprintf("%s config and reload nginx", verb))
	if dryRun {
		return res, nil
	}

	if enable {
		err = mgr.Enable(domain)
	} else {
		err = mgr.Disable(domain)
	}
	if err != nil {
		return nil, err
	}
	st.Sites[domain].Enabled = enable
	if err := st.Save(); err != nil {
		return nil, err
	}
	if err := mgr.Reload(); err != nil {
		return res, fmt.Errorf("config updated and validated, but reload failed: %w", err)
	}
	res.Applied = true
	res.Reloaded = true
	return res, nil
}

// discoverContainer resolves a container's loopback port, warning about
// publicly exposed bindings. It returns an AmbiguousError when the choice is
// unclear.
func (o *Ops) discoverContainer(name string) (ContainerPort, []string, error) {
	if !docker.Available(o.Runner) {
		return ContainerPort{}, nil, fmt.Errorf("docker CLI not found (needed for container discovery)")
	}
	c, err := docker.Inspect(name, o.Runner)
	if err != nil {
		return ContainerPort{}, nil, err
	}
	var notes []string
	if !c.Running {
		notes = append(notes, fmt.Sprintf("container %q is not running — the site will fail until it starts", name))
	}
	if len(c.Bindings) == 0 {
		return ContainerPort{}, nil, fmt.Errorf("container %q publishes no ports — add -p to the container or use proxy", name)
	}

	var loopback, exposed []ContainerPort
	for _, b := range c.Bindings {
		cp := ContainerPort{HostPort: b.HostPort, ContainerPort: b.ContainerPort, Proto: b.Proto, Exposed: b.Exposed()}
		if b.Exposed() {
			exposed = append(exposed, cp)
		} else {
			loopback = append(loopback, cp)
		}
	}
	candidates := loopback
	if len(candidates) == 0 {
		candidates = exposed
		for _, cp := range candidates {
			notes = append(notes, fmt.Sprintf(
				"container %q publishes port %d publicly — Docker-published ports bypass ufw, so it is reachable from the internet; rebind with -p 127.0.0.1:%d:%d to keep it private",
				name, cp.HostPort, cp.HostPort, cp.ContainerPort))
		}
	}
	if len(candidates) == 1 {
		return candidates[0], notes, nil
	}
	return ContainerPort{}, notes, &AmbiguousError{Container: name, Candidates: candidates}
}

// openPortIfNeeded opens a port when no allow rule exists, tracking ownership.
func (o *Ops) openPortIfNeeded(st *state.State, port int, proto, from string) error {
	rules, err := firewall.Status(o.Runner)
	if err != nil {
		return err
	}
	if firewall.Has(rules, port, proto) {
		st.TrackPort(port, proto, from, false)
		return nil
	}
	if err := firewall.Open(port, proto, from, o.Runner); err != nil {
		return err
	}
	st.TrackPort(port, proto, from, true)
	return nil
}

// NormalizeProxy turns "3000" / "localhost:3000" / "http://host:3000/" into
// "host:port".
func NormalizeProxy(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	t = strings.TrimPrefix(t, "http://")
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimSuffix(t, "/")
	if t == "" {
		return "", fmt.Errorf("empty proxy target")
	}
	if !strings.Contains(t, ":") {
		if _, err := strconv.Atoi(t); err == nil {
			return "127.0.0.1:" + t, nil
		}
		return "", fmt.Errorf("proxy must be [host:]port, got %q", raw)
	}
	return t, nil
}

// ownedFirewallPorts returns ports singgalang itself opened.
func ownedFirewallPorts(st *state.State) []*state.Port {
	var out []*state.Port
	for _, p := range st.Ports {
		if p.Owned {
			out = append(out, p)
		}
	}
	return out
}

func findFile(files []nginx.SiteFile, domain string) (nginx.SiteFile, bool) {
	for _, f := range files {
		if f.Domain == domain {
			return f, true
		}
	}
	return nginx.SiteFile{}, false
}
