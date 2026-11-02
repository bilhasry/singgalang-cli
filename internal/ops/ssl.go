package ops

import (
	"fmt"
	"os"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/firewall"
	"github.com/bilhasry/singgalang-cli/internal/nginx"
	"github.com/bilhasry/singgalang-cli/internal/ssl"
	"github.com/bilhasry/singgalang-cli/internal/state"
)

// SSLIssueInput describes a certificate request.
type SSLIssueInput struct {
	Domain string `json:"domain" jsonschema:"domain of an existing singgalang site to secure"`
	Email  string `json:"email,omitempty" jsonschema:"email for Let's Encrypt registration and expiry notices"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done without changing anything"`
}

// SSLIssueResult reports the outcome of issuing a certificate.
type SSLIssueResult struct {
	Domain   string   `json:"domain"`
	Plan     []string `json:"plan,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Applied  bool     `json:"applied"`
	Reloaded bool     `json:"reloaded"`
}

// IssueSSL obtains a Let's Encrypt certificate for an existing site and
// switches its nginx config to HTTPS.
func (o *Ops) IssueSSL(in SSLIssueInput) (*SSLIssueResult, error) {
	if in.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if !ssl.Available(o.Runner) {
		return nil, fmt.Errorf("certbot not found — install certbot first")
	}

	mutateMu.Lock()
	defer mutateMu.Unlock()

	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	site, ok := st.Sites[in.Domain]
	if !ok {
		return nil, fmt.Errorf("site %s is not managed by singgalang — add it first", in.Domain)
	}
	if site.SSL {
		return nil, fmt.Errorf("site %s already has SSL enabled", in.Domain)
	}
	mgr, err := managerFor(st, o.Runner)
	if err != nil {
		return nil, err
	}

	email := in.Email
	if email == "" {
		email = st.CertEmail
	}

	res := &SSLIssueResult{Domain: in.Domain}
	res.Plan = append(res.Plan,
		fmt.Sprintf("open firewall port 443/tcp (HTTPS) if not already open"),
		fmt.Sprintf("certbot certonly --webroot -w %s -d %s", st.Webroot, in.Domain),
		fmt.Sprintf("enable HTTPS in the nginx config for %s", in.Domain),
		"validate config (nginx -t) and reload nginx",
	)
	if in.DryRun {
		return res, nil
	}

	// ACME webroot must exist before certbot runs.
	if err := os.MkdirAll(st.Webroot, 0o755); err != nil {
		return nil, fmt.Errorf("creating webroot %s: %w", st.Webroot, err)
	}

	// 443 must be reachable for HTTP-01 validation.
	if firewall.Available(o.Runner) {
		if err := o.openPortIfNeeded(st, 443, "tcp", ""); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("firewall: %v", err))
		}
	}

	if err := ssl.Issue(in.Domain, email, st.Webroot, o.Runner); err != nil {
		_ = st.Save() // persist any firewall tracking already done
		return nil, err
	}

	site.SSL = true
	site.Webroot = st.Webroot
	spec := nginx.SiteSpec{
		Domain:   site.Domain,
		Kind:     site.Kind,
		Target:   site.Target,
		SSL:      true,
		Webroot:  st.Webroot,
		CertPath: ssl.CertPath(st.CertsDir, in.Domain),
		KeyPath:  ssl.KeyPath(st.CertsDir, in.Domain),
	}
	if _, err := mgr.AddSite(spec); err != nil {
		site.SSL = false
		return nil, fmt.Errorf("certificate issued but HTTPS config failed, reverted: %w", err)
	}
	st.CertEmail = email
	if err := st.Save(); err != nil {
		return nil, err
	}
	if err := mgr.Reload(); err != nil {
		return res, fmt.Errorf("certificate issued and config validated, but reload failed: %w", err)
	}
	res.Applied = true
	res.Reloaded = true
	return res, nil
}

// CertInfo is a certificate as reported by ListCerts.
type CertInfo struct {
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	NotAfter string   `json:"not_after"`
	DaysLeft int      `json:"days_left"`
	Status   string   `json:"status"`
}

// ListCerts lists issued certificates, optionally filtered by name/domain.
func (o *Ops) ListCerts(filter string) ([]CertInfo, error) {
	st, err := state.Load()
	if err != nil {
		return nil, err
	}
	certs, err := ssl.List(st.CertsDir)
	if err != nil {
		return nil, err
	}
	out := []CertInfo{}
	for _, c := range certs {
		if filter != "" && c.Name != filter && !containsDomain(c.Domains, filter) {
			continue
		}
		out = append(out, CertInfo{
			Name:     c.Name,
			Domains:  c.Domains,
			NotAfter: c.NotAfter.Format("2006-01-02 15:04:05 MST"),
			DaysLeft: c.DaysLeft(),
			Status:   ssl.Status(c),
		})
	}
	return out, nil
}

// RenewResult reports a renewal run.
type RenewResult struct {
	Plan    []string `json:"plan,omitempty"`
	Applied bool     `json:"applied"`
	Output  string   `json:"output,omitempty"`
}

// RenewCerts renews all certificates. When planOnly is true it only reports
// the plan without running certbot. Otherwise dryRun runs certbot's own dry
// run instead of a real renewal.
func (o *Ops) RenewCerts(dryRun, planOnly bool) (*RenewResult, error) {
	if !ssl.Available(o.Runner) {
		return nil, fmt.Errorf("certbot not found — install certbot first")
	}
	res := &RenewResult{}
	if dryRun {
		res.Plan = append(res.Plan, "certbot renew --dry-run (certbot's own test run)")
	} else {
		res.Plan = append(res.Plan, "certbot renew")
	}
	if planOnly {
		return res, nil
	}
	// certbot reads and writes /etc/letsencrypt even in dry-run mode.
	if err := requireRoot("certbot renew"); err != nil {
		return res, err
	}
	args := []string{"renew"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	out, err := o.Runner.Run("certbot", args...)
	if err != nil {
		return res, err
	}
	res.Output = strings.TrimSpace(out)
	res.Applied = true
	return res, nil
}

func containsDomain(domains []string, want string) bool {
	for _, d := range domains {
		if d == want {
			return true
		}
	}
	return false
}
