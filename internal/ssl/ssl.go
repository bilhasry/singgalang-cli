// Package ssl wraps certbot (issue, renew) and parses issued
// certificates directly from disk.
package ssl

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bilhasry/singgalang-cli/internal/system"
)

// Available reports whether certbot is installed.
func Available(r system.Runner) bool {
	return system.Available(r, "certbot")
}

// Cert is one certificate on disk.
type Cert struct {
	Name     string
	Domains  []string
	NotAfter time.Time
	Path     string
}

// DaysLeft returns whole days until expiry.
func (c Cert) DaysLeft() int {
	return int(c.NotAfter.Sub(time.Now()).Hours() / 24)
}

// Issue requests a certificate via certbot's webroot authenticator.
func Issue(domain, email, webroot string, r system.Runner) error {
	args := []string{
		"certonly",
		"--webroot", "-w", webroot,
		"-d", domain,
		"--non-interactive",
		"--agree-tos",
	}
	if email != "" {
		args = append(args, "--email", email)
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	if _, err := r.Run("certbot", args...); err != nil {
		return fmt.Errorf("certbot failed for %s: %w", domain, err)
	}
	return nil
}

// Renew renews all certificates; dryRun runs certbot's own dry run.
func Renew(dryRun bool, r system.Runner) error {
	args := []string{"renew"}
	if dryRun {
		args = append(args, "--dry-run")
	}
	if _, err := r.Run("certbot", args...); err != nil {
		return fmt.Errorf("certbot renew: %w", err)
	}
	return nil
}

// List parses issued certificates from certsDir/live (e.g.
// /etc/letsencrypt/live/<name>/cert.pem).
func List(certsDir string) ([]Cert, error) {
	matches, err := filepath.Glob(filepath.Join(certsDir, "live", "*", "cert.pem"))
	if err != nil {
		return nil, err
	}
	var certs []Cert
	for _, path := range matches {
		c, err := parseCert(path)
		if err != nil {
			continue // skip unreadable/README noise
		}
		certs = append(certs, c)
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].Name < certs[j].Name })
	return certs, nil
}

// Find returns the certificate for a domain/name, or nil.
func Find(certs []Cert, name string) *Cert {
	for i := range certs {
		if certs[i].Name == name {
			return &certs[i]
		}
		for _, d := range certs[i].Domains {
			if d == name {
				return &certs[i]
			}
		}
	}
	return nil
}

func parseCert(path string) (Cert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Cert{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return Cert{}, fmt.Errorf("%s: no PEM data", path)
	}
	der, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Cert{}, fmt.Errorf("%s: %w", path, err)
	}
	name := filepath.Base(filepath.Dir(path))
	return Cert{
		Name:     name,
		Domains:  der.DNSNames,
		NotAfter: der.NotAfter,
		Path:     path,
	}, nil
}

// CertPath returns the standard certbot fullchain path for a domain.
func CertPath(certsDir, domain string) string {
	return filepath.Join(certsDir, "live", domain, "fullchain.pem")
}

// KeyPath returns the standard certbot privkey path for a domain.
func KeyPath(certsDir, domain string) string {
	return filepath.Join(certsDir, "live", domain, "privkey.pem")
}

// Status formats expiry for display.
func Status(c Cert) string {
	days := c.DaysLeft()
	switch {
	case days < 0:
		return fmt.Sprintf("EXPIRED (%s)", c.NotAfter.Format("2006-01-02"))
	case days < 30:
		return fmt.Sprintf("expires in %d days (%s) — expiring soon", days, c.NotAfter.Format("2006-01-02"))
	default:
		return fmt.Sprintf("valid for %d days (until %s)", days, c.NotAfter.Format("2006-01-02"))
	}
}

// JoinDomains formats domains for display.
func JoinDomains(c Cert) string {
	return strings.Join(c.Domains, ", ")
}
