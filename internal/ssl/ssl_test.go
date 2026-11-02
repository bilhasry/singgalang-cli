package ssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir, name string, domains []string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     domains,
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certDir := filepath.Join(dir, "live", name)
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(certDir, "cert.pem"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestList(t *testing.T) {
	dir := t.TempDir()
	writeTestCert(t, dir, "example.com", []string{"example.com", "www.example.com"}, time.Now().Add(80*24*time.Hour))
	writeTestCert(t, dir, "soon.example.com", []string{"soon.example.com"}, time.Now().Add(10*24*time.Hour))

	certs, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs", len(certs))
	}
	// sorted by name
	if certs[0].Name != "example.com" {
		t.Errorf("first cert = %q", certs[0].Name)
	}
	if len(certs[0].Domains) != 2 {
		t.Errorf("domains = %v", certs[0].Domains)
	}
	if certs[0].DaysLeft() < 79 || certs[0].DaysLeft() > 81 {
		t.Errorf("days left = %d, want ~80", certs[0].DaysLeft())
	}
	if !strings.Contains(Status(certs[0]), "valid for") {
		t.Errorf("status = %q", Status(certs[0]))
	}
}

func TestFindAndStatus(t *testing.T) {
	certs := []Cert{
		{Name: "example.com", Domains: []string{"example.com", "www.example.com"}, NotAfter: time.Now().Add(80 * 24 * time.Hour)},
		{Name: "expired.com", Domains: []string{"expired.com"}, NotAfter: time.Now().Add(-24 * time.Hour)},
		{Name: "soon.com", Domains: []string{"soon.com"}, NotAfter: time.Now().Add(10 * 24 * time.Hour)},
	}
	if Find(certs, "example.com") == nil {
		t.Error("Find by name failed")
	}
	if Find(certs, "www.example.com") == nil {
		t.Error("Find by SAN failed")
	}
	if Find(certs, "nope.com") != nil {
		t.Error("Find should return nil")
	}
	if got := Status(certs[1]); !strings.HasPrefix(got, "EXPIRED") {
		t.Errorf("expired status = %q", got)
	}
	if got := Status(certs[2]); !strings.Contains(got, "expiring soon") {
		t.Errorf("soon status = %q", got)
	}
}

func TestPaths(t *testing.T) {
	if got := CertPath("/etc/letsencrypt", "a.com"); got != "/etc/letsencrypt/live/a.com/fullchain.pem" {
		t.Errorf("CertPath = %q", got)
	}
	if got := KeyPath("/etc/letsencrypt", "a.com"); got != "/etc/letsencrypt/live/a.com/privkey.pem" {
		t.Errorf("KeyPath = %q", got)
	}
}
