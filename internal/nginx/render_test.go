package nginx

import (
	"strings"
	"testing"
)

func TestRenderProxy(t *testing.T) {
	out, err := Render(SiteSpec{Domain: "api.example.com", Kind: "proxy", Target: "127.0.0.1:3000"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"server_name api.example.com;",
		"proxy_pass http://127.0.0.1:3000;",
		"root /var/www/certbot;",
		"listen 80;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ssl_certificate") {
		t.Error("HTTP-only config must not contain ssl_certificate")
	}
}

func TestRenderStatic(t *testing.T) {
	out, err := Render(SiteSpec{Domain: "www.example.com", Kind: "static", Target: "/srv/www"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "root /srv/www;") {
		t.Errorf("missing static root:\n%s", out)
	}
	if strings.Contains(out, "proxy_pass") {
		t.Error("static config must not contain proxy_pass")
	}
}

func TestRenderSSL(t *testing.T) {
	out, err := Render(SiteSpec{Domain: "api.example.com", Kind: "proxy", Target: "127.0.0.1:3000", SSL: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"listen 443 ssl;",
		"ssl_certificate     /etc/letsencrypt/live/api.example.com/fullchain.pem;",
		"ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;",
		"return 301 https://$host$request_uri;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// the ACME location must exist in both the redirect and SSL blocks
	if got := strings.Count(out, "location /.well-known/acme-challenge/"); got != 2 {
		t.Errorf("ACME location appears %d times, want 2", got)
	}
}

func TestRenderBadKind(t *testing.T) {
	if _, err := Render(SiteSpec{Domain: "x", Kind: "weird", Target: "y"}); err == nil {
		t.Error("expected error for unknown kind")
	}
}

func TestFileNameRoundTrip(t *testing.T) {
	name := FileName("api.example.com")
	if name != "singgalang-api.example.com.conf" {
		t.Errorf("FileName = %q", name)
	}
	if got := DomainFromFileName(name); got != "api.example.com" {
		t.Errorf("DomainFromFileName = %q", got)
	}
	if got := DomainFromFileName("singgalang-api.example.com.conf.disabled"); got != "api.example.com" {
		t.Errorf("DomainFromFileName(disabled) = %q", got)
	}
}
