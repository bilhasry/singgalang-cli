package nginx

import (
	"bytes"
	"fmt"
	"path/filepath"
	"text/template"

	"github.com/bilhasry/singgalang-cli/templates"
)

var siteTmpl = template.Must(template.ParseFS(templates.FS, "site.tmpl"))

// Render renders a site config from the embedded template. Certificate
// paths default to the standard certbot layout.
func Render(spec SiteSpec) (string, error) {
	if spec.Webroot == "" {
		spec.Webroot = "/var/www/certbot"
	}
	if spec.SSL {
		if spec.CertPath == "" {
			spec.CertPath = filepath.Join("/etc/letsencrypt/live", spec.Domain, "fullchain.pem")
		}
		if spec.KeyPath == "" {
			spec.KeyPath = filepath.Join("/etc/letsencrypt/live", spec.Domain, "privkey.pem")
		}
	}
	if spec.Kind != "proxy" && spec.Kind != "static" {
		return "", fmt.Errorf("unknown site kind %q (want proxy or static)", spec.Kind)
	}
	var buf bytes.Buffer
	if err := siteTmpl.Execute(&buf, spec); err != nil {
		return "", fmt.Errorf("rendering config for %s: %w", spec.Domain, err)
	}
	return buf.String(), nil
}

// RenderNginxConf renders the top-level nginx.conf (docker mode).
func RenderNginxConf() (string, error) {
	data, err := templates.FS.ReadFile("nginx.conf.tmpl")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ComposeData feeds the docker-compose template.
type ComposeData struct {
	ContainerName string
	ConfDir       string
	Webroot       string
	CertsDir      string
}

// RenderCompose renders the docker-compose file (docker mode).
func RenderCompose(d ComposeData) (string, error) {
	t := template.Must(template.ParseFS(templates.FS, "docker-compose.tmpl"))
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", fmt.Errorf("rendering compose file: %w", err)
	}
	return buf.String(), nil
}
