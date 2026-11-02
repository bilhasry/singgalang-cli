// Package templates holds singgalang's embedded configuration templates.
package templates

import "embed"

//go:embed *.tmpl
var FS embed.FS
