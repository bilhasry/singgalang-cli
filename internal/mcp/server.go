// Package mcp exposes singgalang's operations as MCP tools so an AI agent
// can manage nginx sites, SSL certificates and firewall ports.
//
// The server runs over stdio. All tools are thin wrappers over internal/ops,
// so behaviour is identical to the CLI. Tools never prompt; when an operation
// needs root the handler returns a NeedsRootError which surfaces as a tool
// error instructing the agent/operator to run singgalang with sufficient
// privileges.
package mcp

import (
	"context"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Server wraps the MCP server plus the operations it exposes.
type Server struct {
	*mcp.Server
	ops *ops.Ops
}

// New builds a singgalang MCP server with every tool registered.
func New(name, version string) *Server {
	o := ops.New()
	s := mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, nil)
	srv := &Server{Server: s, ops: o}

	srv.registerDetect()
	srv.registerInit()
	srv.registerSites()
	srv.registerSSL()
	srv.registerPorts()
	srv.registerReload()
	return srv
}

// Run serves MCP over stdio until the client disconnects or ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	return s.Server.Run(ctx, &mcp.StdioTransport{})
}

// ptr returns a pointer to b, for ToolAnnotations tri-state fields.
func ptr[T any](b T) *T { return &b }

// --- detect ---

type detectOut = ops.EnvReport

func (s *Server) registerDetect() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "detect_environment",
		Title:       "Detect environment",
		Description: "Detect the host environment: OS, nginx/docker/certbot/ufw/systemctl presence, current nginx mode, state directory and whether singgalang is running as root. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, detectOut, error) {
		return nil, s.ops.Detect(), nil
	})
}

// --- init ---

func (s *Server) registerInit() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "init",
		Title:       "Initialise singgalang",
		Description: "Detect the environment and write singgalang state. In docker mode this also creates the managed nginx config dir with nginx.conf and a docker-compose.yaml. Idempotent.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ops.InitInput) (*mcp.CallToolResult, *ops.InitResult, error) {
		res, err := s.ops.Init(in)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})
}

// --- sites ---

func (s *Server) registerSites() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "site_add",
		Title:       "Add site",
		Description: "Create a new site. Provide exactly one of: proxy ([host:]port to reverse-proxy, e.g. '3000'), root (absolute dir to serve statically), or container (docker container name whose published loopback port is discovered). Writes the nginx config, validates with nginx -t (rolling back on failure), opens firewall port 80 if needed, and reloads nginx. Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: false, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ops.SiteAddInput) (*mcp.CallToolResult, *ops.SiteAddResult, error) {
		res, err := s.ops.AddSite(in)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "site_list",
		Title:       "List sites",
		Description: "List configured sites with their kind (proxy/static), target, SSL status and whether they are enabled. Optionally filter by domain. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Domain string `json:"domain,omitempty" jsonschema:"optional domain to filter by"`
	}) (*mcp.CallToolResult, []ops.SiteInfo, error) {
		sites, err := s.ops.ListSites(in.Domain)
		if err != nil {
			return nil, nil, err
		}
		return nil, sites, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "site_remove",
		Title:       "Remove site",
		Description: "Delete a site's nginx config and reload nginx. If it was the last site, also closes firewall ports that singgalang itself opened. Destructive. Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Domain string `json:"domain" jsonschema:"domain of the site to remove"`
		DryRun bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done"`
	}) (*mcp.CallToolResult, *ops.SiteActionResult, error) {
		res, err := s.ops.RemoveSite(in.Domain, in.DryRun)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "site_set_enabled",
		Title:       "Enable or disable site",
		Description: "Enable or disable a site without deleting its config, then reload nginx. Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Domain  string `json:"domain" jsonschema:"domain of the site"`
		Enabled bool   `json:"enabled" jsonschema:"true to enable, false to disable"`
		DryRun  bool   `json:"dry_run,omitempty" jsonschema:"when true, only report what would be done"`
	}) (*mcp.CallToolResult, *ops.SiteActionResult, error) {
		res, err := s.ops.ToggleSite(in.Domain, in.Enabled, in.DryRun)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})
}

// --- ssl ---

func (s *Server) registerSSL() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "ssl_issue",
		Title:       "Issue SSL certificate",
		Description: "Obtain a Let's Encrypt certificate for an existing singgalang site using certbot's webroot mode, opens firewall port 443 if needed, switches the nginx config to HTTPS and reloads. Destructive (changes live TLS config). Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ops.SSLIssueInput) (*mcp.CallToolResult, *ops.SSLIssueResult, error) {
		res, err := s.ops.IssueSSL(in)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "ssl_list",
		Title:       "List certificates",
		Description: "List issued certificates with domains, expiry date, days remaining and status. Optionally filter by name or domain. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		Filter string `json:"filter,omitempty" jsonschema:"optional certificate name or domain to filter by"`
	}) (*mcp.CallToolResult, []ops.CertInfo, error) {
		certs, err := s.ops.ListCerts(in.Filter)
		if err != nil {
			return nil, nil, err
		}
		return nil, certs, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "ssl_renew",
		Title:       "Renew certificates",
		Description: "Renew all Let's Encrypt certificates with certbot. Set dry_run to perform certbot's own dry-run test instead of a real renewal. Destructive (renews live certificates).",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct {
		DryRun bool `json:"dry_run,omitempty" jsonschema:"when true, run certbot --dry-run instead of a real renewal"`
	}) (*mcp.CallToolResult, *ops.RenewResult, error) {
		res, err := s.ops.RenewCerts(in.DryRun, false)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})
}

// --- ports ---

func (s *Server) registerPorts() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "port_open",
		Title:       "Open firewall port",
		Description: "Open a TCP/UDP port in ufw (allow rule) and track it as singgalang-managed. Idempotent: if the rule already exists it is a no-op. Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{IdempotentHint: true, DestructiveHint: ptr(false), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ops.PortActionInput) (*mcp.CallToolResult, *ops.PortActionResult, error) {
		res, err := s.ops.OpenPort(in)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "port_close",
		Title:       "Close firewall port",
		Description: "Close a firewall port (delete the ufw allow rule). Refuses to close ports singgalang did not open unless force is true. Destructive. Set dry_run to preview.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, in ops.PortActionInput) (*mcp.CallToolResult, *ops.PortActionResult, error) {
		res, err := s.ops.ClosePort(in)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})

	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "port_list",
		Title:       "List firewall and Docker ports",
		Description: "List ufw firewall rules (marking which singgalang opened) and Docker-published ports, warning about Docker ports that bypass ufw. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *ops.PortsReport, error) {
		res, err := s.ops.ListPorts()
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})
}

// --- reload ---

func (s *Server) registerReload() {
	mcp.AddTool(s.Server, &mcp.Tool{
		Name:        "reload",
		Title:       "Validate and reload nginx",
		Description: "Validate the nginx config with nginx -t and reload nginx. Fails without reloading if the config is invalid. Destructive (affects live traffic routing).",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)},
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, *ops.ReloadResult, error) {
		res, err := s.ops.Reload()
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	})
}
