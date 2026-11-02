package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	singmcp "github.com/bilhasry/singgalang-cli/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the MCP server over stdio so an AI agent can manage the web server",
	Long: `Run the Model Context Protocol (MCP) server over stdio.

Configure your AI client (e.g. Claude Code, OpenCode) to launch:

    singgalang mcp

The server exposes tools for sites, SSL certificates and firewall ports.
Mutating tools require root when the operation touches system paths
(/etc/nginx, ufw, certbot); run the client or singgalang with sufficient
privileges, or the tool will return an error explaining what is needed.

Example client configuration (JSON):

    {
      "mcpServers": {
        "singgalang": {
          "command": "singgalang",
          "args": ["mcp"]
        }
      }
    }`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// MCP speaks JSON-RPC on stdio: log to stderr only.
		srv := singmcp.New("singgalang", Version)

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		return srv.Run(ctx)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
