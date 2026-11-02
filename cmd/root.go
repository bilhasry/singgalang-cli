// Package cmd wires the singgalang CLI commands.
package cmd

import (
	"fmt"
	"os"

	"github.com/bilhasry/singgalang-cli/internal/state"
	"github.com/spf13/cobra"
)

// Version is the CLI version reported by --version.
const Version = "0.1.0"

var (
	forceFlag    bool
	dryFlag      bool
	stateDirFlag string
)

var rootCmd = &cobra.Command{
	Use:           "singgalang",
	Short:         "singgalang — one CLI to manage nginx, sites, SSL and firewall for your web services",
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if stateDirFlag != "" {
			state.SetDir(stateDirFlag)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&forceFlag, "force", false, "skip confirmation prompts")
	rootCmd.PersistentFlags().BoolVar(&dryFlag, "dry", false, "print what would be done without changing anything")
	rootCmd.PersistentFlags().StringVar(&stateDirFlag, "state-dir", "", "state directory (default ~/.singgalang)")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
