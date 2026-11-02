package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/bilhasry/singgalang-cli/internal/system"
)

// opsInstance is the shared operations core used by every command and by the
// MCP server.
var opsInstance = ops.New()

// isInteractive reports whether stdin is a terminal.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// confirm asks the user for confirmation; --force skips the prompt.
func confirm(prompt string) (bool, error) {
	if forceFlag {
		return true, nil
	}
	if !isInteractive() {
		return false, fmt.Errorf("confirmation required; re-run with --force to proceed")
	}
	fmt.Printf("%s [y/N]: ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// plan prints a planned action line.
func plan(format string, a ...interface{}) {
	fmt.Printf("  plan: "+format+"\n", a...)
}

// info prints a status line.
func info(format string, a ...interface{}) {
	fmt.Printf("  "+format+"\n", a...)
}

// warn prints a warning line.
func warn(format string, a ...interface{}) {
	fmt.Printf("  warning: "+format+"\n", a...)
}

// requireRoot elevates the process when needed.
func requireRoot() error {
	return system.EnsureRoot(stateDir())
}

// stateDir resolves the state directory for elevation.
func stateDir() string {
	return ops.StateDir()
}
