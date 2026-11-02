// Package system provides shell-out helpers, environment detection and
// privilege handling for singgalang.
package system

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner executes external commands. A fake implementation can be
// substituted in tests.
type Runner interface {
	Run(name string, args ...string) (string, error)
	LookPath(name string) (string, error)
}

// CommandError wraps a failed external command with its output.
type CommandError struct {
	Name   string
	Args   []string
	Output string
	Err    error
}

func (e *CommandError) Error() string {
	cmd := strings.Join(append([]string{e.Name}, e.Args...), " ")
	if e.Output != "" {
		return fmt.Sprintf("%s: %v\n%s", cmd, e.Err, e.Output)
	}
	return fmt.Sprintf("%s: %v", cmd, e.Err)
}

func (e *CommandError) Unwrap() error { return e.Err }

// ExecRunner is the default Runner backed by os/exec.
type ExecRunner struct{}

func (ExecRunner) Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(out)
		}
		return out, &CommandError{Name: name, Args: args, Output: msg, Err: err}
	}
	return out, nil
}

func (ExecRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Default is the process-wide runner.
var Default Runner = ExecRunner{}

// Available reports whether the named binary is on PATH.
func Available(r Runner, name string) bool {
	_, err := r.LookPath(name)
	return err == nil
}

// IsRoot reports whether the process runs with effective uid 0.
func IsRoot() bool {
	return os.Geteuid() == 0
}

// EnsureRoot guarantees root privileges for the current invocation.
// When not root it re-executes the CLI under sudo, passing the state dir
// explicitly so the elevated process works on the same state.
func EnsureRoot(stateDir string) error {
	if IsRoot() {
		return nil
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("root privileges are required; run this command as root or install sudo")
	}
	abs, err := filepath.Abs(os.Args[0])
	if err != nil {
		abs = os.Args[0]
	}
	childArgs := os.Args[1:]
	if !hasStateDirFlag(childArgs) {
		childArgs = append([]string{"--state-dir=" + stateDir}, childArgs...)
	}
	fmt.Fprintln(os.Stderr, "singgalang: root privileges required, requesting sudo...")
	cmd := exec.Command(sudo, append([]string{abs}, childArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("sudo failed (exit %d)", ee.ExitCode())
		}
		return fmt.Errorf("failed to elevate via sudo: %w", err)
	}
	// The child re-ran the whole command as root; we are done.
	os.Exit(0)
	return nil
}

func hasStateDirFlag(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "--state-dir=") {
			return true
		}
	}
	return false
}

// Env describes the detected host environment.
type Env struct {
	OSName       string
	OSPretty     string
	NginxBinary  string // path if found
	NginxConfDir bool
	Docker       string
	Certbot      string
	Ufw          string
	Systemctl    string
}

// Detect inspects the host for singgalang's dependencies.
func Detect(r Runner) Env {
	var e Env
	e.OSName, e.OSPretty = readOSRelease()
	if p, err := r.LookPath("nginx"); err == nil {
		e.NginxBinary = p
	}
	if _, err := os.Stat("/etc/nginx"); err == nil {
		e.NginxConfDir = true
	}
	if p, err := r.LookPath("docker"); err == nil {
		e.Docker = p
	}
	if p, err := r.LookPath("certbot"); err == nil {
		e.Certbot = p
	}
	if p, err := r.LookPath("ufw"); err == nil {
		e.Ufw = p
	}
	if p, err := r.LookPath("systemctl"); err == nil {
		e.Systemctl = p
	}
	return e
}

func readOSRelease() (id, pretty string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown", "unknown"
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		case strings.HasPrefix(line, "PRETTY_NAME="):
			pretty = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	if id == "" {
		id = "unknown"
	}
	if pretty == "" {
		pretty = "unknown"
	}
	return id, pretty
}
