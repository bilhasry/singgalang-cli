// Package firewall wraps ufw and understands which rules singgalang
// itself opened.
package firewall

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/system"
)

// Available reports whether ufw is installed.
func Available(r system.Runner) bool {
	return system.Available(r, "ufw")
}

// Rule is one parsed ufw status line.
type Rule struct {
	Port   int
	Proto  string
	From   string
	Action string
	V6     bool
}

// Active reports whether the ufw firewall is enabled.
func Active(r system.Runner) (bool, error) {
	out, err := r.Run("ufw", "status")
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(strings.TrimSpace(out), "Status: active"), nil
}

// Status parses `ufw status`.
func Status(r system.Runner) ([]Rule, error) {
	out, err := r.Run("ufw", "status")
	if err != nil {
		return nil, err
	}
	return ParseStatus(out), nil
}

// ParseStatus parses the textual output of `ufw status`.
func ParseStatus(out string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Status:") ||
			strings.HasPrefix(line, "To:") || strings.HasPrefix(line, "--") ||
			strings.HasPrefix(line, "Default:") || strings.HasPrefix(line, "Logging:") {
			continue
		}
		v6 := strings.HasSuffix(line, "(v6)")
		line = strings.TrimSuffix(line, "(v6)")
		line = strings.TrimSpace(line)

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[0] is the destination ("80/tcp", "8000:8100", "22"),
		// the action follows, then optionally "IN"/"OUT" and the source.
		rest := fields[1:]
		if len(rest) >= 2 && (rest[1] == "IN" || rest[1] == "OUT") {
			rest = append([]string{rest[0] + " " + rest[1]}, rest[2:]...)
		}
		action := rest[0]
		from := "Anywhere"
		if len(rest) > 1 {
			from = strings.Join(rest[1:], " ")
		}
		for _, target := range strings.Split(fields[0], ",") {
			port, proto := splitTarget(target)
			if port == 0 {
				continue // app profile names etc.
			}
			rules = append(rules, Rule{Port: port, Proto: proto, From: from, Action: action, V6: v6})
		}
	}
	return rules
}

func splitTarget(target string) (port int, proto string) {
	proto = "tcp"
	if i := strings.IndexByte(target, '/'); i >= 0 {
		proto = target[i+1:]
		target = target[:i]
	}
	if i := strings.IndexByte(target, ':'); i >= 0 {
		target = target[:i] // ranges: take the first port
	}
	p, err := strconv.Atoi(target)
	if err != nil {
		return 0, proto
	}
	return p, proto
}

// Has reports whether an allow rule for port/proto already exists.
func Has(rules []Rule, port int, proto string) bool {
	for _, rule := range rules {
		if rule.Port == port && rule.Proto == proto &&
			strings.HasPrefix(rule.Action, "ALLOW") {
			return true
		}
	}
	return false
}

// Open adds a ufw allow rule.
func Open(port int, proto, from string, r system.Runner) error {
	var target string
	if from != "" {
		target = fmt.Sprintf("from %s to any port %d proto %s", from, port, proto)
	} else {
		target = fmt.Sprintf("%d/%s", port, proto)
	}
	if _, err := r.Run("ufw", "allow", target); err != nil {
		return fmt.Errorf("opening port %d/%s: %w", port, proto, err)
	}
	return nil
}

// Close deletes a ufw allow rule without prompting (ufw --force).
func Close(port int, proto, from string, r system.Runner) error {
	var target string
	if from != "" {
		target = fmt.Sprintf("from %s to any port %d proto %s", from, port, proto)
	} else {
		target = fmt.Sprintf("%d/%s", port, proto)
	}
	if _, err := r.Run("ufw", "--force", "delete", "allow", target); err != nil {
		return fmt.Errorf("closing port %d/%s: %w", port, proto, err)
	}
	return nil
}
