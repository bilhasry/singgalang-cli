// Package docker wraps the docker CLI: container inspection and port
// discovery for proxy targets.
package docker

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/system"
)

// Available reports whether the docker CLI is installed.
func Available(r system.Runner) bool {
	return system.Available(r, "docker")
}

// Binding is one published port of a container.
type Binding struct {
	ContainerPort int
	Proto         string
	HostIP        string
	HostPort      int
}

// Exposed reports whether the binding faces the public interface
// (i.e. bypasses ufw).
func (b Binding) Exposed() bool {
	return b.HostIP != "127.0.0.1" && b.HostIP != "::1" && b.HostIP != "localhost"
}

// Container is the subset of docker inspect singgalang needs.
type Container struct {
	Name     string
	Running  bool
	Bindings []Binding
}

type inspectResult struct {
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

// Inspect looks up a single container by name or id.
func Inspect(name string, r system.Runner) (*Container, error) {
	out, err := r.Run("docker", "inspect", name)
	if err != nil {
		return nil, fmt.Errorf("inspecting container %q: %w", name, err)
	}
	list, err := parseInspect(out)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("container %q not found", name)
	}
	return list[0], nil
}

// ListRunning returns all running containers with their bindings.
func ListRunning(r system.Runner) ([]*Container, error) {
	ids, err := r.Run("docker", "ps", "-q")
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}
	ids = strings.TrimSpace(ids)
	if ids == "" {
		return nil, nil
	}
	inspectArgs := append([]string{"inspect"}, strings.Fields(ids)...)
	out, err := r.Run("docker", inspectArgs...)
	if err != nil {
		return nil, fmt.Errorf("inspecting containers: %w", err)
	}
	return parseInspect(out)
}

func parseInspect(out string) ([]*Container, error) {
	var results []inspectResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		return nil, fmt.Errorf("parsing docker inspect output: %w", err)
	}
	var containers []*Container
	for _, res := range results {
		c := &Container{
			Name:    strings.TrimPrefix(res.Name, "/"),
			Running: res.State.Running,
		}
		for portProto, bindings := range res.HostConfig.PortBindings {
			containerPort, proto := splitPortProto(portProto)
			for _, b := range bindings {
				hostPort := 0
				fmt.Sscanf(b.HostPort, "%d", &hostPort)
				if hostPort == 0 {
					continue // not published
				}
				c.Bindings = append(c.Bindings, Binding{
					ContainerPort: containerPort,
					Proto:         proto,
					HostIP:        b.HostIP,
					HostPort:      hostPort,
				})
			}
		}
		sort.Slice(c.Bindings, func(i, j int) bool {
			if c.Bindings[i].ContainerPort != c.Bindings[j].ContainerPort {
				return c.Bindings[i].ContainerPort < c.Bindings[j].ContainerPort
			}
			return c.Bindings[i].HostPort < c.Bindings[j].HostPort
		})
		containers = append(containers, c)
	}
	return containers, nil
}

func splitPortProto(s string) (int, string) {
	proto := "tcp"
	if i := strings.IndexByte(s, '/'); i >= 0 {
		proto = s[i+1:]
		s = s[:i]
	}
	port := 0
	fmt.Sscanf(s, "%d", &port)
	return port, proto
}
