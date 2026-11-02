package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/spf13/cobra"
)

var (
	portNumber int
	portProto  string
	portFrom   string
)

var portCmd = &cobra.Command{
	Use:   "port",
	Short: "Manage firewall ports (open, close, list)",
}

// --- open ---

var portOpenCmd = &cobra.Command{
	Use:   "open",
	Short: "Open a port in ufw",
	RunE: func(cmd *cobra.Command, args []string) error {
		in := ops.PortActionInput{
			Port: portNumber, Proto: portProto, From: portFrom, DryRun: true,
		}
		planRes, err := opsInstance.OpenPort(in)
		if err != nil {
			return err
		}
		fmt.Println("firewall")
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		if dryFlag {
			info("dry run: nothing was changed")
			return nil
		}
		if err := requireRoot(); err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("Open port %d/%s?", portNumber, normalizeProto(portProto)))
		if err != nil {
			return err
		}
		if !ok {
			info("aborted")
			return nil
		}
		in.DryRun = false
		res, err := opsInstance.OpenPort(in)
		if err != nil {
			return err
		}
		if res.Noop {
			info("%s", res.Message)
			return nil
		}
		info("opened port %d/%s (tracked as singgalang-managed)", res.Port, res.Proto)
		return nil
	},
}

// --- close ---

var portCloseCmd = &cobra.Command{
	Use:   "close",
	Short: "Close a port in ufw (only singgalang-managed rules unless --force)",
	RunE: func(cmd *cobra.Command, args []string) error {
		in := ops.PortActionInput{
			Port: portNumber, Proto: portProto, From: portFrom, Force: forceFlag, DryRun: true,
		}
		planRes, err := opsInstance.ClosePort(in)
		if err != nil {
			return err
		}
		fmt.Println("firewall")
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		if dryFlag {
			info("dry run: nothing was changed")
			return nil
		}
		if err := requireRoot(); err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("Close port %d/%s?", portNumber, normalizeProto(portProto)))
		if err != nil {
			return err
		}
		if !ok {
			info("aborted")
			return nil
		}
		in.DryRun = false
		res, err := opsInstance.ClosePort(in)
		if err != nil {
			return err
		}
		if res.Noop {
			info("%s", res.Message)
			return nil
		}
		info("closed port %d/%s", res.Port, res.Proto)
		return nil
	},
}

// --- list ---

var portListCmd = &cobra.Command{
	Use:   "list",
	Short: "List ufw rules and Docker-published ports",
	RunE: func(cmd *cobra.Command, args []string) error {
		rep, err := opsInstance.ListPorts()
		if err != nil {
			return err
		}

		fmt.Println("firewall (ufw)")
		if !rep.FirewallActive {
			fmt.Println("  status: inactive or ufw unavailable (rules stored but not enforced)")
		} else if len(rep.FirewallRules) == 0 {
			fmt.Println("  no rules")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 4, 4, 2, ' ', 0)
			fmt.Fprintln(w, "  TO\tACTION\tFROM\tMANAGED")
			for _, r := range rep.FirewallRules {
				to := fmt.Sprintf("%d/%s", r.Port, r.Proto)
				managed := r.Managed
				if managed == "" {
					managed = "-"
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", to, r.Action, r.From, managed)
			}
			w.Flush()
		}

		fmt.Println()
		fmt.Println("docker published ports")
		if len(rep.DockerPorts) == 0 {
			fmt.Println("  none published")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 4, 4, 2, ' ', 0)
			fmt.Fprintln(w, "  CONTAINER\tBIND\tPORT\tRISK")
			for _, d := range rep.DockerPorts {
				fmt.Fprintf(w, "  %s\t%s\t%d/%s\t%s\n", d.Container, d.Bind, d.ContainerPort, d.Proto, d.Risk)
			}
			w.Flush()
		}
		for _, warnMsg := range rep.Warnings {
			warn("%s", warnMsg)
		}
		return nil
	},
}

func normalizeProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

func init() {
	portOpenCmd.Flags().IntVar(&portNumber, "port", 0, "port number (required)")
	portOpenCmd.Flags().StringVar(&portProto, "proto", "tcp", "protocol: tcp or udp")
	portOpenCmd.Flags().StringVar(&portFrom, "from", "", "restrict source CIDR (e.g. 10.0.0.0/8)")

	portCloseCmd.Flags().IntVar(&portNumber, "port", 0, "port number (required)")
	portCloseCmd.Flags().StringVar(&portProto, "proto", "tcp", "protocol: tcp or udp")
	portCloseCmd.Flags().StringVar(&portFrom, "from", "", "source CIDR the rule was opened with")

	portCmd.AddCommand(portOpenCmd, portCloseCmd, portListCmd)
	rootCmd.AddCommand(portCmd)
}
