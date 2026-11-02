package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/spf13/cobra"
)

var (
	siteDomain    string
	siteProxy     string
	siteRoot      string
	siteContainer string
)

var siteCmd = &cobra.Command{
	Use:   "site",
	Short: "Manage virtual hosts (add, list, remove, enable, disable)",
}

// --- add ---

var siteAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Create a new site (reverse proxy or static)",
	RunE: func(cmd *cobra.Command, args []string) error {
		in := ops.SiteAddInput{
			Domain:    siteDomain,
			Proxy:     siteProxy,
			Root:      siteRoot,
			Container: siteContainer,
			DryRun:    true, // first pass: build plan without changing anything
		}
		planRes, err := opsInstance.AddSite(in)
		if err != nil {
			return err
		}

		fmt.Printf("site %s\n", siteDomain)
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		for _, n := range planRes.Warnings {
			warn("%s", n)
		}
		if dryFlag {
			fmt.Println("\n--- rendered config ---")
			fmt.Print(planRes.Config)
			info("dry run: nothing was changed")
			return nil
		}

		// Elevate before confirming so sudo's re-exec does not prompt twice.
		if needsRootForSite(planRes) {
			if err := requireRoot(); err != nil {
				return err
			}
		}
		ok, err := confirm(fmt.Sprintf("Apply changes for %s?", siteDomain))
		if err != nil {
			return err
		}
		if !ok {
			info("aborted")
			return nil
		}

		in.DryRun = false
		res, err := opsInstance.AddSite(in)
		if err != nil {
			return err
		}
		info("wrote %s", res.ConfigPath)
		for _, n := range res.Warnings {
			warn("%s", n)
		}
		if res.Reloaded {
			info("nginx reloaded — site %s is live", siteDomain)
		}
		return nil
	},
}

// needsRootForSite reports whether the add plan touches host paths/firewall,
// which require root.
func needsRootForSite(r *ops.SiteAddResult) bool {
	return r.NeedsRoot
}

// --- list ---

var siteListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured sites",
	RunE: func(cmd *cobra.Command, args []string) error {
		sites, err := opsInstance.ListSites(siteDomain)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "DOMAIN\tKIND\tTARGET\tSSL\tENABLED")
		for _, s := range sites {
			enabled := "no"
			if s.Enabled {
				enabled = "yes"
			}
			sslCol := "-"
			if s.SSL {
				sslCol = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Domain, s.Kind, s.Target, sslCol, enabled)
		}
		w.Flush()
		if len(sites) == 0 {
			if siteDomain != "" {
				fmt.Printf("no site matching %s\n", siteDomain)
			} else {
				fmt.Println("no sites configured — add one with 'singgalang site add'")
			}
		}
		return nil
	},
}

// --- remove ---

var siteRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a site",
	RunE: func(cmd *cobra.Command, args []string) error {
		planRes, err := opsInstance.RemoveSite(siteDomain, true)
		if err != nil {
			return err
		}
		fmt.Printf("remove site %s\n", siteDomain)
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
		ok, err := confirm(fmt.Sprintf("Remove %s?", siteDomain))
		if err != nil {
			return err
		}
		if !ok {
			info("aborted")
			return nil
		}
		res, err := opsInstance.RemoveSite(siteDomain, false)
		if err != nil {
			return err
		}
		for _, p := range res.ClosedPorts {
			info("closed firewall port %d", p)
		}
		if res.Reloaded {
			info("nginx reloaded")
		}
		return nil
	},
}

// --- enable / disable ---

var siteEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable a disabled site",
	RunE: func(cmd *cobra.Command, args []string) error {
		return toggleSite(true)
	},
}

var siteDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable a site without deleting it",
	RunE: func(cmd *cobra.Command, args []string) error {
		return toggleSite(false)
	},
}

func toggleSite(enable bool) error {
	verb := "disable"
	if enable {
		verb = "enable"
	}
	planRes, err := opsInstance.ToggleSite(siteDomain, enable, true)
	if err != nil {
		return err
	}
	fmt.Printf("%s site %s\n", verb, siteDomain)
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
	ok, err := confirm(fmt.Sprintf("%s %s?", capitalize(verb), siteDomain))
	if err != nil {
		return err
	}
	if !ok {
		info("aborted")
		return nil
	}
	res, err := opsInstance.ToggleSite(siteDomain, enable, false)
	if err != nil {
		return err
	}
	if res.Reloaded {
		info("nginx reloaded — site %s is now %sd", siteDomain, verb)
	}
	return nil
}

// capitalize upper-cases the first letter of s.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func init() {
	siteAddCmd.Flags().StringVar(&siteDomain, "domain", "", "site domain name (required)")
	siteAddCmd.Flags().StringVar(&siteProxy, "proxy", "", "reverse proxy target, [host:]port (e.g. 3000)")
	siteAddCmd.Flags().StringVar(&siteRoot, "root", "", "static files root directory (absolute path)")
	siteAddCmd.Flags().StringVar(&siteContainer, "container", "", "docker container to discover the proxy port from")
	siteListCmd.Flags().StringVar(&siteDomain, "domain", "", "filter by domain")
	siteRemoveCmd.Flags().StringVar(&siteDomain, "domain", "", "domain of the site to remove (required)")
	siteEnableCmd.Flags().StringVar(&siteDomain, "domain", "", "domain of the site to enable (required)")
	siteDisableCmd.Flags().StringVar(&siteDomain, "domain", "", "domain of the site to disable (required)")

	siteCmd.AddCommand(siteAddCmd, siteListCmd, siteRemoveCmd, siteEnableCmd, siteDisableCmd)
	rootCmd.AddCommand(siteCmd)
}
