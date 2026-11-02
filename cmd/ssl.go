package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/spf13/cobra"
)

var (
	sslDomain string
	sslEmail  string
)

var sslCmd = &cobra.Command{
	Use:   "ssl",
	Short: "Manage TLS certificates (issue, list, renew)",
}

// --- issue ---

var sslIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a Let's Encrypt certificate for a site",
	RunE: func(cmd *cobra.Command, args []string) error {
		if sslDomain == "" {
			return fmt.Errorf("--domain is required")
		}

		// First pass: plan only (no changes).
		planRes, err := opsInstance.IssueSSL(ops.SSLIssueInput{Domain: sslDomain, Email: sslEmail, DryRun: true})
		if err != nil {
			return err
		}
		fmt.Printf("ssl for %s\n", sslDomain)
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		for _, n := range planRes.Warnings {
			warn("%s", n)
		}
		if dryFlag {
			info("dry run: nothing was changed")
			return nil
		}

		if err := requireRoot(); err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("Issue a certificate for %s?", sslDomain))
		if err != nil {
			return err
		}
		if !ok {
			info("aborted")
			return nil
		}

		email := sslEmail
		if email == "" && isInteractive() {
			fmt.Print("email for Let's Encrypt expiration notices: ")
			email, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			email = strings.TrimSpace(email)
		}
		res, err := opsInstance.IssueSSL(ops.SSLIssueInput{Domain: sslDomain, Email: email, DryRun: false})
		if err != nil {
			return err
		}
		for _, n := range res.Warnings {
			warn("%s", n)
		}
		if res.Reloaded {
			info("nginx reloaded — https://%s is live", sslDomain)
		}
		return nil
	},
}

// --- list ---

var sslListCmd = &cobra.Command{
	Use:   "list",
	Short: "List issued certificates and their expiry",
	RunE: func(cmd *cobra.Command, args []string) error {
		certs, err := opsInstance.ListCerts(sslDomain)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			fmt.Println("no certificates found")
			return nil
		}
		fmt.Printf("%-30s %-40s %s\n", "NAME", "DOMAINS", "STATUS")
		for _, c := range certs {
			fmt.Printf("%-30s %-40s %s\n", c.Name, truncate(strings.Join(c.Domains, ", "), 40), c.Status)
			if c.DaysLeft < 30 {
				warn("%s expires in %d days — renew with 'singgalang ssl renew'", c.Name, c.DaysLeft)
			}
		}
		return nil
	},
}

// --- renew ---

var sslRenewCmd = &cobra.Command{
	Use:   "renew",
	Short: "Renew all certificates (add --dry to test with certbot --dry-run)",
	RunE: func(cmd *cobra.Command, args []string) error {
		planRes, err := opsInstance.RenewCerts(dryFlag, true)
		if err != nil {
			return err
		}
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		if dryFlag {
			info("running certbot renew --dry-run...")
		} else {
			if err := requireRoot(); err != nil {
				return err
			}
			ok, err := confirm("Renew all certificates?")
			if err != nil {
				return err
			}
			if !ok {
				info("aborted")
				return nil
			}
		}
		planRes, err = opsInstance.RenewCerts(dryFlag, false)
		if err != nil {
			return err
		}
		if planRes.Output != "" {
			fmt.Println(planRes.Output)
		}
		return nil
	},
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func init() {
	sslIssueCmd.Flags().StringVar(&sslDomain, "domain", "", "domain of the site (required)")
	sslIssueCmd.Flags().StringVar(&sslEmail, "email", "", "Let's Encrypt registration email")
	sslListCmd.Flags().StringVar(&sslDomain, "domain", "", "filter by domain")
	sslCmd.AddCommand(sslIssueCmd, sslListCmd, sslRenewCmd)
	rootCmd.AddCommand(sslCmd)
}
