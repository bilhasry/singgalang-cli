package cmd

import (
	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Validate nginx config (nginx -t) and reload it",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Plan pass reports the mode without touching anything.
		planRes, err := opsInstance.PlanReload()
		if err != nil {
			return err
		}
		plan("nginx -t (validate)")
		plan("reload nginx (%s mode)", planRes.Mode)
		if dryFlag {
			info("dry run: nothing was changed")
			return nil
		}
		if err := requireRoot(); err != nil {
			return err
		}
		res, err := opsInstance.Reload()
		if err != nil {
			return err
		}
		info("config ok, nginx reloaded (%s mode)", res.Mode)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}
