package cmd

import (
	"fmt"

	"github.com/bilhasry/singgalang-cli/internal/ops"
	"github.com/spf13/cobra"
)

var (
	initNginxMode     string
	initEmail         string
	initWebroot       string
	initContainerName string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Detect the environment and set up singgalang state",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Print the environment report first.
		env := opsInstance.Detect()
		fmt.Println("singgalang environment")
		fmt.Printf("  os           %s (%s)\n", env.OSPretty, env.OS)
		fmt.Printf("  nginx        %s\n", orNot(env.NginxBinary))
		fmt.Printf("  nginx conf   %s\n", yesNo(env.NginxConfDir, "/etc/nginx"))
		fmt.Printf("  docker       %s\n", orNot(env.Docker))
		fmt.Printf("  certbot      %s\n", orNot(env.Certbot))
		fmt.Printf("  ufw          %s\n", orNot(env.Ufw))
		fmt.Printf("  systemctl    %s\n", orNot(env.Systemctl))
		fmt.Println()

		in := ops.InitInput{
			NginxMode:     initNginxMode,
			Email:         initEmail,
			Webroot:       initWebroot,
			ContainerName: initContainerName,
			DryRun:        true,
		}
		planRes, err := opsInstance.Init(in)
		if err != nil {
			return err
		}
		for _, p := range planRes.Plan {
			plan("%s", p)
		}
		if planRes.Env.NginxMode != initNginxMode && (initNginxMode == "auto" || initNginxMode == "") {
			info("detected nginx mode: %s", planRes.Env.NginxMode)
		}
		if planRes.Started != "" {
			fmt.Println()
			fmt.Println("  start the nginx container with:")
			fmt.Printf("    %s\n", planRes.Started)
		}
		if dryFlag {
			info("dry run: state not written")
			return nil
		}

		in.DryRun = false
		res, err := opsInstance.Init(in)
		if err != nil {
			return err
		}
		info("state written")
		_ = res
		return nil
	},
}

func orNot(path string) string {
	if path == "" {
		return "not found"
	}
	return path
}

func yesNo(ok bool, yes string) string {
	if ok {
		return yes
	}
	return "not found"
}

func init() {
	initCmd.Flags().StringVar(&initNginxMode, "nginx-mode", "auto", "where nginx runs: auto, host or docker")
	initCmd.Flags().StringVar(&initEmail, "email", "", "email used for Let's Encrypt registration")
	initCmd.Flags().StringVar(&initWebroot, "webroot", "/var/www/certbot", "ACME webroot directory")
	initCmd.Flags().StringVar(&initContainerName, "container-name", "singgalang-nginx", "nginx container name (docker mode)")
	rootCmd.AddCommand(initCmd)
}
