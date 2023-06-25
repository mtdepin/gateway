package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "all server status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("command line arguments are incorrect")
		}

		cmd.SilenceUsage = true

		return nil
	},
}

func init() {
	rootCmd.AddCommand(allCmd)
}
