package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("command line arguments are incorrect")
		}

		cmd.SilenceUsage = true
		fmt.Println(getVersion())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
