package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{Use: "detect"}

func Execute() {
	if rootCmd.Execute() != nil {
		os.Exit(1)
	}
}
