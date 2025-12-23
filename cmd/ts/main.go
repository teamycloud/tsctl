package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/teamycloud/remote-docker-agent/pkg/commands_ts"
)

var rootCmd = &cobra.Command{
	Use:   "ts",
	Short: "tinyscale - your container runtime on the cloud",
	Long:  `Utilities for managing and connecting container hosts on the tinyscale platform`,
}

func init() {
	// Add commands to root
	rootCmd.AddCommand(commands_ts.NewStartCommand())
	rootCmd.AddCommand(commands_ts.NewGuestExecCommand())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
