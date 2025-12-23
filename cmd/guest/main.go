package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/teamycloud/remote-docker-agent/pkg/commands_guest"
)

func main() {
	var port int

	rootCmd := &cobra.Command{
		Use:   "guest",
		Short: "Guest agent for remote command execution and file transfer",
		Run: func(cmd *cobra.Command, args []string) {
			commands_guest.RunServer(port)
		},
	}

	rootCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
