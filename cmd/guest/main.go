package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	commands_guest "github.com/teamycloud/tsctl/pkg/commands-guest"
)

func main() {
	var (
		port       int
		enableMTLS bool
		caCerts    string
		serverCert string
		serverKey  string
		allowedCNs string
	)

	rootCmd := &cobra.Command{
		Use:   "guest",
		Short: "Guest agent for remote command execution and file transfer",
		Run: func(cmd *cobra.Command, args []string) {
			config := &commands_guest.ServerConfig{
				Port:       port,
				EnableMTLS: enableMTLS,
			}

			// Parse mTLS configuration if enabled
			if enableMTLS {
				if caCerts == "" {
					fmt.Fprintf(os.Stderr, "Error: --ca-certs is required when mTLS is enabled\n")
					os.Exit(1)
				}
				if serverCert == "" {
					fmt.Fprintf(os.Stderr, "Error: --server-cert is required when mTLS is enabled\n")
					os.Exit(1)
				}
				if serverKey == "" {
					fmt.Fprintf(os.Stderr, "Error: --server-key is required when mTLS is enabled\n")
					os.Exit(1)
				}

				config.CACertPaths = parseCommaSeparated(caCerts)
				config.ServerCert = serverCert
				config.ServerKey = serverKey

				if allowedCNs != "" {
					config.AllowedCNs = parseCommaSeparated(allowedCNs)
				}
			}

			commands_guest.RunServerWithConfig(config)
		},
	}

	rootCmd.Flags().IntVarP(&port, "port", "p", 2090, "Port to listen on")
	rootCmd.Flags().BoolVar(&enableMTLS, "enable-mtls", false, "Enable mutual TLS authentication")
	rootCmd.Flags().StringVar(&caCerts, "ca-certs", "", "Comma-separated list of CA certificate paths for client verification")
	rootCmd.Flags().StringVar(&serverCert, "server-cert", "", "Server certificate path")
	rootCmd.Flags().StringVar(&serverKey, "server-key", "", "Server private key path")
	rootCmd.Flags().StringVar(&allowedCNs, "allowed-cns", "", "Comma-separated list of allowed client certificate CNs (optional, if empty all verified certs are allowed)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseCommaSeparated parses a comma-separated string into a slice
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
