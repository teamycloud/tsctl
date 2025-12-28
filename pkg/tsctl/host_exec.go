package tsctl

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
	"github.com/teamycloud/tsctl/pkg/utils"
	"github.com/teamycloud/tsctl/pkg/utils/tlsconfig"
)

type CommandRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Envs    []string `json:"envs,omitempty"`
}

func NewHostExecCommand() *cobra.Command {
	var (
		serverAddr     string
		clientCertFile string
		clientKeyFile  string
		caCertFile     string
		insecure       bool
		envs           []string
	)

	cmd := &cobra.Command{
		Use:   "host-exec [flags] -- COMMAND [args...]",
		Short: "Execute a command on the container host",
		Long: `Execute a command on the container host server provided by tinyscale.

Use -- to separate ts flags from the command to execute and its arguments.

Example:
  tsctl host-exec --server=host:port -- ls -la
  tsctl host-exec --server=host:port --insecure -- bash -c "echo hello"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// At this point, args contains everything after "--"
			// Cobra automatically handles the "--" delimiter
			if len(args) == 0 {
				return fmt.Errorf("no command specified. Usage: tsctl host-exec [flags] -- COMMAND [args...]")
			}

			var tlsClientConfig *tls.Config
			var err error

			command := args[0]
			cmdArgs := args[1:]

			if clientCertFile != "" && clientKeyFile != "" {
				cfgBuilder := tlsconfig.NewTLSConfigBuilder().
					WithServerName(ts_tunnel.URLHostName(serverAddr)).
					WithClientCertificate(clientCertFile, clientKeyFile).
					WithCACertificate(caCertFile).
					WithInsecureSkipVerify(insecure)

				tlsClientConfig, err = cfgBuilder.Build()
				if err != nil {
					return fmt.Errorf("unable to build TLS configuration: %w", err)
				}
			}

			return executeCommand(serverAddr, command, cmdArgs, envs, tlsClientConfig)
		},
		Hidden: true, // this command is not for manual use
	}

	// Add flags
	cmd.Flags().StringVar(&serverAddr, "server-addr", "", "Server address (ip:port or hostname:port)")
	cmd.Flags().StringVar(&clientCertFile, "cert", "", "Client certificate file")
	cmd.Flags().StringVar(&clientKeyFile, "key", "", "Client key file")
	cmd.Flags().StringVar(&caCertFile, "ca", "", "CA certificate file")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Environment variable (can be repeated, format: KEY=VALUE)")

	cmd.MarkFlagRequired("server")

	return cmd
}

func executeCommand(serverAddr, command string, args []string, envs []string, tlsCfg *tls.Config) error {
	cmdReq := CommandRequest{
		Command: command,
		Args:    args,
		Envs:    envs,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(cmdReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal command request: %v\n", err)
		os.Exit(-1)
	}

	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/tinyscale/v1/host-exec/command", scheme, serverAddr)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		os.Exit(-1)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Upgrade", "tcp")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("User-Agent", "tsctl")

	// Create TLS config if needed
	var netConn net.Conn
	if tlsCfg != nil {
		// Manually dial with TLS
		conn, err := tls.Dial("tcp", serverAddr, tlsCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to server: %v\n", err)
			os.Exit(-1)
		}
		netConn = conn
	} else {
		// Dial without TLS
		conn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to connect to server: %v\n", err)
			os.Exit(-1)
		}
		netConn = conn
	}
	defer netConn.Close()

	// Write the HTTP request
	if err := req.Write(netConn); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write request: %v\n", err)
		os.Exit(-1)
	}

	// Read the response
	reader := bufio.NewReader(netConn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response: %v\n", err)
		os.Exit(-1)
	}

	// Check if connection was upgraded
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Failed to upgrade connection: %s - %s\n", resp.Status, string(body))
		os.Exit(-1)
	}

	if strings.ToLower(resp.Header.Get("Upgrade")) != "tcp" {
		fmt.Fprintf(os.Stderr, "Server did not upgrade to TCP\n")
		os.Exit(-1)
	}

	_ = utils.CopyWithSplitMerge(netConn, os.Stdin, os.Stdout)

	return nil
}
