package commands_ts

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type CommandRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Envs    []string `json:"envs,omitempty"`
}

type TLSConfig struct {
	clientCertFile string
	clientKeyFile  string
	caCertFile     string
	serverName     string
	insecure       bool
}

func NewGuestExecCommand() *cobra.Command {
	var (
		serverAddr     string
		clientCertFile string
		clientKeyFile  string
		caCertFile     string
		serverName     string
		insecure       bool
		envs           []string
	)

	cmd := &cobra.Command{
		Use:   "guest-exec [flags] -- COMMAND [args...]",
		Short: "Execute a command on the remote guest",
		Long: `Execute a command on the remote guest server via HTTP upgrade to TCP.

Use -- to separate ts flags from the command to execute and its arguments.

Example:
  ts guest-exec --server=host:port -- ls -la
  ts guest-exec --server=host:port --insecure -- bash -c "echo hello"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// At this point, args contains everything after "--"
			// Cobra automatically handles the "--" delimiter
			if len(args) == 0 {
				return fmt.Errorf("no command specified. Usage: ts guest-exec [flags] -- COMMAND [args...]")
			}

			command := args[0]
			cmdArgs := args[1:]

			tlsConfig := TLSConfig{
				clientCertFile: clientCertFile,
				clientKeyFile:  clientKeyFile,
				caCertFile:     caCertFile,
				serverName:     serverName,
				insecure:       insecure,
			}

			return executeCommand(serverAddr, command, cmdArgs, envs, tlsConfig)
		},
	}

	// Add flags
	cmd.Flags().StringVar(&serverAddr, "server", "", "Server address (ip:port or hostname:port)")
	cmd.Flags().StringVar(&clientCertFile, "cert", "", "Client certificate file")
	cmd.Flags().StringVar(&clientKeyFile, "key", "", "Client key file")
	cmd.Flags().StringVar(&caCertFile, "ca", "", "CA certificate file")
	cmd.Flags().StringVar(&serverName, "server-name", "", "Server name for TLS verification")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	cmd.Flags().StringArrayVarP(&envs, "env", "e", []string{}, "Environment variable (can be repeated, format: KEY=VALUE)")

	cmd.MarkFlagRequired("server")

	return cmd
}

func executeCommand(serverAddr, command string, args []string, envs []string, tlsCfg TLSConfig) error {
	// Create the command request
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

	// Determine if we should use TLS
	useTLS := tlsCfg.clientCertFile != "" || tlsCfg.caCertFile != "" || tlsCfg.insecure

	// Create the HTTP request
	var scheme string
	if useTLS {
		scheme = "https"
	} else {
		scheme = "http"
	}

	url := fmt.Sprintf("%s://%s/command", scheme, serverAddr)
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		os.Exit(-1)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Upgrade", "tcp")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("User-Agent", "ts")

	// Create TLS config if needed
	var netConn net.Conn
	if useTLS {
		tlsClientConfig, err := buildTLSConfig(tlsCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to build TLS config: %v\n", err)
			os.Exit(-1)
		}

		// Manually dial with TLS
		conn, err := tls.Dial("tcp", serverAddr, tlsClientConfig)
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

	// Connection is now upgraded to TCP
	// Copy stdin to connection and connection to Stderr
	errCh := make(chan error, 2)

	// Copy stdin to connection
	go func() {
		_, err := io.Copy(netConn, os.Stdin)
		errCh <- err
	}()

	// Copy connection to Stderr
	go func() {
		_, err := io.Copy(os.Stdout, netConn)
		errCh <- err
	}()

	// Wait for either goroutine to finish
	<-errCh

	return nil
}

func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.insecure,
	}

	// Set server name if provided
	if cfg.serverName != "" {
		tlsConfig.ServerName = cfg.serverName
	}

	// Load client certificate if provided
	if cfg.clientCertFile != "" && cfg.clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.clientCertFile, cfg.clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if cfg.caCertFile != "" {
		caCert, err := os.ReadFile(cfg.caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}
