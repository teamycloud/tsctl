package agent_transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mutagen-io/mutagen/pkg/agent"
	"github.com/mutagen-io/mutagen/pkg/agent/transport"
)

const (
	// upgradeTimeout is the maximum time to wait for the HTTP UPGRADE to complete.
	upgradeTimeout = 30 * time.Second
	// commandTimeout is the maximum time to wait for a command response.
	commandTimeout = 60 * time.Second
)

// tstunnelTransport implements the agent.Transport interface using mTLS-enabled TCP connections.
type tstunnelTransport struct {
	// serverAddr is the HTTPS serverAddr to connect to (e.g., "containers.tinyscale.net:443").
	serverAddr string
	// serverName is the remote host identifier used in SNI (optional).
	serverName string
	// certFile is the path to the client certificate file.
	certFile string
	// keyFile is the path to the client key file.
	keyFile string
	// caFile is the path to the CA certificate file (optional).
	caFile string

	insecure bool

	tlsConfig *tls.Config
	// prompter is the prompter identifier to use for prompting.
	prompter string
}

// TransportOptions provides configuration options for creating a tstunnel transport.
type TransportOptions struct {
	// ServerAddr is the HTTPS serverAddr to connect to (host:port).
	ServerAddr string
	// ServerName is the remote host identifier for SNI routing.(optional)
	ServerName string
	// CertFile is the path to the client certificate file.
	CertFile string
	// KeyFile is the path to the client key file.
	KeyFile string
	// CAFile is the path to the CA certificate file (optional).
	CAFile string

	Insecure bool

	// Prompter is the prompter identifier.
	Prompter string
}

// NewTransport creates a new tstunnel transport using the specified options.
func NewTransport(opts TransportOptions) (agent.Transport, error) {
	var tlsCfg *tls.Config
	var err error

	// Validate required options.
	if opts.ServerAddr == "" {
		return nil, errors.New("ServerAddr is required")
	}

	// TLSConfig is optional. If provided, ensure SNI is set correctly.
	if opts.ServerName == "" {
		// Construct SNI from serverName and serverAddr domain.
		host, _, err := net.SplitHostPort(opts.ServerAddr)
		if err != nil {
			// If no port, use the serverAddr as-is.
			host = opts.ServerAddr
		}
		opts.ServerName = host
	}

	if opts.CertFile != "" && opts.KeyFile != "" {
		tlsCfgBuilder := NewTLSConfigBuilder()
		tlsCfgBuilder.
			WithServerName(opts.ServerName).
			WithClientCertificate(opts.CertFile, opts.KeyFile).
			WithCACertificate(opts.CAFile)
		if opts.Insecure {
			tlsCfgBuilder.WithInsecureSkipVerify()
		}

		tlsCfg, err = tlsCfgBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("unable to build TLS configuration: %w", err)
		}
	}

	return &tstunnelTransport{
		serverAddr: opts.ServerAddr,
		certFile:   opts.CertFile,
		keyFile:    opts.KeyFile,
		caFile:     opts.CAFile,
		insecure:   opts.Insecure,
		tlsConfig:  tlsCfg,
		prompter:   opts.Prompter,
	}, nil
}

// Copy implements the Copy method of agent.Transport.
func (t *tstunnelTransport) Copy(localPath, remoteName string) error {
	// Use the /copy endpoint provided by pkg/commands-guest
	// Create a context with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	// Open the local file.
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer file.Close()

	// Get file info for size.
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat local file: %w", err)
	}

	// Create HTTP client with TLS config if available.
	client := &http.Client{
		Timeout: commandTimeout,
		Transport: &http.Transport{
			TLSClientConfig: t.tlsConfig,
		},
	}

	// Build the URL for the copy endpoint (use https if TLS is configured, otherwise http).
	scheme := "http"
	if t.tlsConfig != nil {
		scheme = "https"
	}
	copyURL := fmt.Sprintf("%s://%s/tinyscale/v1/host/copy?path=%s", scheme, t.serverAddr, url.QueryEscape(remoteName))

	// Create HTTP POST request.
	req, err := http.NewRequestWithContext(ctx, "POST", copyURL, file)
	if err != nil {
		return fmt.Errorf("failed to create copy request: %w", err)
	}

	// Set required headers.
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = fileInfo.Size()

	// Send the request.
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send copy request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("copy failed with status %s: %s", resp.Status, string(body))
	}

	return nil
}

// Command implements the Command method of agent.Transport.
func (t *tstunnelTransport) Command(command string) (*exec.Cmd, error) {
	// Use the current executable with host-exec sub-command.
	// The command will establish an upgrade connection to /tinyscale/v1/host/command
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Build arguments according to host-exec command definition.
	// Format: executable host-exec --serverAddr=<serverAddr> --cert=<cert> --key=<key> [--ca=<ca>] [--serverAddr-name=<sni>] -- <command>
	args := []string{
		"host-exec",
		fmt.Sprintf("--server-addr=%s", t.serverAddr),
	}

	if t.certFile != "" {
		args = append(args, fmt.Sprintf("--cert=%s", t.certFile))
	}
	if t.keyFile != "" {
		args = append(args, fmt.Sprintf("--key=%s", t.keyFile))
	}
	if t.caFile != "" {
		args = append(args, fmt.Sprintf("--ca=%s", t.caFile))
	}
	if t.serverName != "" {
		args = append(args, fmt.Sprintf("--server-name=%s", t.serverName))
	}
	if t.insecure {
		args = append(args, "--insecure")
	}

	// Add the delimiter and the command to execute.
	args = append(args, "--")
	args = append(args, strings.Split(command, " ")...)

	// Create the command.
	cmd := exec.Command(execPath, args...)

	// Set process attributes.
	cmd.SysProcAttr = transport.ProcessAttributes()

	return cmd, nil
}

// ClassifyError implements the ClassifyError method of agent.Transport.
func (t *tstunnelTransport) ClassifyError(processState *os.ProcessState, errorOutput string) (bool, bool, error) {
	// Check for common error patterns that might indicate the agent needs installation.

	// Connection errors typically indicate network issues rather than missing agents.
	if strings.Contains(errorOutput, "connection refused") ||
		strings.Contains(errorOutput, "connection timeout") ||
		strings.Contains(errorOutput, "TLS handshake") {
		return false, false, errors.New("connection error - check network and TLS configuration")
	}

	// Agent not found errors indicate installation is needed.
	if strings.Contains(errorOutput, "agent not found") ||
		strings.Contains(errorOutput, "command not found") ||
		strings.Contains(errorOutput, "no such file") {
		return true, false, nil
	}

	// Check for Windows-specific errors (though less common with tstunnel).
	if strings.Contains(errorOutput, "is not recognized as an internal or external command") {
		return true, true, nil
	}

	// Version mismatch errors also suggest reinstallation.
	if strings.Contains(errorOutput, "version mismatch") ||
		strings.Contains(errorOutput, "incompatible version") {
		return true, false, nil
	}

	// If we can't classify the error, return an error to abort.
	return false, false, errors.New("unknown error condition encountered")
}
