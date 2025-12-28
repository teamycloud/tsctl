package agent_transport

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/mutagen-io/mutagen/pkg/agent"
	"github.com/mutagen-io/mutagen/pkg/agent/transport"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
	"github.com/teamycloud/tsctl/pkg/utils/shelex"
)

// tstunnelTransport implements the agent.Transport interface using mTLS-enabled TCP connections.
type tstunnelTransport struct {
	ts_tunnel.ServerOptions
	// prompter is the prompter identifier to use for prompting.
	prompter string
}

// NewTransport creates a new tstunnel transport using the specified options.
func NewTransport(opts ts_tunnel.ServerOptions, prompter string) (agent.Transport, error) {
	if opts.ServerAddr == "" {
		return nil, errors.New("ServerAddr is required")
	}

	return &tstunnelTransport{
		ServerOptions: opts,
		prompter:      prompter,
	}, nil
}

// Copy implements the Copy method of agent.Transport.
// ts-tunnel 不允许、也不需要向服务端上传文件
// 在 Mutagen 的默认实现中，Copy 方法用于向远端复制、安装 agnet。在我们的实现中，agent 的安装是由服务端自动完成的。
func (t *tstunnelTransport) Copy(localPath, remoteName string) error {
	return nil
}

// Command implements the Command method of agent.Transport.
func (t *tstunnelTransport) Command(command string) (*exec.Cmd, error) {
	commandParts, err := shelex.Split(command)
	if err != nil {
		return nil, fmt.Errorf("failed to parse command: %w", err)
	}

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
		fmt.Sprintf("--server-addr=%s", t.ServerAddr),
	}

	if t.CertFile != "" {
		args = append(args, fmt.Sprintf("--cert=%s", t.CertFile))
	}
	if t.KeyFile != "" {
		args = append(args, fmt.Sprintf("--key=%s", t.KeyFile))
	}
	if t.CAFile != "" {
		args = append(args, fmt.Sprintf("--ca=%s", t.CAFile))
	}
	if t.Insecure {
		args = append(args, "--insecure")
	}

	// Add the delimiter and the command to execute.
	args = append(args, "--")
	args = append(args, commandParts...)

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
