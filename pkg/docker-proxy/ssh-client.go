package docker_proxy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/teamycloud/tsctl/pkg/docker-proxy/types"
	"golang.org/x/crypto/ssh"
)

// SSHClient manages SSH connection and provides methods to dial remote Docker
type SSHClient struct {
	cfg    types.Config
	client *ssh.Client
}

// NewSSHClient creates a new SSH client and establishes the connection
func NewSSHClient(cfg types.Config) (*SSHClient, error) {
	// Read SSH private key
	key, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read ssh key: %w", err)
	}

	// Parse the private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse ssh key: %w", err)
	}

	// Configure SSH client
	sshCfg := &ssh.ClientConfig{
		User: cfg.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: verify host key in production
		Timeout:         10 * time.Second,
	}

	// Establish SSH connection
	client, err := ssh.Dial("tcp", cfg.SSHHost, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}

	return &SSHClient{
		cfg:    cfg,
		client: client,
	}, nil
}

// DialRemoteDocker dials the remote Docker socket via the SSH tunnel
// Supports both unix sockets and TCP addresses
func (s *SSHClient) DialRemoteDocker() (net.Conn, error) {
	dockerURL, err := url.Parse(s.cfg.RemoteDocker)
	if err != nil {
		return nil, fmt.Errorf("parse remote docker url: %w", err)
	}

	var conn net.Conn

	switch dockerURL.Scheme {
	case "unix":
		// Dial Unix socket on remote host via SSH
		conn, err = s.client.Dial("unix", dockerURL.Path)
	case "tcp":
		// Dial TCP address on remote host via SSH
		conn, err = s.client.Dial("tcp", dockerURL.Host)
	default:
		return nil, fmt.Errorf("unsupported docker url scheme: %s (use 'unix' or 'tcp')", dockerURL.Scheme)
	}

	if err != nil {
		return nil, fmt.Errorf("ssh dial docker: %w", err)
	}

	return conn, nil
}

// Close closes the SSH connection
func (s *SSHClient) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// Client returns the underlying SSH client for advanced usage
func (s *SSHClient) Client() *ssh.Client {
	return s.client
}

// ExecuteCommand executes a command on the remote host via SSH
func (s *SSHClient) ExecuteCommand(command string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("create ssh session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("execute command: %w", err)
	}

	return string(output), nil
}
