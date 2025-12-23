package tcp_agent

import (
	"fmt"
	"net"
)

// Transport defines the interface for different transport mechanisms (SSH, mTLS, etc.)
type Transport interface {
	// DialRemoteDocker dials the remote Docker daemon
	DialRemoteDocker() (net.Conn, error)
	
	// ExecuteCommand executes a command on the remote host (SSH-specific, may not be supported by all transports)
	ExecuteCommand(command string) (string, error)
	
	// Close closes the transport connection
	Close() error
}

// NewTransport creates a new transport based on the configuration
func NewTransport(cfg Config) (Transport, error) {
	switch cfg.Transport {
	case TransportSSH:
		return NewSSHClient(cfg)
	case TransportMTLS:
		return NewMTLSClient(cfg)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Transport)
	}
}
