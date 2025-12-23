package tcp_agent

import "fmt"

// TransportType defines the type of transport to use
type TransportType string

const (
	TransportSSH  TransportType = "ssh"
	TransportMTLS TransportType = "mtls"
)

// Config holds configuration for the TCP agent
type Config struct {
	ListenAddr   string        // Local address to listen on (e.g., "127.0.0.1:2375")
	Transport    TransportType // Transport type: "ssh" or "mtls"
	
	// SSH transport configuration
	SSHUser      string // SSH username for remote connection (e.g., "root")
	SSHHost      string // SSH host and port (e.g., "remote.example.com:22")
	SSHKeyPath   string // Path to SSH private key (e.g., "/home/user/.ssh/id_rsa")
	
	// mTLS transport configuration
	MTLSEndpoint string // mTLS endpoint address (e.g., "gateway.tinyscale.net:443")
	MTLSCertPath string // Path to client certificate
	MTLSKeyPath  string // Path to client private key
	MTLSCAPath   string // Path to CA certificate (optional)
	MTLSSNIHost  string // SNI hostname (e.g., "abcdefg.containers.tinyscale.net")
	
	RemoteDocker string // Remote Docker socket URL (e.g., "unix:///var/run/docker.sock" or "tcp://127.0.0.1:2375")
}

// Validate checks if the configuration is valid based on the selected transport
func (c *Config) Validate() error {
	if c.Transport == TransportMTLS {
		if c.MTLSEndpoint == "" {
			return fmt.Errorf("mTLS endpoint is required when using mTLS transport")
		}
		if c.MTLSCertPath == "" || c.MTLSKeyPath == "" {
			return fmt.Errorf("mTLS certificate and key are required when using mTLS transport")
		}
		if c.MTLSSNIHost == "" {
			return fmt.Errorf("mTLS SNI hostname is required when using mTLS transport")
		}
	} else if c.Transport == TransportSSH {
		if c.SSHHost == "" {
			return fmt.Errorf("SSH host is required when using SSH transport")
		}
		if c.SSHKeyPath == "" {
			return fmt.Errorf("SSH key path is required when using SSH transport")
		}
	} else {
		return fmt.Errorf("invalid transport type: %s (must be 'ssh' or 'mtls')", c.Transport)
	}
	return nil
}
