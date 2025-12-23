package tcp_agent

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
