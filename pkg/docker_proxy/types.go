package docker_proxy

// TransportType represents the type of transport to use for remote connections
type TransportType string

const (
	// TransportSSH uses SSH for remote connections
	TransportSSH TransportType = "ssh"
	// TransportTSTunnel uses ts-tunnel (mTLS) for remote connections
	TransportTSTunnel TransportType = "tinyscale"
)

// Config holds configuration for the TCP agent
type Config struct {
	ListenAddr    string        // Local address to listen on (e.g., "127.0.0.1:2375")
	TransportType TransportType // Type of transport to use ("ssh" or "tstunnel")

	// SSH-specific fields (used when TransportType == TransportSSH)
	SSHUser      string // SSH username for remote connection (e.g., "root")
	SSHHost      string // SSH host and port (e.g., "remote.example.com:22")
	SSHKeyPath   string // Path to SSH private key (e.g., "/home/user/.ssh/id_rsa")
	RemoteDocker string // Remote Docker socket URL (e.g., "unix:///var/run/docker.sock" or "tcp://127.0.0.1:2375")

	// TS-Tunnel specific fields (used when TransportType == TransportTSTunnel)
	TSTunnelServer   string // HTTPS endpoint (e.g., "containers.tinyscale.net:443")
	TSTunnelCertFile string // Path to client certificate file
	TSTunnelKeyFile  string // Path to client key file
	TSTunnelCAFile   string // Path to CA certificate file (optional)
	TSInsecure       bool   // Skip TLS Verify
}
