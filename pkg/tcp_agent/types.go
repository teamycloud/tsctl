package tcp_agent

// Config holds configuration for the TCP agent
type Config struct {
	ListenAddr   string // Local address to listen on (e.g., "127.0.0.1:2375")
	SSHUser      string // SSH username for remote connection (e.g., "root")
	SSHHost      string // SSH host and port (e.g., "remote.example.com:22")
	SSHKeyPath   string // Path to SSH private key (e.g., "/home/user/.ssh/id_rsa")
	RemoteDocker string // Remote Docker socket URL (e.g., "unix:///var/run/docker.sock" or "tcp://127.0.0.1:2375")
}
