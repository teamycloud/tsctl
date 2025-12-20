package tcp_agent

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// PortBinding represents a port mapping from local to remote
type PortBinding struct {
	HostPort      string // Local port (e.g., "8080")
	ContainerPort string // Container port with protocol (e.g., "80/tcp")
	Protocol      string // tcp or udp
	Listener      net.Listener
	StopCh        chan struct{}
}

// ContainerPorts tracks port forwards for a specific container
type ContainerPorts struct {
	ContainerID string
	Bindings    []*PortBinding
}

// PortForwardManager manages port forwards for all containers
type PortForwardManager struct {
	mu             sync.RWMutex
	containers     map[*http.Request]*ContainerPorts // containerID -> ports
	containerPorts map[string]*ContainerPorts        // containerID -> ports
	sshClient      *SSHClient
}

// NewPortForwardManager creates a new port forward manager
func NewPortForwardManager(sshClient *SSHClient) *PortForwardManager {
	return &PortForwardManager{
		containers:     make(map[*http.Request]*ContainerPorts),
		containerPorts: make(map[string]*ContainerPorts),
		sshClient:      sshClient,
	}
}

// StorePortBindingsStart stores the port bindings for a container (before it's created)
func (m *PortForwardManager) StorePortBindingsStart(req *http.Request, hostPorts map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bindings := make([]*PortBinding, 0)
	for containerPort, hostPortList := range hostPorts {
		if len(hostPortList) == 0 {
			continue
		}

		// Extract protocol from container port (e.g., "80/tcp" -> "tcp")
		parts := strings.Split(containerPort, "/")
		port := containerPort
		protocol := "tcp"
		if len(parts) == 2 {
			port = parts[0]
			protocol = parts[1]
		}

		// For now, take the first host port binding
		for _, hostPort := range hostPortList {
			if hostPort == "" {
				continue
			}

			binding := &PortBinding{
				HostPort:      hostPort,
				ContainerPort: port,
				Protocol:      protocol,
				StopCh:        make(chan struct{}),
			}
			bindings = append(bindings, binding)
			log.Printf("Stored port bindings: %s:%s -> %s/%s",
				hostPort, port, port, protocol)
		}
	}

	if len(bindings) > 0 {
		m.containers[req] = &ContainerPorts{
			Bindings: bindings,
		}
	}
}

// StorePortBindingsEnd stores the port bindings for a container (before it's created)
func (m *PortForwardManager) StorePortBindingsEnd(req *http.Request, containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if portBindings, ok := m.containers[req]; ok {
		if containerID != "" {
			m.containerPorts[containerID] = portBindings
		}
	}
	delete(m.containers, req)
}

// SetupForwards sets up SSH port forwards for a container
func (m *PortForwardManager) SetupForwards(containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	containerPorts, exists := m.containerPorts[containerID]
	if !exists {
		log.Printf("No port bindings found for container %s", containerID)
		return nil
	}

	log.Printf("Setting up port forwards for container %s", containerID)

	for _, binding := range containerPorts.Bindings {
		if err := m.setupSingleForward(binding); err != nil {
			log.Printf("Failed to setup port forward %s: %v", binding.HostPort, err)
			// Continue with other ports even if one fails
		}
	}

	return nil
}

// setupSingleForward sets up a single SSH port forward
func (m *PortForwardManager) setupSingleForward(binding *PortBinding) error {
	// Parse host port
	hostPortInt, err := strconv.Atoi(binding.HostPort)
	if err != nil {
		return fmt.Errorf("invalid host port %s: %w", binding.HostPort, err)
	}

	// Listen on local port
	localAddr := fmt.Sprintf("127.0.0.1:%d", hostPortInt)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", localAddr, err)
	}

	binding.Listener = listener
	log.Printf("✓ Port forward: localhost:%s -> remote container port %s/%s",
		binding.HostPort, binding.ContainerPort, binding.Protocol)

	// Start accepting connections
	go m.acceptConnections(binding, listener)

	return nil
}

// acceptConnections accepts connections and forwards them via SSH
func (m *PortForwardManager) acceptConnections(binding *PortBinding, listener net.Listener) {
	for {
		select {
		case <-binding.StopCh:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-binding.StopCh:
				return
			default:
				log.Printf("Accept error on port %s: %v", binding.HostPort, err)
				continue
			}
		}

		// Handle connection in goroutine
		go m.handleForwardedConnection(conn, binding)
	}
}

// handleForwardedConnection forwards a single connection via SSH
func (m *PortForwardManager) handleForwardedConnection(localConn net.Conn, binding *PortBinding) {
	defer localConn.Close()

	// Dial the container port on the remote host via SSH
	// Docker containers are accessible via localhost from the Docker host
	remoteAddr := fmt.Sprintf("127.0.0.1:%s", binding.HostPort) // todo: using container IP address and port?
	remoteConn, err := m.sshClient.Client().Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Failed to dial remote %s: %v", remoteAddr, err)
		return
	}
	defer remoteConn.Close()

	// Bidirectional copy
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(remoteConn, localConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(localConn, remoteConn)
		done <- struct{}{}
	}()

	// Wait for one direction to finish
	<-done
}

// TeardownForwards tears down port forwards for a container
func (m *PortForwardManager) TeardownForwards(containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	containerPorts, exists := m.containerPorts[containerID]
	if !exists {
		return
	}

	log.Printf("Tearing down port forwards for container %s", containerID)

	for _, binding := range containerPorts.Bindings {
		close(binding.StopCh)
		if binding.Listener != nil {
			binding.Listener.Close()
			log.Printf("✗ Closed port forward: localhost:%s", binding.HostPort)
		}
	}

	delete(m.containerPorts, containerID)
}

// TeardownAll tears down all port forwards
func (m *PortForwardManager) TeardownAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Tearing down all port forwards")

	for containerID, containerPorts := range m.containerPorts {
		for _, binding := range containerPorts.Bindings {
			close(binding.StopCh)
			if binding.Listener != nil {
				binding.Listener.Close()
			}
		}
		delete(m.containerPorts, containerID)
	}
}
