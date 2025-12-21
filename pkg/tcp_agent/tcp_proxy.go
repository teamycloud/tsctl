package tcp_agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
)

var (
	// Pattern to match /containers/create
	containerCreatePattern = regexp.MustCompile(`^/v[\d.]+/containers/create$`)
	// Pattern to match /containers/{id}/start
	containerStartPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)/start$`)
	// Pattern to match /containers/{id}/stop
	containerStopPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)/stop$`)
	// Pattern to match DELETE /containers/{id}
	containerRemovePattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)$`)
	// Pattern to match /containers/{id}/wait - long-running request that completes when container exits
	containerWaitPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)/wait`)
)

// TCPProxy implements a transparent TCP proxy that forwards connections
// through an SSH tunnel to a remote Docker daemon
type TCPProxy struct {
	cfg            Config
	sshClient      *SSHClient
	portForwardMgr *PortForwardManager
	mutagenSyncMgr *synchronization.Manager
	listener       net.Listener
	wg             sync.WaitGroup
	stopCh         chan struct{}
}

// NewTCPProxy creates a new TCP proxy instance and establishes SSH connection
func NewTCPProxy(cfg Config, forwardingManager *forwarding.Manager, synchronizationManager *synchronization.Manager) (*TCPProxy, error) {
	// Create SSH client
	sshClient, err := NewSSHClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ssh client: %w", err)
	}

	// Create port forward manager
	portForwardMgr := NewPortForwardManager(cfg, forwardingManager)

	return &TCPProxy{
		cfg:            cfg,
		sshClient:      sshClient,
		portForwardMgr: portForwardMgr,
		mutagenSyncMgr: synchronizationManager,
		stopCh:         make(chan struct{}),
	}, nil
}

// ListenAndServe starts the TCP proxy server
func (p *TCPProxy) ListenAndServe() error {
	listener, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = listener

	log.Printf("TCP proxy listening on %s, proxying to %s via SSH", p.cfg.ListenAddr, p.cfg.RemoteDocker)

	for {
		select {
		case <-p.stopCh:
			return nil
		default:
		}

		// Accept new connections
		clientConn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		// Handle each connection in a goroutine
		p.wg.Add(1)
		go p.handleConnection(clientConn)
	}
}

// handleConnection proxies data between client and remote Docker daemon
// with optional HTTP-level interception for specific Docker API calls
func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Establish connection to remote Docker via SSH
	remoteConn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		log.Printf("Failed to dial remote Docker: %v", err)
		return
	}
	defer remoteConn.Close()

	log.Printf("New connection from %s -> %s", clientConn.RemoteAddr(), p.cfg.RemoteDocker)

	// Create buffered readers for both directions
	clientReader := bufio.NewReader(clientConn)
	remoteReader := bufio.NewReader(remoteConn)

	// Loop to handle multiple HTTP requests on the same connection (HTTP Keep-Alive)
	for {
		// Try to parse HTTP request
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF {
				log.Printf("Client closed connection from %s", clientConn.RemoteAddr())
				return
			}
			// Not HTTP or parse error, fall back to transparent TCP proxy
			log.Printf("Not HTTP or parse error, using transparent proxy: %v", err)
			p.transparentProxy(clientConn, remoteConn, clientReader)
			return
		}

		// Handle container lifecycle operations BEFORE forwarding
		p.handleContainerOperation(req)

		// Forward the request to remote Docker
		if err := req.Write(remoteConn); err != nil {
			log.Printf("Failed to forward request: %v", err)
			return
		}

		// Read and forward the response back to client
		resp, err := http.ReadResponse(remoteReader, req)
		if err != nil {
			log.Printf("Failed to read response: %v", err)
			return
		}

		// Handle container lifecycle operations AFTER receiving response
		p.handleContainerOperationResponse(req, resp)

		// Special handling for /wait endpoint - it's a long-running streaming response
		// We need to proxy it transparently and teardown port forwards when it completes
		if req.Method == http.MethodPost && containerWaitPattern.MatchString(req.URL.Path) {
			matches := containerWaitPattern.FindStringSubmatch(req.URL.Path)
			if len(matches) > 1 {
				containerID := matches[1]
				log.Printf("Container wait request detected for: %s (will teardown forwards when complete)", containerID)

				// Write response headers to client
				if err := resp.Write(clientConn); err != nil {
					resp.Body.Close()
					log.Printf("Failed to forward wait response: %v", err)
					return
				}
				// Don't close resp.Body yet - let it stream

				// The connection will close when the container exits and /wait completes
				// Teardown port forwards after verifying the container actually stopped
				defer func() {
					log.Printf("Container wait completed (connection closed) for: %s, verifying container state...", containerID)

					// Verify the container is actually stopped before tearing down port forwards
					if p.isContainerStopped(containerID) {
						log.Printf("Container confirmed stopped: %s, tearing down port forwards", containerID)
						p.portForwardMgr.TeardownForwards(containerID)
					} else {
						log.Printf("Container still running: %s, keeping port forwards active", containerID)
					}
				}()

				// The /wait response body continues streaming until container exits
				// We just let it complete naturally - when it's done, the defer will run
				return
			}
		}

		// Write response back to client
		if err := resp.Write(clientConn); err != nil {
			resp.Body.Close()
			log.Printf("Failed to forward response: %v", err)
			return
		}
		resp.Body.Close()

		// Check if connection should be closed
		// HTTP/1.0 defaults to close, HTTP/1.1 defaults to keep-alive
		if shouldCloseConnection(req, resp) {
			log.Printf("Closing connection after response (Connection: close)")
			return
		}

		// Check for Connection Upgrade (like docker attach with WebSocket/TCP upgrade)
		if isConnectionUpgrade(resp) {
			log.Printf("Connection upgrade detected, switching to transparent proxy")
			p.transparentProxyWithReaders(clientConn, remoteConn, clientReader, remoteReader)
			return
		}

		// Continue loop to handle next request on same connection
		log.Printf("Waiting for next request on connection from %s", clientConn.RemoteAddr())
	}
}

// handleContainerOperation handles container operations BEFORE forwarding the request
func (p *TCPProxy) handleContainerOperation(req *http.Request) {
	// Handle container create - extract port bindings
	if req.Method == http.MethodPost && containerCreatePattern.MatchString(req.URL.Path) {
		p.handleContainerCreateRequest(req)
	}

	// Handle container stop/remove - tear down port forwards
	if req.Method == http.MethodPost && containerStopPattern.MatchString(req.URL.Path) {
		matches := containerStopPattern.FindStringSubmatch(req.URL.Path)
		if len(matches) > 1 {
			containerID := matches[1]
			log.Printf("Container stop detected: %s", containerID)
			p.portForwardMgr.TeardownForwards(containerID)
		}
	}

	if req.Method == http.MethodDelete && containerRemovePattern.MatchString(req.URL.Path) {
		matches := containerRemovePattern.FindStringSubmatch(req.URL.Path)
		if len(matches) > 1 {
			containerID := matches[1]
			log.Printf("Container remove detected: %s", containerID)
			p.portForwardMgr.TeardownForwards(containerID)
		}
	}
}

// handleContainerOperationResponse handles container operations AFTER receiving the response
func (p *TCPProxy) handleContainerOperationResponse(req *http.Request, resp *http.Response) {
	// Handle container create - extract port bindings
	if req.Method == http.MethodPost && containerCreatePattern.MatchString(req.URL.Path) {
		p.handleContainerCreateResponse(req, resp)
	}

	// Handle container start - setup port forwards
	if req.Method == http.MethodPost && containerStartPattern.MatchString(req.URL.Path) {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			matches := containerStartPattern.FindStringSubmatch(req.URL.Path)
			if len(matches) > 1 {
				containerID := matches[1]
				log.Printf("Container start detected: %s", containerID)
				if err := p.portForwardMgr.SetupForwards(containerID); err != nil {
					log.Printf("Failed to setup port forwards for %s: %v", containerID, err)
				}
			}
		}
	}
}

// handleContainerCreate extracts port bindings from container create request and stores them
func (p *TCPProxy) handleContainerCreateRequest(req *http.Request) {
	reqBytes, err := dumpRequestBody(req)
	if err != nil {
		log.Printf("Failed to dump HTTP request: %v", err)
		return
	}

	// Parse request JSON to get port bindings
	var createReq struct {
		HostConfig struct {
			PortBindings map[string][]struct {
				HostIp   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
		} `json:"HostConfig"`
	}

	if err := json.Unmarshal(reqBytes, &createReq); err != nil {
		log.Printf("Failed to parse container create request: %v", err)
		return
	}

	// Extract port bindings
	portBindings := make(map[string][]string)
	for containerPort, bindings := range createReq.HostConfig.PortBindings {
		hostPorts := make([]string, 0)
		for _, binding := range bindings {
			if binding.HostPort != "" {
				hostPorts = append(hostPorts, binding.HostPort)
			}
		}
		if len(hostPorts) > 0 {
			portBindings[containerPort] = hostPorts
			log.Printf("Port binding found: %s -> %v", containerPort, hostPorts)
		}
	}

	if len(portBindings) > 0 {
		p.portForwardMgr.StorePortBindingsStart(req, portBindings)
	}
}

// handleContainerCreate extracts port bindings from container create request and stores them
func (p *TCPProxy) handleContainerCreateResponse(req *http.Request, resp *http.Response) {
	if resp.StatusCode != 201 {
		log.Printf("Container create detected with unexpected status code: %d", resp.StatusCode)
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		return
	}

	// Read response body to get container ID
	var respBody bytes.Buffer
	if resp.Body != nil {
		body, _ := io.ReadAll(resp.Body)
		respBody.Write(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Parse response JSON to get container ID
	var createResp struct {
		Id       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}

	if err := json.Unmarshal(respBody.Bytes(), &createResp); err != nil {
		log.Printf("Failed to parse container create response: %v", err)
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		return
	}

	if createResp.Id == "" {
		log.Printf("No container ID in create response")
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		return
	}

	log.Printf("Container created with ID: %s", createResp.Id)
	p.portForwardMgr.StorePortBindingsEnd(req, createResp.Id)
}

// transparentProxyWithReaders handles bidirectional copying with buffered readers
func (p *TCPProxy) transparentProxyWithReaders(clientConn net.Conn, remoteConn net.Conn, clientReader *bufio.Reader, remoteReader *bufio.Reader) {
	errCh := make(chan error, 2)

	// Client -> Remote
	go func() {
		var err error
		// First, copy any buffered data from the reader
		if clientReader != nil && clientReader.Buffered() > 0 {
			buffered := make([]byte, clientReader.Buffered())
			_, err = io.ReadFull(clientReader, buffered)
			if err != nil {
				errCh <- err
				return
			}
			_, err = remoteConn.Write(buffered)
			if err != nil {
				errCh <- err
				return
			}
		}

		// Then continue copying from the underlying connection
		if clientReader != nil {
			_, err = io.Copy(remoteConn, clientReader)
		} else {
			_, err = io.Copy(remoteConn, clientConn)
		}
		errCh <- err
	}()

	// Remote -> Client
	go func() {
		var err error
		// First, copy any buffered data from the remote reader
		if remoteReader != nil && remoteReader.Buffered() > 0 {
			buffered := make([]byte, remoteReader.Buffered())
			_, err = io.ReadFull(remoteReader, buffered)
			if err != nil {
				errCh <- err
				return
			}
			_, err = clientConn.Write(buffered)
			if err != nil {
				errCh <- err
				return
			}
		}

		// Then continue copying from the underlying connection
		if remoteReader != nil {
			_, err = io.Copy(clientConn, remoteReader)
		} else {
			_, err = io.Copy(clientConn, remoteConn)
		}
		errCh <- err
	}()

	// Wait for either direction to complete
	err := <-errCh
	if err != nil && err != io.EOF {
		log.Printf("Connection copy error: %v", err)
	}

	log.Printf("Connection closed from %s", clientConn.RemoteAddr())
}

// transparentProxy handles bidirectional copying between client and remote
func (p *TCPProxy) transparentProxy(clientConn net.Conn, remoteConn net.Conn, clientReader *bufio.Reader) {
	errCh := make(chan error, 2)

	// Client -> Remote
	go func() {
		var err error
		// First, copy any buffered data from the reader
		if clientReader != nil && clientReader.Buffered() > 0 {
			buffered := make([]byte, clientReader.Buffered())
			_, err = io.ReadFull(clientReader, buffered)
			if err != nil {
				errCh <- err
				return
			}
			_, err = remoteConn.Write(buffered)
			if err != nil {
				errCh <- err
				return
			}
		}

		// Then continue copying from the underlying connection
		if clientReader != nil {
			_, err = io.Copy(remoteConn, clientReader)
		} else {
			_, err = io.Copy(remoteConn, clientConn)
		}
		errCh <- err
	}()

	// Remote -> Client
	go func() {
		_, err := io.Copy(clientConn, remoteConn)
		errCh <- err
	}()

	// Wait for either direction to complete
	err := <-errCh
	if err != nil && err != io.EOF {
		log.Printf("Connection copy error: %v", err)
	}

	log.Printf("Connection closed from %s", clientConn.RemoteAddr())
}

// Close gracefully shuts down the proxy
func (p *TCPProxy) Close() error {
	close(p.stopCh)

	if p.listener != nil {
		p.listener.Close()
	}

	p.wg.Wait()

	// Tear down all port forwards
	if p.portForwardMgr != nil {
		p.portForwardMgr.TeardownAll()
	}

	// Close SSH connection
	if p.sshClient != nil {
		if err := p.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}

	return nil
}

// dumpRequestBody logs HTTP request details for debugging
func dumpRequestBody(r *http.Request) ([]byte, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		// Restore body
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	return body, nil
}

// shouldInterceptRequest checks if the request should be intercepted
func shouldInterceptRequest(r *http.Request) bool {
	if r.Method == http.MethodPost && containerCreatePattern.MatchString(r.URL.Path) {
		return true
	}
	// Add more patterns here as needed
	return false
}

// shouldCloseConnection determines if the connection should be closed after the response
func shouldCloseConnection(req *http.Request, resp *http.Response) bool {
	// Check response Connection header
	if resp.Header.Get("Connection") == "close" {
		return true
	}

	// Check request Connection header
	if req.Header.Get("Connection") == "close" {
		return true
	}

	// HTTP/1.0 defaults to close unless Keep-Alive is specified
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return req.Header.Get("Connection") != "Keep-Alive"
	}

	// HTTP/1.1 defaults to keep-alive
	return false
}

// isConnectionUpgrade checks if the response indicates a protocol upgrade
func isConnectionUpgrade(resp *http.Response) bool {
	// Check for 101 Switching Protocols or Upgrade header
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}

	// Also check for Upgrade header in the response
	if resp.Header.Get("Upgrade") != "" {
		return true
	}

	return false
}

// isContainerStopped checks if a container is actually stopped by inspecting its state
func (p *TCPProxy) isContainerStopped(containerID string) bool {
	// Create a new connection to query container state
	conn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		log.Printf("Failed to dial remote Docker for state check: %v", err)
		return false
	}
	defer conn.Close()

	// Build the inspect request
	req, err := http.NewRequest("GET", fmt.Sprintf("/containers/%s/json", containerID), nil)
	if err != nil {
		log.Printf("Failed to create inspect request: %v", err)
		return false
	}
	req.Host = "localhost"

	// Send the request
	if err := req.Write(conn); err != nil {
		log.Printf("Failed to send inspect request: %v", err)
		return false
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Failed to read inspect response: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		log.Printf("Container inspect returned status %d (container may be removed)", resp.StatusCode)
		return true // If container doesn't exist, consider it stopped
	}

	// Parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read inspect response body: %v", err)
		return false
	}

	// Parse JSON to get container state
	var inspectResp struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}

	if err := json.Unmarshal(body, &inspectResp); err != nil {
		log.Printf("Failed to parse inspect response: %v", err)
		return false
	}

	// Container is stopped if not running
	isStopped := !inspectResp.State.Running
	log.Printf("Container %s state: Running=%v, Status=%s", containerID, inspectResp.State.Running, inspectResp.State.Status)

	return isStopped
}
