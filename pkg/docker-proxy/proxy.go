package docker_proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sync"

	"github.com/mutagen-io/mutagen/cmd"
	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/identifier"
	"github.com/mutagen-io/mutagen/pkg/logging"
	"github.com/mutagen-io/mutagen/pkg/prompting"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	"github.com/teamycloud/tsctl/pkg/docker-proxy/mutagen-bridge"
	"github.com/teamycloud/tsctl/pkg/docker-proxy/types"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
)

var (
	fullContainerIDPattern = regexp.MustCompile(`^([a-f0-9]{64})$`)
	// Pattern to match /containers/create
	containerCreatePattern = regexp.MustCompile(`^/v[\d.]+/containers/create$`)
	// Pattern to match /containers/{id}/start
	containerStartPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)/start$`)
	// Pattern to match /containers/{id}/stop
	containerStopPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-zA-Z0-9][a-zA-Z0-9_.-]+)/stop$`)
	// Pattern to match DELETE /containers/{id}
	containerRemovePattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-zA-Z0-9][a-zA-Z0-9_.-]+)$`)
	// Pattern to match /containers/{id}/wait - long-running request that completes when container exits
	containerWaitPattern = regexp.MustCompile(`^/v[\d.]+/containers/([a-f0-9]+)/wait`)
)

// DockerAPIProxy implements a transparent TCP proxy that forwards connections
// through an SSH tunnel to a remote Docker daemon
type DockerAPIProxy struct {
	cfg    types.Config
	logger *logging.Logger

	sshClient        *SSHClient
	tsTunnelOpts     *ts_tunnel.ServerOptions
	tlsConfig        *tls.Config
	prompter         *cmd.StatusLinePrompter
	promptIdentifier string

	portForwardMgr *mutagen_bridge.PortForwardManager
	fileSyncMgr    *mutagen_bridge.FileSyncManager

	listener net.Listener
	wg       sync.WaitGroup

	stopCh           chan struct{}
	containerIDCache sync.Map // Cache for *http.Request -> containerID mapping
}

// NewProxy creates a new TCP proxy instance and establishes SSH connection
func NewProxy(cfg types.Config, forwardingManager *forwarding.Manager, synchronizationManager *synchronization.Manager,
	logger *logging.Logger) (*DockerAPIProxy, error) {
	var sshClient *SSHClient
	var tsTunnelOpts *ts_tunnel.ServerOptions

	if cfg.TransportType == types.TransportSSH {
		var err error
		sshClient, err = NewSSHClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("create ssh client: %w", err)
		}
	} else {
		tsTunnelOpts = &ts_tunnel.ServerOptions{
			ServerAddr: cfg.TSTunnelServer,
			CertFile:   cfg.TSTunnelCertFile,
			KeyFile:    cfg.TSTunnelKeyFile,
			CAFile:     cfg.TSTunnelCAFile,
			Insecure:   cfg.TSInsecure,
		}
	}

	prompter := &cmd.StatusLinePrompter{Printer: &cmd.StatusLinePrinter{}}
	promptIdentifier, err := identifier.New(identifier.PrefixPrompter)
	if err != nil {
		return nil, fmt.Errorf("unable to generate prompter identifier: %w", err)
	}
	if err := prompting.RegisterPrompterWithIdentifier(promptIdentifier, prompter); err != nil {
		return nil, fmt.Errorf("unable to register prompter: %w", err)
	}

	// Create port forward manager
	portForwardMgr := mutagen_bridge.NewPortForwardBridge(cfg, forwardingManager, logger.Sublogger("port-forward-bridge"))

	// Create file sync manager
	fileSyncMgr := mutagen_bridge.NewFileSyncBridge(cfg, synchronizationManager, logger.Sublogger("file-sync-bridge"))

	proxy := &DockerAPIProxy{
		cfg:              cfg,
		logger:           logger,
		sshClient:        sshClient,
		tsTunnelOpts:     tsTunnelOpts,
		prompter:         prompter,
		promptIdentifier: promptIdentifier,
		portForwardMgr:   portForwardMgr,
		fileSyncMgr:      fileSyncMgr,
		stopCh:           make(chan struct{}),
	}

	// Start goroutine to clean up orphaned sessions from previous runs
	go proxy.cleanupOrphanedMutagenSessions()

	return proxy, nil
}

// ListenAndServe starts the TCP proxy server
func (p *DockerAPIProxy) ListenAndServe() error {
	listener, err := net.Listen("tcp", p.cfg.ListenAddr)
	if err != nil {
		return err
	}
	p.listener = listener

	p.logger.Infof("Proxy listening on %s, proxying via %s", p.cfg.ListenAddr, p.cfg.TransportType)

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
				p.logger.Debugf("Accept error: %v", err)
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
func (p *DockerAPIProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Establish connection to remote Docker via SSH
	remoteConn, err := p.dialRemote()
	if err != nil {
		p.logger.Warnf("Failed to dial remote Docker: %v", err)
		return
	}
	defer remoteConn.Close()

	p.logger.Tracef("New connection from %s -> %s", clientConn.RemoteAddr(), remoteConn.RemoteAddr().String())

	// Create buffered readers for both directions
	clientReader := bufio.NewReader(clientConn)
	remoteReader := bufio.NewReader(remoteConn)

	for {
		// Try to parse HTTP request
		req, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF {
				p.logger.Debugf("Client closed connection from %s", clientConn.RemoteAddr())
				return
			}

			p.logger.Debugf("Not HTTP or parse error, using transparent proxy: %v", err)
			p.transparentProxy(clientConn, remoteConn, clientReader)
			return
		}

		// Handle container lifecycle operations BEFORE forwarding
		p.handleContainerOperation(req)

		// Forward the request to remote Docker
		if err := req.Write(remoteConn); err != nil {
			p.logger.Warnf("Failed to forward request: %v", err)
			return
		}

		// Read and forward the response back to client
		resp, err := http.ReadResponse(remoteReader, req)
		if err != nil {
			p.logger.Warnf("Failed to read response: %v", err)
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
				p.logger.Tracef("Container wait request detected for: %s (will teardown forwards when complete)", containerID)

				// Write response headers to client
				if err := resp.Write(clientConn); err != nil {
					resp.Body.Close()
					p.logger.Debugf("Failed to forward wait response: %v", err)
					return
				}
				// Don't close resp.Body yet - let it stream

				// The connection will close when the container exits and /wait completes
				// Teardown port forwards after verifying the container actually stopped
				defer func() {
					p.logger.Tracef("Container wait completed (connection closed) for: %s, verifying container state...", containerID)

					// Verify the container is actually stopped before tearing down port forwards
					if p.isContainerStopped(containerID) {
						p.logger.Tracef("Container confirmed stopped: %s, tearing down port forwards", containerID)
						p.portForwardMgr.TeardownForwards(containerID)
						p.fileSyncMgr.TeardownSyncs(containerID)
					} else {
						p.logger.Tracef("Container still running: %s, keeping port forwards active", containerID)
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
			p.logger.Warnf("Failed to forward response: %v", err)
			return
		}
		resp.Body.Close()

		// Check if connection should be closed
		// HTTP/1.0 defaults to close, HTTP/1.1 defaults to keep-alive
		if shouldCloseConnection(req, resp) {
			p.logger.Tracef("Closing connection after response (Connection: close)")
			return
		}

		// Check for Connection Upgrade (like docker attach with WebSocket/TCP upgrade)
		if isConnectionUpgrade(resp) {
			p.logger.Tracef("Connection upgrade detected, switching to transparent proxy")
			p.transparentProxyWithReaders(clientConn, remoteConn, clientReader, remoteReader)
			return
		}

		p.logger.Tracef("Waiting for next request on connection from %s", clientConn.RemoteAddr())
	}
}

func (p *DockerAPIProxy) dialRemote() (net.Conn, error) {
	if p.cfg.TransportType == types.TransportSSH {
		return p.sshClient.DialRemoteDocker()
	} else {
		conn, tlsCfg, err := ts_tunnel.Dial(p.tsTunnelOpts, p.tlsConfig)
		if tlsCfg != nil {
			p.tlsConfig = tlsCfg
		}
		return conn, err
	}
}

// handleContainerOperation handles container operations BEFORE forwarding the request
func (p *DockerAPIProxy) handleContainerOperation(req *http.Request) {
	p.logger.Tracef("Container operation request %s %s", req.Method, req.URL.Path)

	if req.Method == http.MethodPost && containerCreatePattern.MatchString(req.URL.Path) {
		p.handleContainerCreateRequest(req)
	}

	// Handle container remove - resolve and cache container ID BEFORE the request is sent
	// This is necessary because the container might be deleted after the request
	if req.Method == http.MethodDelete && containerRemovePattern.MatchString(req.URL.Path) {
		matches := containerRemovePattern.FindStringSubmatch(req.URL.Path)
		if len(matches) > 1 {
			containerIDOrName := matches[1]
			// Extract API version from the request path
			apiVersion := extractAPIVersion(req.URL.Path)

			// Resolve the container ID now, before it gets deleted
			var fullContainerID string
			if fullContainerIDPattern.MatchString(containerIDOrName) {
				fullContainerID = containerIDOrName
			} else {
				// Query the container ID from Docker API
				fullContainerID = p.getContainerID(apiVersion, containerIDOrName)
			}

			if fullContainerID != "" {
				// Cache the container ID for later use in the response handler
				p.containerIDCache.Store(req, fullContainerID)
				p.logger.Tracef("Cached container ID %s for remove request (original: %s)", fullContainerID, containerIDOrName)
			}
		}
	}
}

// handleContainerOperationResponse handles container operations AFTER receiving the response
func (p *DockerAPIProxy) handleContainerOperationResponse(req *http.Request, resp *http.Response) {
	p.logger.Tracef("Container operation response to %s %s\n    %d", req.Method, req.URL.Path, resp.StatusCode)

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
				p.logger.Tracef("Container start detected: %s", containerID)

				if err := p.portForwardMgr.SetupForwards(containerID, p.promptIdentifier); err != nil {
					p.logger.Warnf("Failed to setup port forwards for %s: %v", containerID, err)
				}
				if err := p.fileSyncMgr.SetupSyncs(containerID, p.promptIdentifier); err != nil {
					p.logger.Warnf("Failed to setup file syncs for %s: %v", containerID, err)
				}
			}
		}
	}

	// Handle container stop - tear down port forwards
	// Stop is safe to resolve async since container still exists after stop
	if req.Method == http.MethodPost && containerStopPattern.MatchString(req.URL.Path) {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			matches := containerStopPattern.FindStringSubmatch(req.URL.Path)
			if len(matches) > 1 {
				containerIDOrName := matches[1]
				p.logger.Tracef("Container stop detected: %s", containerIDOrName)
				go p.teardownForContainer(containerIDOrName, resp.Header["Api-Version"][0])
			}
		}
	}

	// Handle container remove - use cached container ID
	if req.Method == http.MethodDelete && containerRemovePattern.MatchString(req.URL.Path) {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Retrieve cached container ID
			if cachedID, ok := p.containerIDCache.LoadAndDelete(req); ok {
				if containerID, ok := cachedID.(string); ok {
					p.logger.Tracef("Container remove detected, using cached ID: %s", containerID)
					go p.teardownForContainer(containerID, "")
				}
			} else {
				// Fallback: try to resolve (though this might fail if container is already removed)
				matches := containerRemovePattern.FindStringSubmatch(req.URL.Path)
				if len(matches) > 1 {
					containerIDOrName := matches[1]
					if fullContainerIDPattern.MatchString(matches[1]) {
						p.logger.Tracef("Container remove detected (no cache): %s", containerIDOrName)
						go p.teardownForContainer(containerIDOrName, resp.Header["Api-Version"][0])
					}
				}
			}
		}

		p.containerIDCache.Delete(req)
	}
}

func (p *DockerAPIProxy) teardownForContainer(containerIDOrName string, apiVersion string) {
	p.logger.Debugf("Tearing down filesync and port-forwards for container %s", containerIDOrName)

	// If it's already a full container ID, teardown directly
	if fullContainerIDPattern.MatchString(containerIDOrName) {
		p.portForwardMgr.TeardownForwards(containerIDOrName)
		p.fileSyncMgr.TeardownSyncs(containerIDOrName)
		return
	}

	// Fetch actual container ID by inspecting the container
	containerID := p.getContainerID(apiVersion, containerIDOrName)
	if containerID == "" {
		p.logger.Debugf("Failed to get container ID for %s, skipping teardown", containerIDOrName)
		return
	}

	p.logger.Tracef("Resolved container name/short ID %s to full ID %s", containerIDOrName, containerID)

	p.portForwardMgr.TeardownForwards(containerID)
	p.fileSyncMgr.TeardownSyncs(containerID)
}

// transparentProxyWithReaders handles bidirectional copying with buffered readers
func (p *DockerAPIProxy) transparentProxyWithReaders(clientConn net.Conn, remoteConn net.Conn, clientReader *bufio.Reader, remoteReader *bufio.Reader) {
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
		p.logger.Warnf("Connection copy error: %v", err)
	}

	p.logger.Tracef("Connection closed from %s", clientConn.RemoteAddr())
}

// transparentProxy handles bidirectional copying between client and remote
func (p *DockerAPIProxy) transparentProxy(clientConn net.Conn, remoteConn net.Conn, clientReader *bufio.Reader) {
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
		p.logger.Warnf("Connection copy error: %v", err)
	}

	p.logger.Tracef("Connection closed from %s", clientConn.RemoteAddr())
}

// Close gracefully shuts down the proxy
func (p *DockerAPIProxy) Close() error {
	close(p.stopCh)

	if p.listener != nil {
		p.listener.Close()
		p.listener = nil
	}

	p.wg.Wait()

	if p.sshClient != nil {
		if err := p.sshClient.Close(); err != nil {
			p.logger.Infof("Error closing SSH client: %v", err)
		}
	}

	return nil
}

// cleanupOrphanedMutagenSessions detects and removes port-forward and file-sync sessions
// for containers that no longer exist or are not running on the remote host
func (p *DockerAPIProxy) cleanupOrphanedMutagenSessions() {
	p.logger.Infof("Starting cleanup of orphaned sessions from previous runs...")

	// Collect all unique container IDs from both managers
	allContainerIDs := make(map[string]bool)

	// Get all existing port forward sessions
	portForwardSessions, err := p.portForwardMgr.ListSessions()
	if err != nil {
		p.logger.Warnf("Failed to list port forward sessions: %v", err)
	} else {
		p.logger.Debugf("Found %d existing port forward sessions", len(portForwardSessions))
		for containerID := range portForwardSessions {
			allContainerIDs[containerID] = true
		}
	}

	// Get all existing file sync sessions
	fileSyncSessions, err := p.fileSyncMgr.ListSessions()
	if err != nil {
		p.logger.Warnf("Failed to list file sync sessions: %v", err)
	} else {
		p.logger.Debugf("Found %d existing file sync sessions", len(fileSyncSessions))
		for containerID := range fileSyncSessions {
			allContainerIDs[containerID] = true
		}
	}

	if len(allContainerIDs) == 0 {
		p.logger.Debugf("No existing sessions found, cleanup completed")
		return
	}

	p.logger.Debugf("Found %d unique containers with active sessions", len(allContainerIDs))

	// Check running state for all containers in a single loop
	containersToTeardown := make([]string, 0)
	for containerID := range allContainerIDs {
		if !p.isContainerRunning(containerID) {
			p.logger.Debugf("Container %s is not running, will teardown sessions", containerID)
			containersToTeardown = append(containersToTeardown, containerID)
		} else {
			p.logger.Debugf("Container %s is still running, keeping sessions", containerID)
		}
	}

	// Teardown sessions for all non-running containers
	if len(containersToTeardown) > 0 {
		p.logger.Debugf("Tearing down sessions for %d containers", len(containersToTeardown))
		for _, containerID := range containersToTeardown {
			p.portForwardMgr.TeardownForwards(containerID)
			p.fileSyncMgr.TeardownSyncs(containerID)
		}
	}

	p.logger.Debugf("Orphaned session cleanup completed")
}
