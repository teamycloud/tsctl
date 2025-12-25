package docker_api_proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/mutagen-io/mutagen/cmd"
	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/identifier"
	"github.com/mutagen-io/mutagen/pkg/prompting"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
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

// TCPProxy implements a transparent TCP proxy that forwards connections
// through an SSH tunnel to a remote Docker daemon
type TCPProxy struct {
	cfg              Config                  `json:"cfg"`
	sshClient        *SSHClient              `json:"ssh_client,omitempty"`
	portForwardMgr   *PortForwardManager     `json:"port_forward_mgr,omitempty"`
	fileSyncMgr      *FileSyncManager        `json:"file_sync_mgr,omitempty"`
	listener         net.Listener            `json:"listener,omitempty"`
	wg               sync.WaitGroup          `json:"wg"`
	prompter         *cmd.StatusLinePrompter `json:"prompter"`
	promptIdentifier string                  `json:"promptIdentifier"`
	stopCh           chan struct{}           `json:"stop_ch,omitempty"`
	containerIDCache sync.Map                `json:"-"` // Cache for *http.Request -> containerID mapping
}

// NewTCPProxy creates a new TCP proxy instance and establishes SSH connection
func NewTCPProxy(cfg Config, forwardingManager *forwarding.Manager, synchronizationManager *synchronization.Manager) (*TCPProxy, error) {
	sshClient, err := NewSSHClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ssh client: %w", err)
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
	portForwardMgr := NewPortForwardManager(cfg, forwardingManager)

	// Create file sync manager
	fileSyncMgr := NewFileSyncManager(cfg, synchronizationManager)

	proxy := &TCPProxy{
		cfg:              cfg,
		sshClient:        sshClient,
		prompter:         prompter,
		promptIdentifier: promptIdentifier,
		portForwardMgr:   portForwardMgr,
		fileSyncMgr:      fileSyncMgr,
		stopCh:           make(chan struct{}),
	}

	// Start goroutine to clean up orphaned sessions from previous runs
	go proxy.cleanupOrphanedSessions()

	return proxy, nil
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
						p.fileSyncMgr.TeardownSyncs(containerID)
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
				log.Printf("Cached container ID %s for remove request (original: %s)", fullContainerID, containerIDOrName)
			}
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

				if err := p.portForwardMgr.SetupForwards(containerID, p.promptIdentifier); err != nil {
					log.Printf("Failed to setup port forwards for %s: %v", containerID, err)
				}
				if err := p.fileSyncMgr.SetupSyncs(containerID, p.promptIdentifier); err != nil {
					log.Printf("Failed to setup file syncs for %s: %v", containerID, err)
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
				log.Printf("Container stop detected: %s", containerIDOrName)
				go p.teardownForContainer(resp.Header["Api-Version"][0], containerIDOrName)
			}
		}
	}

	// Handle container remove - use cached container ID
	if req.Method == http.MethodDelete && containerRemovePattern.MatchString(req.URL.Path) {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Retrieve cached container ID
			if cachedID, ok := p.containerIDCache.LoadAndDelete(req); ok {
				if containerID, ok := cachedID.(string); ok {
					log.Printf("Container remove detected, using cached ID: %s", containerID)
					go p.teardownForContainer("", containerID)
				}
			} else {
				// Fallback: try to resolve (though this might fail if container is already removed)
				matches := containerRemovePattern.FindStringSubmatch(req.URL.Path)
				if len(matches) > 1 {
					containerIDOrName := matches[1]
					if fullContainerIDPattern.MatchString(matches[1]) {
						log.Printf("Container remove detected (no cache): %s", containerIDOrName)
						go p.teardownForContainer(resp.Header["Api-Version"][0], containerIDOrName)
					}
				}
			}
		}

		p.containerIDCache.Delete(req)
	}
}

func (p *TCPProxy) teardownForContainer(apiVersion string, containerIDOrName string) {
	// If it's already a full container ID, teardown directly
	if fullContainerIDPattern.MatchString(containerIDOrName) {
		p.portForwardMgr.TeardownForwards(containerIDOrName)
		p.fileSyncMgr.TeardownSyncs(containerIDOrName)
		return
	}

	// Fetch actual container ID by inspecting the container
	containerID := p.getContainerID(apiVersion, containerIDOrName)
	if containerID == "" {
		log.Printf("Failed to get container ID for %s, skipping teardown", containerIDOrName)
		return
	}

	log.Printf("Resolved container name/short ID %s to full ID %s", containerIDOrName, containerID)
	p.portForwardMgr.TeardownForwards(containerID)
	p.fileSyncMgr.TeardownSyncs(containerID)
}

// extractAPIVersion extracts the API version from a Docker API request path
// e.g., "/v1.45/containers/abc/remove" -> "1.45"
func extractAPIVersion(path string) string {
	// Match pattern like /v1.45/...
	pattern := regexp.MustCompile(`^/v([\d.]+)/`)
	matches := pattern.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	// Default to 1.45 if not found
	return "1.45"
}

// getContainerID fetches the full container ID from Docker API given a name or short ID
func (p *TCPProxy) getContainerID(apiVersion string, containerIDOrName string) string {
	// Create a new connection to query container info
	conn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		log.Printf("Failed to dial remote Docker for container ID lookup: %v", err)
		return ""
	}
	defer conn.Close()

	// Build the inspect request
	requestPath := fmt.Sprintf("/v%s/containers/%s/json", apiVersion, containerIDOrName)
	req, err := http.NewRequest("GET", requestPath, nil)
	if err != nil {
		log.Printf("Failed to create container inspect request: %v", err)
		return ""
	}
	req.Host = "docker.example.com"
	req.Header.Set("User-Agent", "Docker-Client/28.0.4 (darwin) tsagent/1.0.0")

	// Send the request
	if err := req.Write(conn); err != nil {
		log.Printf("Failed to send container inspect request: %v", err)
		return ""
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Failed to read container inspect response: %v", err)
		return ""
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		log.Printf("Container inspect returned status %d for %s (container may not exist)", resp.StatusCode, containerIDOrName)
		return ""
	}

	// Parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read container inspect response body: %v", err)
		return ""
	}

	// Parse JSON to get container ID
	var inspectResp struct {
		Id string `json:"Id"`
	}

	if err := json.Unmarshal(body, &inspectResp); err != nil {
		log.Printf("Failed to parse container inspect response: %v", err)
		return ""
	}

	return inspectResp.Id
}

const SyncBasePath = "/opt/container-mount-sync"

// rewriteBindMount rewrites a bind mount string by replacing the host path with a remote sync path
// Input format: "source:target[:ro]"
// Output format: "/opt/container-mount-sync/target:target[:ro]"
func rewriteBindMount(bind string, basePath string) string {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 {
		// Invalid format, return as-is
		return bind
	}

	// parts[0] = source (host path)
	// parts[1] = target (container path)
	// parts[2+] = optional flags (e.g., "ro")

	source := parts[0]
	target := parts[1]
	newSource := fmt.Sprintf("%s%s", basePath, source)

	if len(parts) == 2 {
		return fmt.Sprintf("%s:%s", newSource, target)
	} else {
		// Preserve any additional flags
		flags := strings.Join(parts[2:], ":")
		return fmt.Sprintf("%s:%s:%s", newSource, target, flags)
	}
}

// handleContainerCreate extracts port bindings from container create request and stores them
func (p *TCPProxy) handleContainerCreateRequest(req *http.Request) {
	var originalReqBody []byte
	var replacedReqBody []byte

	defer func() {
		if replacedReqBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(replacedReqBody))
			//req.Header.Set("Content-Length", strconv.Itoa(len(replacedReqBody)))
			req.ContentLength = int64(len(replacedReqBody))
			req.Header.Del("Content-Length")
		} else if originalReqBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(originalReqBody))
		}
	}()

	if req.Body != nil {
		rBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("Error reading container create request body: %v", err)
			return
		}
		originalReqBody = rBytes
	}

	// Parse request JSON to get port bindings and bind mounts
	var createReq struct {
		HostConfig struct {
			PortBindings map[string][]struct {
				HostIp   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
			Binds  []string `json:"Binds"`
			Mounts []struct {
				Type     string `json:"Type"`
				Source   string `json:"Source"`
				Target   string `json:"Target"`
				ReadOnly bool   `json:"ReadOnly,omitempty"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
	}

	if err := json.Unmarshal(originalReqBody, &createReq); err != nil {
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

	mounts := make([]string, 0)
	if len(createReq.HostConfig.Binds) > 0 {
		mounts = append(mounts, createReq.HostConfig.Binds...)
		// insert SyncBasePath into the Binds
	}
	if len(createReq.HostConfig.Mounts) > 0 {
		for _, mount := range createReq.HostConfig.Mounts {
			if mount.Type == "bind" {
				m := fmt.Sprintf("%s:%s", mount.Source, mount.Target)
				if mount.ReadOnly {
					m = fmt.Sprintf("%s:ro", m)
				}
				mounts = append(mounts, m)
			}
		}
		// insert SyncBasePath into the Mounts
	}

	if len(mounts) > 0 {
		log.Printf("Bind mounts found: %d mounts", len(mounts))

		p.fileSyncMgr.StoreBindMountsStart(req, mounts)
		parsedMounts := p.fileSyncMgr.GetMounts(req)
		if parsedMounts != nil && len(parsedMounts.Mounts) > 0 {
			// Create mount directories on remote host before starting
			if err := p.createRemoteMountDirectories(parsedMounts); err != nil {
				log.Printf("Failed to create remote mount directories: %v", err)
			}
		}

		// Rewrite mount paths in the request body using generic map manipulation
		// to preserve all unknown fields
		var createReqMap map[string]interface{}
		if err := json.Unmarshal(originalReqBody, &createReqMap); err != nil {
			log.Printf("Failed to parse request for mount rewriting: %v", err)
		} else {
			needsRewrite := false

			if hostConfig, ok := createReqMap["HostConfig"].(map[string]interface{}); ok {
				// Rewrite HostConfig.Binds (string array format)
				if binds, ok := hostConfig["Binds"].([]interface{}); ok && len(binds) > 0 {
					newBinds := make([]interface{}, 0, len(binds))
					for _, bindIface := range binds {
						if bind, ok := bindIface.(string); ok {
							newBind := rewriteBindMount(bind, SyncBasePath)
							newBinds = append(newBinds, newBind)
							if newBind != bind {
								needsRewrite = true
								log.Printf("Rewriting bind mount: %s -> %s", bind, newBind)
							}
						}
					}
					hostConfig["Binds"] = newBinds
				}

				// Rewrite HostConfig.Mounts (object array format)
				if mountsArray, ok := hostConfig["Mounts"].([]interface{}); ok && len(mountsArray) > 0 {
					for _, mountIface := range mountsArray {
						if mount, ok := mountIface.(map[string]interface{}); ok {
							mountType, _ := mount["Type"].(string)
							if mountType == "bind" {
								source, _ := mount["Source"].(string)
								target, _ := mount["Target"].(string)

								if source != "" && target != "" {
									newSource := fmt.Sprintf("%s%s", SyncBasePath, source)
									if newSource != source {
										mount["Source"] = newSource
										needsRewrite = true
										log.Printf("Rewriting mount source: %s -> %s", source, newSource)
									}
								}
							}
						}
					}
				}
			}

			// Marshal back if we made changes
			if needsRewrite {
				modifiedBody, err := json.Marshal(createReqMap)
				if err != nil {
					log.Printf("Failed to marshal modified request: %v", err)
				} else {
					replacedReqBody = modifiedBody
					log.Printf("Request body rewritten with sync base path modifications")
				}
			}
		}
	}
}

type ContainerResponse struct {
	Id       string   `json:"Id,omitempty"`
	Warnings []string `json:"Warnings,omitempty"`
	Message  string   `json:"Message,omitempty"`
}

// handleContainerCreate extracts port bindings from container create request and stores them
func dumpContainerResponseAndWrite(resp *http.Response) (*ContainerResponse, error) {
	// Read response body to get container ID
	var respBody bytes.Buffer
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf("Internal agent error: %v", err))))
			return nil, err
		}

		respBody.Write(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))

		respObj := ContainerResponse{}
		if err := json.Unmarshal(respBody.Bytes(), &respObj); err != nil {
			return nil, err
		}
		return &respObj, nil
	}

	// empty response body
	return nil, nil
}
func (p *TCPProxy) handleContainerCreateResponse(req *http.Request, resp *http.Response) {
	if resp.StatusCode != 201 {
		log.Printf("Container create detected with unexpected status code: %d", resp.StatusCode)
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	createResp, err := dumpContainerResponseAndWrite(resp)
	if err != nil || createResp == nil {
		if err != nil {
			log.Printf("Failed to get container create response: %v", err)
		}
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	if createResp.Id == "" {
		log.Printf("No container ID in create response")
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	log.Printf("Container created with ID: %s", createResp.Id)
	p.portForwardMgr.StorePortBindingsEnd(req, createResp.Id)
	p.fileSyncMgr.StoreBindMountsEnd(req, createResp.Id)
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
		p.listener = nil
	}

	p.wg.Wait()

	// Close SSH connection
	if p.sshClient != nil {
		if err := p.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}

	return nil
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

// createRemoteMountDirectories creates all mount directories on the remote host
// It resolves original local paths and creates directories based on whether they are
// directories or files (creating parent directory for files)
func (p *TCPProxy) createRemoteMountDirectories(mounts *ContainerMounts) error {
	log.Printf("Creating remote mount directories for container")

	for _, mount := range mounts.Mounts {
		// Get the original local path
		localPath := mount.HostPath

		// Determine the remote path based on the sync base path
		// The remote path is: SyncBasePath + localPath
		remotePath := fmt.Sprintf("%s%s", SyncBasePath, localPath)

		// Check if the local path is a directory or file
		info, err := os.Stat(localPath)
		if err != nil {
			log.Printf("Warning: cannot stat local path %s: %v", localPath, err)
			continue
		}

		var dirToCreate string
		if info.IsDir() {
			// If it's a directory, create it on remote
			dirToCreate = remotePath
			log.Printf("Local path %s is a directory, will create %s on remote", localPath, dirToCreate)
		} else {
			// If it's a file, create its parent directory on remote
			dirToCreate = filepath.Dir(remotePath)
			log.Printf("Local path %s is a file, will create parent directory %s on remote", localPath, dirToCreate)
		}

		// Execute SSH command to create the directory
		cmd := fmt.Sprintf("mkdir -p '%s'", dirToCreate)
		log.Printf("Executing on remote host: %s", cmd)

		if output, err := p.sshClient.ExecuteCommand(cmd); err != nil {
			log.Printf("Failed to create directory %s on remote host: %v, output: %s", dirToCreate, err, output)
			// Continue with other mounts even if one fails
			continue
		}

		log.Printf("Successfully created directory %s on remote host", dirToCreate)
	}

	return nil
}

// cleanupOrphanedSessions detects and removes port-forward and file-sync sessions
// for containers that no longer exist or are not running on the remote host
func (p *TCPProxy) cleanupOrphanedSessions() {
	log.Printf("Starting cleanup of orphaned sessions from previous runs...")

	// Collect all unique container IDs from both managers
	allContainerIDs := make(map[string]bool)

	// Get all existing port forward sessions
	portForwardSessions, err := p.portForwardMgr.ListSessions()
	if err != nil {
		log.Printf("Failed to list port forward sessions: %v", err)
	} else {
		log.Printf("Found %d existing port forward sessions", len(portForwardSessions))
		for containerID := range portForwardSessions {
			allContainerIDs[containerID] = true
		}
	}

	// Get all existing file sync sessions
	fileSyncSessions, err := p.fileSyncMgr.ListSessions()
	if err != nil {
		log.Printf("Failed to list file sync sessions: %v", err)
	} else {
		log.Printf("Found %d existing file sync sessions", len(fileSyncSessions))
		for containerID := range fileSyncSessions {
			allContainerIDs[containerID] = true
		}
	}

	if len(allContainerIDs) == 0 {
		log.Printf("No existing sessions found, cleanup completed")
		return
	}

	log.Printf("Found %d unique containers with active sessions", len(allContainerIDs))

	// Check running state for all containers in a single loop
	containersToTeardown := make([]string, 0)
	for containerID := range allContainerIDs {
		if !p.isContainerRunning(containerID) {
			log.Printf("Container %s is not running, will teardown sessions", containerID)
			containersToTeardown = append(containersToTeardown, containerID)
		} else {
			log.Printf("Container %s is still running, keeping sessions", containerID)
		}
	}

	// Teardown sessions for all non-running containers
	if len(containersToTeardown) > 0 {
		log.Printf("Tearing down sessions for %d containers", len(containersToTeardown))
		for _, containerID := range containersToTeardown {
			p.portForwardMgr.TeardownForwards(containerID)
			p.fileSyncMgr.TeardownSyncs(containerID)
		}
	}

	log.Printf("Orphaned session cleanup completed")
}

// isContainerRunning checks if a container exists and is running on the remote host
func (p *TCPProxy) isContainerRunning(containerID string) bool {
	// Create a new connection to query container state
	conn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		log.Printf("Failed to dial remote Docker for container check: %v", err)
		return false
	}
	defer conn.Close()

	// Build the inspect request
	req, err := http.NewRequest("GET", fmt.Sprintf("/containers/%s/json", containerID), nil)
	if err != nil {
		log.Printf("Failed to create inspect request: %v", err)
		return false
	}
	req.Host = "docker.example.com"
	req.Header.Set("User-Agent", "Docker-Client/28.0.4 (darwin) tsagent/1.0.0")

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
		log.Printf("Container %s does not exist (status %d)", containerID, resp.StatusCode)
		return false
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

	isRunning := inspectResp.State.Running
	log.Printf("Container %s state: Running=%v, Status=%s", containerID, inspectResp.State.Running, inspectResp.State.Status)

	return isRunning
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
