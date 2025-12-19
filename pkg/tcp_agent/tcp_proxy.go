package tcp_agent

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"sync"
)

var (
	// Pattern to match /containers/create
	containerCreatePattern = regexp.MustCompile(`^/v[\d.]+/containers/create$`)
	// Pattern to match /containers/{id}/start
	containerStartPattern = regexp.MustCompile(`^/v[\d.]+/containers/[a-f0-9]+/start$`)
)

// TCPProxy implements a transparent TCP proxy that forwards connections
// through an SSH tunnel to a remote Docker daemon
type TCPProxy struct {
	cfg       Config
	sshClient *SSHClient
	listener  net.Listener
	wg        sync.WaitGroup
	stopCh    chan struct{}
}

// NewTCPProxy creates a new TCP proxy instance and establishes SSH connection
func NewTCPProxy(cfg Config) (*TCPProxy, error) {
	// Create SSH client
	sshClient, err := NewSSHClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create ssh client: %w", err)
	}

	return &TCPProxy{
		cfg:       cfg,
		sshClient: sshClient,
		stopCh:    make(chan struct{}),
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

		// Check if this request should be intercepted
		if shouldInterceptRequest(req) {
			log.Printf("!!! INTERCEPTING: %s %s !!!", req.Method, req.URL.Path)
			dumpHTTPRequest(req)
		} else {
			log.Printf("Proxying: %s %s", req.Method, req.URL.Path)
		}

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

	// Close SSH connection
	if p.sshClient != nil {
		if err := p.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}

	return nil
}

// dumpHTTPRequest logs HTTP request details for debugging
func dumpHTTPRequest(r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	b, err := httputil.DumpRequest(r, false) // headers only
	if err != nil {
		log.Printf("dump request error: %v", err)
		return
	}

	log.Printf("=== INTERCEPTED HTTP REQUEST ===\n%s", b)
	if len(body) > 0 {
		log.Printf("Body:\n%s", body)
	}
	log.Printf("================================\n")

	// Restore body
	r.Body = io.NopCloser(bytes.NewReader(body))
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
