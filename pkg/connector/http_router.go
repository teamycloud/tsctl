package mtlsproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/teamycloud/tsctl/pkg/utils"
)

// HTTPRouter handles HTTP request inspection and routing
type HTTPRouter struct {
	backendHost  string
	clientCert   *tls.Certificate
	dockerPort   int
	hostExecPort int
}

// NewHTTPRouterWithClientCert creates a new HTTP router with client certificate
func NewHTTPRouterWithClientCert(backendHost string, clientCert *tls.Certificate, dockerPort, hostExecPort int) *HTTPRouter {
	return &HTTPRouter{
		backendHost:  backendHost,
		clientCert:   clientCert,
		dockerPort:   dockerPort,
		hostExecPort: hostExecPort,
	}
}

// RouteAndProxy inspects the first HTTP request and routes to the appropriate backend port
func (r *HTTPRouter) RouteAndProxy(clientConn net.Conn) error {
	// Peek at the first HTTP request to determine routing
	reader := bufio.NewReader(clientConn)

	// Read the first line (HTTP request line)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read HTTP request line: %w", err)
	}

	// Parse request line to extract path
	path, err := extractPathFromRequestLine(requestLine)
	if err != nil {
		return fmt.Errorf("failed to parse request path: %w", err)
	}

	// Determine target port based on path prefix
	targetPort := r.determinePort(path)
	backendAddr := fmt.Sprintf("%s:%d", r.backendHost, targetPort)

	// Connect to backend with or without client certificate
	var backendConn net.Conn
	var connErr error

	if r.clientCert != nil {
		// Use TLS with client certificate
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{*r.clientCert},
			InsecureSkipVerify: true, // Backend is in trusted network
		}
		backendConn, connErr = tls.Dial("tcp", backendAddr, tlsConfig)
	} else {
		// Plain TCP connection
		backendConn, connErr = net.Dial("tcp", backendAddr)
	}

	if connErr != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, connErr)
	}
	defer backendConn.Close()

	// Write the request line we already read
	if _, err := backendConn.Write([]byte(requestLine)); err != nil {
		return fmt.Errorf("failed to write request line to backend: %w", err)
	}

	// Now we need to bridge the connections
	// First, copy any remaining buffered data from the reader
	if reader.Buffered() > 0 {
		buffered := make([]byte, reader.Buffered())
		if _, err := io.ReadFull(reader, buffered); err != nil {
			return fmt.Errorf("failed to read buffered data: %w", err)
		}
		if _, err := backendConn.Write(buffered); err != nil {
			return fmt.Errorf("failed to write buffered data to backend: %w", err)
		}
	}

	return utils.CopyBiDirectional(clientConn, backendConn)
}

// determinePort determines the backend port based on the request path
func (r *HTTPRouter) determinePort(path string) int {
	// Check for mutagen calls first (more specific prefix)
	if strings.HasPrefix(path, "/tinyscale/v1/host-exec/") {
		return r.hostExecPort
	}

	// Check for Docker Engine API
	if strings.HasPrefix(path, "/v1/") {
		return r.dockerPort
	}

	// Default to Docker port for unknown paths
	return r.dockerPort
}

// extractPathFromRequestLine extracts the path from an HTTP request line
// Request line format: METHOD PATH HTTP/VERSION
// Example: GET /v1/containers/json HTTP/1.1
func extractPathFromRequestLine(requestLine string) (string, error) {
	// Trim whitespace
	requestLine = strings.TrimSpace(requestLine)

	// Split by spaces
	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid HTTP request line: %s", requestLine)
	}

	// The path is the second part
	path := parts[1]

	// Remove query string if present (keep only the path)
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	return path, nil
}
