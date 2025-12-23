package tstunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/mutagen-io/mutagen/pkg/agent"
	"github.com/mutagen-io/mutagen/pkg/logging"
)

// Transport implements a custom transport for mutagen that uses HTTP UPGRADE
// over mTLS to establish TCP tunnels to Tinyscale servers
type Transport struct {
	endpoint  string // mTLS endpoint (e.g., "gateway.tinyscale.net:443")
	certPath  string // Client certificate path
	keyPath   string // Client private key path
	caPath    string // CA certificate path (optional)
	sniHost   string // SNI hostname
	logger    *logging.Logger
	tlsConfig *tls.Config // Cached TLS config
}

// NewTransport creates a new tstunnel transport
func NewTransport(endpoint, certPath, keyPath, caPath, sniHost string, logger *logging.Logger) (*Transport, error) {
	t := &Transport{
		endpoint: endpoint,
		certPath: certPath,
		keyPath:  keyPath,
		caPath:   caPath,
		sniHost:  sniHost,
		logger:   logger,
	}
	
	// Build TLS config once during initialization
	tlsConfig, err := t.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	t.tlsConfig = tlsConfig
	
	return t, nil
}

// buildTLSConfig creates a TLS configuration for mTLS connections
func (t *Transport) buildTLSConfig() (*tls.Config, error) {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(t.certPath, t.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	// Load CA certificate if provided
	var rootCAs *x509.CertPool
	if t.caPath != "" {
		caCert, err := os.ReadFile(t.caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}

		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
	}

	// Configure TLS
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		ServerName:   t.sniHost,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// dialWithUpgrade establishes an mTLS connection and performs HTTP UPGRADE
func (t *Transport) dialWithUpgrade(apiPath string) (net.Conn, *bufio.Reader, error) {
	// Clone TLS config for thread safety
	tlsConfig := t.tlsConfig.Clone()
	
	// Dial the mTLS endpoint
	conn, err := tls.Dial("tcp", t.endpoint, tlsConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("mtls dial: %w", err)
	}

	// Send HTTP UPGRADE request to establish TCP tunnel
	req, err := http.NewRequest("GET", apiPath, nil)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("create upgrade request: %w", err)
	}

	// Set required headers for HTTP UPGRADE
	req.Host = t.sniHost
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")

	// Write the request to the connection
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("write upgrade request: %w", err)
	}

	// Read the HTTP response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("read upgrade response: %w", err)
	}
	defer resp.Body.Close()

	// Check if the upgrade was successful
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, nil, fmt.Errorf("upgrade failed with status: %d %s", resp.StatusCode, resp.Status)
	}

	// Check if the connection was upgraded to TCP
	if resp.Header.Get("Upgrade") != "tcp" {
		conn.Close()
		return nil, nil, fmt.Errorf("upgrade response missing 'Upgrade: tcp' header")
	}

	return conn, reader, nil
}

// Dial establishes a connection to the remote agent via HTTP UPGRADE over mTLS
func (t *Transport) Dial(command agent.Command) (io.ReadWriteCloser, error) {
	// Determine the API path based on the command type
	var apiPath string
	switch command {
	case agent.CommandForwarder:
		apiPath = "/tinyscale/v1/tunnel/forward"
	case agent.CommandSynchronizer:
		apiPath = "/tinyscale/v1/tunnel/sync"
	default:
		return nil, fmt.Errorf("unsupported agent command: %v", command)
	}

	// Set command header for the upgrade request
	conn, reader, err := t.dialWithUpgrade(apiPath)
	if err != nil {
		return nil, err
	}

	t.logger.Info("Successfully established TCP tunnel via HTTP UPGRADE")

	// Now the connection is upgraded to a raw TCP tunnel
	// We need to wrap it to handle any buffered data
	return &upgradedConn{
		Conn:   conn,
		reader: reader,
	}, nil
}

// Copy implements the Transport.Copy method (optional for some transports)
func (t *Transport) Copy() agent.Transport {
	// Clone TLS config to avoid race conditions
	var clonedConfig *tls.Config
	if t.tlsConfig != nil {
		clonedConfig = t.tlsConfig.Clone()
	}
	
	return &Transport{
		endpoint:  t.endpoint,
		certPath:  t.certPath,
		keyPath:   t.keyPath,
		caPath:    t.caPath,
		sniHost:   t.sniHost,
		logger:    t.logger,
		tlsConfig: clonedConfig,
	}
}

// upgradedConn wraps a net.Conn and bufio.Reader to handle buffered data
// after HTTP UPGRADE
type upgradedConn struct {
	net.Conn
	reader         *bufio.Reader
	readerConsumed bool
	once           sync.Once // Ensure reader flag is only set once
}

// Read reads from the buffered reader first, then from the underlying connection
func (u *upgradedConn) Read(p []byte) (int, error) {
	// If there's buffered data and we haven't consumed it yet, read from it first
	if !u.readerConsumed && u.reader != nil && u.reader.Buffered() > 0 {
		n, err := u.reader.Read(p)
		// Mark reader as consumed after draining all buffered data
		if err == nil && u.reader.Buffered() == 0 {
			u.once.Do(func() {
				u.readerConsumed = true
			})
		}
		return n, err
	}
	// Otherwise, read directly from the connection
	return u.Conn.Read(p)
}

// Dialer creates a TCP connection using the tstunnel transport
// This can be used for port forwarding
// Note: Context parameter reserved for future cancellation support
func (t *Transport) Dialer(_ context.Context) (net.Conn, error) {
	// Use the common dialWithUpgrade method
	conn, reader, err := t.dialWithUpgrade("/tinyscale/v1/tunnel/port")
	if err != nil {
		return nil, err
	}

	t.logger.Info("Successfully established TCP tunnel for port forwarding via HTTP UPGRADE")

	// Now the connection is upgraded to a raw TCP tunnel
	return &upgradedConn{
		Conn:   conn,
		reader: reader,
	}, nil
}
