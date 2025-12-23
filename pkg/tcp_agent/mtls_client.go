package tcp_agent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// MTLSClient manages mTLS connection and provides methods to dial remote services
type MTLSClient struct {
	cfg       Config
	tlsConfig *tls.Config
}

// NewMTLSClient creates a new mTLS client with the provided configuration
func NewMTLSClient(cfg Config) (*MTLSClient, error) {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.MTLSCertPath, cfg.MTLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}

	// Load CA certificate if provided
	var rootCAs *x509.CertPool
	if cfg.MTLSCAPath != "" {
		caCert, err := os.ReadFile(cfg.MTLSCAPath)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}

		rootCAs = x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		MinVersion:   tls.VersionTLS12,
	}

	return &MTLSClient{
		cfg:       cfg,
		tlsConfig: tlsConfig,
	}, nil
}

// DialRemoteDocker dials the remote Docker API via mTLS with proper SNI
func (m *MTLSClient) DialRemoteDocker() (net.Conn, error) {
	// Clone TLS config and set SNI for Docker API
	tlsConfig := m.tlsConfig.Clone()
	tlsConfig.ServerName = m.cfg.MTLSSNIHost

	// Dial the mTLS endpoint
	conn, err := tls.Dial("tcp", m.cfg.MTLSEndpoint, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("mtls dial: %w", err)
	}

	return conn, nil
}

// DialTinyscaleAPI dials the Tinyscale API endpoint via mTLS with proper SNI
// This is used for HTTP UPGRADE to create TCP tunnels for mutagen
func (m *MTLSClient) DialTinyscaleAPI() (net.Conn, error) {
	// Clone TLS config and set SNI for Tinyscale API
	tlsConfig := m.tlsConfig.Clone()
	tlsConfig.ServerName = m.cfg.MTLSSNIHost

	// Dial the mTLS endpoint
	conn, err := tls.Dial("tcp", m.cfg.MTLSEndpoint, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("mtls dial tinyscale: %w", err)
	}

	return conn, nil
}

// Close closes the mTLS client (no-op for now as connections are per-dial)
func (m *MTLSClient) Close() error {
	return nil
}

// ExecuteCommand is not supported for mTLS transport
func (m *MTLSClient) ExecuteCommand(command string) (string, error) {
	return "", fmt.Errorf("ExecuteCommand is not supported for mTLS transport")
}
