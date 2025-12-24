package agent_transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfigBuilder helps construct TLS configurations for tstunnel transport.
type TLSConfigBuilder struct {
	clientCertFile string
	clientKeyFile  string
	caCertFile     string
	serverName     string
	insecure       bool
}

// NewTLSConfigBuilder creates a new TLS configuration builder.
func NewTLSConfigBuilder() *TLSConfigBuilder {
	return &TLSConfigBuilder{}
}

// WithClientCertificate sets the client certificate and key files.
func (b *TLSConfigBuilder) WithClientCertificate(certFile, keyFile string) *TLSConfigBuilder {
	b.clientCertFile = certFile
	b.clientKeyFile = keyFile
	return b
}

// WithCACertificate sets the CA certificate file for serverAddr verification.
func (b *TLSConfigBuilder) WithCACertificate(caCertFile string) *TLSConfigBuilder {
	b.caCertFile = caCertFile
	return b
}

// WithServerName sets the expected serverAddr name for SNI and certificate verification.
func (b *TLSConfigBuilder) WithServerName(serverName string) *TLSConfigBuilder {
	b.serverName = serverName
	return b
}

// WithInsecureSkipVerify disables serverAddr certificate verification (not recommended for production).
func (b *TLSConfigBuilder) WithInsecureSkipVerify() *TLSConfigBuilder {
	b.insecure = true
	return b
}

// Build constructs the TLS configuration.
func (b *TLSConfigBuilder) Build() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: b.serverName,
	}

	// Load client certificate if provided.
	if b.clientCertFile != "" && b.clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(b.clientCertFile, b.clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	} else if b.clientCertFile != "" || b.clientKeyFile != "" {
		return nil, errors.New("both client certificate and key files must be provided")
	}

	// Load CA certificate if provided.
	if b.caCertFile != "" {
		caCert, err := os.ReadFile(b.caCertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	// Set insecure skip verify if requested.
	if b.insecure {
		config.InsecureSkipVerify = true
	}

	return config, nil
}
