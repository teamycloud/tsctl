package mtlsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Proxy represents the mTLS TCP proxy server
type Proxy struct {
	config   *Config
	caPool   *x509.CertPool
	db       *DatabaseProvider
	logger   *logrus.Logger
	listener net.Listener
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewProxy creates a new mTLS proxy instance
func NewProxy(config *Config, logger *logrus.Logger) (*Proxy, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Load CA certificates
	caPool, err := config.LoadCACertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificates: %w", err)
	}

	// Connect to database
	db, err := NewDatabaseProvider(&config.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Proxy{
		config: config,
		caPool: caPool,
		db:     db,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start starts the proxy server
func (p *Proxy) Start() error {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(p.config.ServerCertPath, p.config.ServerKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %w", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    p.caPool,
		MinVersion:   tls.VersionTLS12,
		// Validate SNI is provided
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if hello.ServerName == "" {
				return nil, errors.New("SNI is required")
			}
			return nil, nil
		},
	}

	// Create TLS listener
	listener, err := tls.Listen("tcp", p.config.ListenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start listener: %w", err)
	}

	p.listener = listener
	p.logger.Infof("mTLS proxy listening on %s", p.config.ListenAddr)

	// Accept connections
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptConnections()
	}()

	return nil
}

// acceptConnections accepts incoming connections
func (p *Proxy) acceptConnections() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.ctx.Done():
				return
			default:
				p.logger.Errorf("failed to accept connection: %v", err)
				continue
			}
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handleConnection(conn)
		}()
	}
}

// handleConnection handles a single client connection
func (p *Proxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		p.logger.Error("connection is not a TLS connection")
		return
	}

	// Get client certificate
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		p.logger.Error("no client certificate provided")
		return
	}

	clientCert := state.PeerCertificates[0]

	// Validate certificate (already done by TLS, but we do additional checks)
	if err := ValidateCertificate(clientCert, p.caPool); err != nil {
		p.logger.Errorf("certificate validation failed: %v", err)
		return
	}

	// Validate issuer match
	if err := ValidateIssuerMatch(clientCert, p.caPool, p.config.Issuer); err != nil {
		p.logger.Errorf("issuer validation failed: %v", err)
		return
	}

	// Extract user identity
	identity, err := ExtractUserIdentity(clientCert, p.config.Issuer)
	if err != nil {
		p.logger.Errorf("failed to extract user identity: %v", err)
		return
	}

	p.logger.Infof("authenticated user: %s (org: %s)", identity.UserID, identity.OrgID)

	// Extract connectID from SNI
	sni := state.ServerName
	connectID, err := p.parseConnectIDFromSNI(sni)
	if err != nil {
		p.logger.Errorf("failed to parse connect_id from SNI: %v", err)
		return
	}

	p.logger.Infof("routing connection to: %s", connectID)

	// Route the connection
	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
	defer cancel()

	target, err := p.db.RouteConnection(ctx, identity.UserID, identity.OrgID, connectID)
	if err != nil {
		p.logger.Errorf("routing failed: %v", err)
		return
	}

	p.logger.Infof("routing user %s to backend %s", identity.UserID, target.BackendAddr)

	// Use HTTP-aware routing
	router := NewHTTPRouter(target.BackendAddr)
	if err := router.RouteAndProxy(tlsConn); err != nil {
		p.logger.Errorf("proxy failed: %v", err)
		return
	}
}

// parseConnectIDFromSNI extracts connectID from SNI hostname
// SNI format: <connectID>.connect.tinyscale.com
// Returns the connectID (first part before the first dot)
func (p *Proxy) parseConnectIDFromSNI(sni string) (string, error) {
	if sni == "" {
		return "", errors.New("SNI is empty")
	}

	// Split by dot and get the first part
	parts := strings.Split(sni, ".")
	if len(parts) == 0 {
		return "", errors.New("invalid SNI format")
	}

	connectID := parts[0]
	if connectID == "" {
		return "", errors.New("connectID is empty")
	}

	return connectID, nil
}

// Stop stops the proxy server
func (p *Proxy) Stop() error {
	p.cancel()

	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			p.logger.Errorf("failed to close listener: %v", err)
		}
	}

	// Wait for all connections to finish (with timeout)
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		p.logger.Info("all connections closed gracefully")
	case <-time.After(30 * time.Second):
		p.logger.Warn("timeout waiting for connections to close")
	}

	if p.db != nil {
		p.db.Close()
	}

	return nil
}
