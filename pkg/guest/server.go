package guest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var (
	// Global registry for active processes and connections
	processRegistry = &ProcessRegistry{
		processes:   make(map[*os.Process]struct{}),
		connections: make(map[net.Conn]struct{}),
	}
)

type ProcessRegistry struct {
	mu          sync.Mutex
	processes   map[*os.Process]struct{}
	connections map[net.Conn]struct{}
}

func (pr *ProcessRegistry) AddProcess(p *os.Process) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.processes[p] = struct{}{}
}

func (pr *ProcessRegistry) RemoveProcess(p *os.Process) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	delete(pr.processes, p)
}

func (pr *ProcessRegistry) AddConnection(conn net.Conn) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.connections[conn] = struct{}{}
}

func (pr *ProcessRegistry) RemoveConnection(conn net.Conn) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	delete(pr.connections, conn)
}

func (pr *ProcessRegistry) TerminateAll() {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	// Send SIGINT to all processes
	log.Printf("Sending SIGINT to %d active processes...", len(pr.processes))
	for p := range pr.processes {
		if err := p.Signal(syscall.SIGINT); err != nil {
			log.Printf("Failed to send SIGINT to process %d: %v", p.Pid, err)
		}
	}

	// Wait for processes to terminate (with timeout)
	log.Println("Waiting for processes to terminate...")
	waitCh := make(chan struct{})
	go func() {
		for p := range pr.processes {
			_, _ = p.Wait()
		}
		close(waitCh)
	}()

	select {
	case <-waitCh:
		log.Println("All processes terminated gracefully")
	case <-time.After(5 * time.Second):
		log.Println("Timeout waiting for processes, forcing termination...")
		for p := range pr.processes {
			_ = p.Kill()
		}
	}

	// Close all connections
	log.Printf("Closing %d active connections...", len(pr.connections))
	for conn := range pr.connections {
		_ = conn.Close()
	}
}

// ServerConfig holds the guest server configuration
type ServerConfig struct {
	Port        int
	CACertPaths []string // Optional: paths to CA certificates for client verification
	ServerCert  string   // Optional: server certificate path for TLS
	ServerKey   string   // Optional: server key path for TLS
	AllowedCNs  []string // Optional: list of allowed client certificate CNs
	EnableMTLS  bool     // Whether to enable mTLS
}

func RunServer(port int) {
	config := &ServerConfig{
		Port:       port,
		EnableMTLS: false,
	}
	RunServerWithConfig(config)
}

func RunServerWithConfig(config *ServerConfig) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tinyscale/v1/host-exec/command", handleCommand)
	mux.HandleFunc("/tinyscale/v1/host-exec/directories", handleCreateDirectories)

	addr := fmt.Sprintf(":%d", config.Port)
	log.Printf("Starting guest agent on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Configure mTLS if enabled
	if config.EnableMTLS {
		if err := configureMTLS(server, config); err != nil {
			log.Fatalf("Failed to configure mTLS: %v", err)
		}
	}

	// Channel to listen for interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		var err error
		if config.EnableMTLS {
			log.Printf("Starting server with mTLS enabled")
			err = server.ListenAndServeTLS(config.ServerCert, config.ServerKey)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	log.Println("Server started. Press Ctrl+C to stop.")

	// Wait for interrupt signal
	<-sigCh
	log.Println("\nReceived shutdown signal, initiating graceful shutdown...")

	// Step 1 & 2: Terminate processes
	processRegistry.TerminateAll()

	// Step 3: Shutdown the server
	log.Println("Shutting down HTTP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("Server shutdown complete")
	}
}

// configureMTLS configures mutual TLS for the server
func configureMTLS(server *http.Server, config *ServerConfig) error {
	// Load CA certificates
	caPool := x509.NewCertPool()
	for _, caPath := range config.CACertPaths {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate %s: %w", caPath, err)
		}
		if !caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate %s", caPath)
		}
	}

	// Create TLS config with client certificate verification
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
		MinVersion: tls.VersionTLS12,
		// Verify client certificate CN against allow list
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(config.AllowedCNs) == 0 {
				// No CN restriction if allow list is empty
				return nil
			}

			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("no verified certificate chain")
			}

			clientCert := verifiedChains[0][0]
			clientCN := clientCert.Subject.CommonName

			// Check if client CN is in the allow list
			for _, allowedCN := range config.AllowedCNs {
				if clientCN == allowedCN {
					log.Printf("Client authenticated with CN: %s", clientCN)
					return nil
				}
			}

			return fmt.Errorf("client CN '%s' is not in the allow list", clientCN)
		},
	}

	server.TLSConfig = tlsConfig
	return nil
}
