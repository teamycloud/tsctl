package commands_guest

import (
	"context"
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

func RunServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/command", handleCommand)
	mux.HandleFunc("/copy", handleCopy)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting guest agent on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Channel to listen for interrupt signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
