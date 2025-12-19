package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/teamycloud/remote-docker-agent/pkg/tcp_agent"
)

func main() {
	var (
		listenAddr   = flag.String("listen", "127.0.0.1:2375", "Local address to listen on")
		sshUser      = flag.String("ssh-user", "root", "SSH username")
		sshHost      = flag.String("ssh-host", "remote.example.com:22", "SSH host and port")
		sshKeyPath   = flag.String("ssh-key", os.Getenv("HOME")+"/.ssh/id_rsa", "Path to SSH private key")
		remoteDocker = flag.String("remote-docker", "unix:///var/run/docker.sock", "Remote Docker socket URL")
	)

	flag.Parse()

	cfg := tcp_agent.Config{
		ListenAddr:   *listenAddr,
		SSHUser:      *sshUser,
		SSHHost:      *sshHost,
		SSHKeyPath:   *sshKeyPath,
		RemoteDocker: *remoteDocker,
	}

	log.Printf("Starting TCP proxy with SSH transport...")
	log.Printf("  Listen: %s", cfg.ListenAddr)
	log.Printf("  SSH: %s@%s", cfg.SSHUser, cfg.SSHHost)
	log.Printf("  Remote Docker: %s", cfg.RemoteDocker)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)

	proxy, err := tcp_agent.NewTCPProxy(cfg)
	if err != nil {
		log.Fatalf("Failed to create TCP proxy: %v", err)
	}
	defer proxy.Close()

	go func() {
		errCh <- proxy.ListenAndServe()
	}()

	log.Println("Proxy started. Press Ctrl+C to stop.")
	log.Printf("Use: export DOCKER_HOST=tcp://%s", cfg.ListenAddr)

	// Wait for shutdown signal or error
	select {
	case <-sigCh:
		log.Println("Shutting down gracefully...")
	case err := <-errCh:
		if err != nil {
			log.Fatalf("Proxy error: %v", err)
		}
	}
}
