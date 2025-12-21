package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/logging"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	"github.com/teamycloud/remote-docker-agent/pkg/tcp_agent"

	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/local"
	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/ssh"
)

func main() {
	var (
		listenAddr   = flag.String("listen", "127.0.0.1:2375", "Local address to listen on")
		sshUser      = flag.String("ssh-user", "root", "SSH username")
		sshHost      = flag.String("ssh-host", "remote.example.com:22", "SSH host and port")
		sshKeyPath   = flag.String("ssh-key", os.Getenv("HOME")+"/.ssh/id_rsa", "Path to SSH private key")
		remoteDocker = flag.String("remote-docker", "unix:///var/run/docker.sock", "Remote Docker socket URL")
		logLevelFlag = flag.String("log-level", "info", "Log level")
	)

	flag.Parse()

	// Create the root logger.
	logLevel := logging.LevelInfo
	if l, ok := logging.NameToLevel(*logLevelFlag); !ok {
		fmt.Printf("WARNING: invalid log level specified in environment: %s, default log level 'info' will be used\n", *logLevelFlag)
	} else {
		logLevel = l
	}
	logger := logging.NewLogger(logLevel, os.Stderr)

	// Attempt to acquire the daemon lock and defer its release.
	//lock, err := daemon.AcquireLock()
	//if err != nil {
	//	return fmt.Errorf("unable to acquire daemon lock: %w", err)
	//}
	//defer lock.Release()

	cfg := tcp_agent.Config{
		ListenAddr:   *listenAddr,
		SSHUser:      *sshUser,
		SSHHost:      *sshHost,
		SSHKeyPath:   *sshKeyPath,
		RemoteDocker: *remoteDocker,
	}

	bannerFormat := `
Starting TCP proxy with SSH transport...
  Listen: %s
  SSH: %s@%s
  Remote Docker: %s
`
	logger.Infof(bannerFormat, cfg.ListenAddr, cfg.SSHUser, cfg.SSHHost, cfg.RemoteDocker)

	// todo: list current sessions and get their container IDs (get their labels and try to check if container is still running)
	forwardingManager, err := forwarding.NewManager(logger.Sublogger("forward"))
	if err != nil {
		panic(fmt.Sprintf("unable to create forwarding session manager: %v", err))
	}
	defer forwardingManager.Shutdown()

	// Create a synchronization session manager and defer its shutdown.
	synchronizationManager, err := synchronization.NewManager(logger.Sublogger("sync"))
	if err != nil {
		panic(fmt.Sprintf("unable to create synchronization session manager: %v", err))
	}
	defer synchronizationManager.Shutdown()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)

	proxy, err := tcp_agent.NewTCPProxy(cfg, forwardingManager, synchronizationManager)
	if err != nil {
		log.Fatalf("Failed to create TCP proxy: %v", err)
	}
	defer proxy.Close()

	go func() {
		errCh <- proxy.ListenAndServe()
	}()

	// Create and register the forwarding server.
	//forwardingServer := forwardingsvc.NewServer(forwardingManager)
	//forwardingsvc.RegisterForwardingServer(server, forwardingServer)
	//
	//// Create and register the synchronization server.
	//synchronizationServer := synchronizationsvc.NewServer(synchronizationManager)
	//synchronizationsvc.RegisterSynchronizationServer(server, synchronizationServer)

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
