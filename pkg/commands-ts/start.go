package commands_ts

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/logging"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	"github.com/spf13/cobra"
	"github.com/teamycloud/tsctl/pkg/docker-api-proxy"

	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/local"
	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/ssh"
	_ "github.com/mutagen-io/mutagen/pkg/synchronization/protocols/local"
	_ "github.com/mutagen-io/mutagen/pkg/synchronization/protocols/ssh"

	_ "github.com/teamycloud/tsctl/pkg/ts-tunnel/forwarding-protocol"
	_ "github.com/teamycloud/tsctl/pkg/ts-tunnel/synchronization-protocol"
)

//
//TSTunnelServer   string // HTTPS endpoint (e.g., "containers.tinyscale.net:443")
//TSTunnelCertFile string // Path to client certificate file
//TSTunnelKeyFile  string // Path to client key file
//TSTunnelCAFile   string // Path to CA certificate file (optional)

func NewStartCommand() *cobra.Command {
	var (
		listenAddr   string
		sshUser      string
		sshHost      string
		sshKeyPath   string
		remoteDocker string
		logLevelFlag string

		tsTunnelServer   string // HTTPS endpoint (e.g., "containers.tinyscale.net:443")
		tsTunnelCertFile string // Path to client certificate file
		tsTunnelKeyFile  string // Path to client key file
		tsTunnelCAFile   string // Path to CA certificate file (optional)
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the TCP proxy server",
		Long:  `Start the TCP proxy server that forwards Docker API calls to a remote Docker daemon over SSH.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Create the root logger.
			logLevel := logging.LevelInfo
			if l, ok := logging.NameToLevel(logLevelFlag); !ok {
				fmt.Printf("WARNING: invalid log level specified in environment: %s, default log level 'info' will be used\n", logLevelFlag)
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

			cfg := docker_api_proxy.Config{
				ListenAddr:    listenAddr,
				TransportType: docker_api_proxy.TransportSSH,
				SSHUser:       sshUser,
				SSHHost:       sshHost,
				SSHKeyPath:    sshKeyPath,
				RemoteDocker:  remoteDocker,
			}

			if tsTunnelServer != "" {
				cfg.TransportType = docker_api_proxy.TransportTSTunnel
				cfg.TSTunnelServer = tsTunnelServer

				if tsTunnelCertFile != "" && tsTunnelKeyFile != "" {
					cfg.TSTunnelCertFile = tsTunnelCertFile
					cfg.TSTunnelKeyFile = tsTunnelKeyFile

					if tsTunnelCAFile != "" {
						cfg.TSTunnelCAFile = tsTunnelCAFile
					}
				}
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

			proxy, err := docker_api_proxy.NewTCPProxy(cfg, forwardingManager, synchronizationManager)
			if err != nil {
				log.Fatalf("Failed to create TCP proxy: %v", err)
			}
			//defer proxy.Close()

			go func() {
				errCh <- proxy.ListenAndServe()
			}()

			log.Println("Proxy started. Press Ctrl+C to stop.")
			log.Printf("Use: export DOCKER_HOST=tcp://%s", cfg.ListenAddr)

			// Wait for shutdown signal or error
			select {
			case <-sigCh:
				log.Println("Shutting down gracefully...")
				proxy.Close()
			case err := <-errCh:
				if err != nil {
					log.Fatalf("Proxy error: %v", err)
				}
			}
		},
	}

	// Add flags to the start command
	cmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1:2375", "Local address to listen on")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "SSH username")
	cmd.Flags().StringVar(&sshHost, "ssh-host", "remote.example.com:22", "SSH host and port")
	cmd.Flags().StringVar(&sshKeyPath, "ssh-key", os.Getenv("HOME")+"/.ssh/id_rsa", "Path to SSH private key")
	cmd.Flags().StringVar(&remoteDocker, "remote-docker", "unix:///var/run/docker.sock", "Remote Docker socket URL")
	cmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level")

	cmd.Flags().StringVar(&tsTunnelServer, "ts-server", "", "Tinyscale server address")
	cmd.Flags().StringVar(&tsTunnelCertFile, "ts-cert", "", "Path to mTLS certificate")
	cmd.Flags().StringVar(&tsTunnelKeyFile, "ts-key", "", "Path to mTLS private key")
	cmd.Flags().StringVar(&tsTunnelCAFile, "ts-ca", "", "Path to accepted Tinyscale CA certificate")

	return cmd
}
