package tsctl

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mutagen-io/mutagen/pkg/daemon"
	"github.com/mutagen-io/mutagen/pkg/forwarding"
	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/local"
	_ "github.com/mutagen-io/mutagen/pkg/forwarding/protocols/ssh"
	"github.com/mutagen-io/mutagen/pkg/logging"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	_ "github.com/mutagen-io/mutagen/pkg/synchronization/protocols/local"
	_ "github.com/mutagen-io/mutagen/pkg/synchronization/protocols/ssh"
	"github.com/spf13/cobra"
	"github.com/teamycloud/tsctl/pkg/docker-proxy"
	"github.com/teamycloud/tsctl/pkg/docker-proxy/types"

	_ "github.com/teamycloud/tsctl/pkg/ts-tunnel/forwarding-protocol"
	_ "github.com/teamycloud/tsctl/pkg/ts-tunnel/synchronization-protocol"
)

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
		tsTunnelInsecure bool   // whether can we skip tls verification
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the local proxy for Tinyscale Container API",
		Long:  `Start the TCP proxy server that forwards Container API calls to a remote daemon over running Tinyscale`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create the root logger.
			logLevel := logging.LevelInfo
			if l, ok := logging.NameToLevel(logLevelFlag); !ok {
				fmt.Printf("WARNING: invalid log level specified in environment: %s, default log level 'info' will be used\n", logLevelFlag)
			} else {
				logLevel = l
			}
			logger := logging.NewLogger(logLevel, os.Stderr)

			// Attempt to acquire the daemon lock and defer its release.
			lock, err := daemon.AcquireLock()
			if err != nil {
				return fmt.Errorf("unable to acquire daemon lock: %w, tsctl daemon probably is already running", err)
			}
			defer lock.Release()

			// Create a channel to track termination signals. We do this before creating
			// and starting other infrastructure so that we can ensure things terminate
			// smoothly, not mid-initialization.
			signalTermination := make(chan os.Signal, 2)
			signal.Notify(signalTermination, syscall.SIGINT, syscall.SIGTERM)

			cfg := types.Config{
				ListenAddr:    listenAddr,
				TransportType: types.TransportSSH,
				SSHUser:       sshUser,
				SSHHost:       sshHost,
				SSHKeyPath:    sshKeyPath,
				RemoteDocker:  remoteDocker,
			}

			remoteAddr := ""
			if cfg.SSHHost != "" {
				remoteAddr = fmt.Sprintf("%s@%s", cfg.SSHUser, cfg.SSHHost)
			} else if tsTunnelServer != "" {
				cfg.TransportType = types.TransportTSTunnel
				cfg.TSTunnelServer = tsTunnelServer
				remoteAddr = tsTunnelServer

				if tsTunnelCertFile != "" && tsTunnelKeyFile != "" {
					cfg.TSTunnelCertFile = tsTunnelCertFile
					cfg.TSTunnelKeyFile = tsTunnelKeyFile

				}

				if tsTunnelCAFile != "" {
					cfg.TSTunnelCAFile = tsTunnelCAFile
				}
				cfg.TSInsecure = tsTunnelInsecure
			} else {
				panic("We need to connect to remote docker daemon by either SSH or ts-tunnel")
			}

			bannerFormat := `
Starting TCP proxy with %s transport...
  Listen: %s
  Remote: %s
`
			logger.Infof(bannerFormat, (string)(cfg.TransportType), cfg.ListenAddr, remoteAddr)

			forwardingManager, err := forwarding.NewManager(logger.Sublogger("port-forward"))
			if err != nil {
				panic(fmt.Sprintf("unable to create forwarding session manager: %v", err))
			}
			defer forwardingManager.Shutdown()

			synchronizationManager, err := synchronization.NewManager(logger.Sublogger("file-sync"))
			if err != nil {
				panic(fmt.Sprintf("unable to create synchronization session manager: %v", err))
			}
			defer synchronizationManager.Shutdown()

			errCh := make(chan error, 1)

			proxy, err := docker_proxy.NewProxy(cfg, forwardingManager, synchronizationManager, logger.Sublogger("proxy"))
			if err != nil {
				log.Fatalf("Failed to create TCP proxy: %v", err)
			}
			go func() {
				errCh <- proxy.ListenAndServe()
			}()

			log.Println("Proxy started. Press Ctrl+C to stop.")
			log.Printf("Use: export DOCKER_HOST=tcp://%s", cfg.ListenAddr)

			// Wait for termination from a signal, the daemon service, or the gRPC
			// server. We treat termination via the daemon service as a non-error.
			select {
			case s := <-signalTermination:
				logger.Info("Terminating due to signal:", s)
				proxy.Close()
				return fmt.Errorf("terminated by signal: %s", s)
			case err = <-errCh:
				logger.Error("Daemon server failure:", err)
				return fmt.Errorf("daemon server termination: %w", err)
			}
		},
	}

	// Add flags to the start command
	cmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1:2375", "Local address to listen on")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "SSH username")
	cmd.Flags().StringVar(&sshHost, "ssh-host", "", "SSH host and port")
	cmd.Flags().StringVar(&sshKeyPath, "ssh-key", os.Getenv("HOME")+"/.ssh/id_rsa", "Path to SSH private key")
	cmd.Flags().StringVar(&remoteDocker, "remote-docker", "unix:///var/run/docker.sock", "Remote Docker socket URL when using the SSH transport")

	cmd.Flags().StringVar(&tsTunnelServer, "ts-server", "", "Tinyscale server address")
	cmd.Flags().StringVar(&tsTunnelCertFile, "ts-cert", "", "Path to mTLS certificate")
	cmd.Flags().StringVar(&tsTunnelKeyFile, "ts-key", "", "Path to mTLS private key")
	cmd.Flags().StringVar(&tsTunnelCAFile, "ts-ca", "", "Path to accepted Tinyscale CA certificate")
	cmd.Flags().BoolVar(&tsTunnelInsecure, "ts-insecure", false, "Skip tlsconfig verification when connecting to Tinyscale server")

	cmd.Flags().StringVar(&logLevelFlag, "log-level", "info", "Log level")
	return cmd
}
