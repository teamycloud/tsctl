package ts_tunnel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/teamycloud/tsctl/pkg/utils/tlsconfig"
)

const (
	// upgradeTimeout is the maximum time to wait for the HTTP UPGRADE to complete.
	upgradeTimeout = 30 * time.Second
	// commandTimeout is the maximum time to wait for a command response.
	commandTimeout = 60 * time.Second
)

// ServerOptions provides configuration options for creating a tstunnel transport.
type ServerOptions struct {
	// ServerAddr is the HTTPS serverAddr to connect to (host:port).
	ServerAddr string
	// CertFile is the path to the client certificate file.
	CertFile string
	// KeyFile is the path to the client key file.
	KeyFile string
	// CAFile is the path to the CA certificate file (optional).
	CAFile string

	Insecure bool
}

func Dial(opts *ServerOptions, tlsCfg *tls.Config) (net.Conn, *tls.Config, error) {
	if opts.ServerAddr == "" {
		return nil, nil, errors.New("ServerAddr is required")
	}

	if UseTLS(opts.CertFile, opts.KeyFile, opts.CAFile, opts.Insecure) {
		if tlsCfg == nil {
			tlsCfgBuilder := tlsconfig.NewTLSConfigBuilder().
				WithServerName(URLHostName(opts.ServerAddr)).
				WithClientCertificate(opts.CertFile, opts.KeyFile).
				WithCACertificate(opts.CAFile).
				WithInsecureSkipVerify(opts.Insecure)

			var err error
			tlsCfg, err = tlsCfgBuilder.Build()
			if err != nil {
				return nil, nil, fmt.Errorf("unable to build TLS configuration: %w", err)
			}
		}

		conn, err := tls.Dial("tcp", opts.ServerAddr, tlsCfg)
		if err != nil {
			return nil, tlsCfg, fmt.Errorf("unable to connect to server %s: %w", opts.ServerAddr, err)
		}
		return conn, tlsCfg, nil
	}

	conn, err := net.Dial("tcp", opts.ServerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to connect to server %s: %w", opts.ServerAddr, err)
	}
	return conn, nil, nil
}
