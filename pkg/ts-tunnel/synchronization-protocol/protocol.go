// Package synchronization_protocol provides protocol handlers for connecting to remote endpoints
// via tstunnel (mTLS-enabled TCP) transport for synchronization operations.
package synchronization_protocol

import (
	"context"
	"fmt"
	"io"

	"github.com/mutagen-io/mutagen/pkg/agent"
	"github.com/mutagen-io/mutagen/pkg/logging"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	"github.com/mutagen-io/mutagen/pkg/synchronization/endpoint/remote"
	urlpkg "github.com/mutagen-io/mutagen/pkg/url"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
	tstunneltransport "github.com/teamycloud/tsctl/pkg/ts-tunnel/agent-transport"
)

// ProtocolHandler implements the synchronization.ProtocolHandler interface for
// connecting to remote endpoints over tstunnel (mTLS-enabled TCP). It uses
// the agent infrastructure over a tstunnel transport.
type ProtocolHandler struct{}

// dialResult provides asynchronous agent dialing results.
type dialResult struct {
	// stream is the stream returned by agent dialing.
	stream io.ReadWriteCloser
	// error is the error returned by agent dialing.
	error error
}

// Connect connects to a tstunnel endpoint.
func (h *ProtocolHandler) Connect(
	ctx context.Context,
	logger *logging.Logger,
	url *urlpkg.URL,
	prompter string,
	session string,
	version synchronization.Version,
	configuration *synchronization.Configuration,
	alpha bool,
) (synchronization.Endpoint, error) {
	// Verify that the URL is of the correct kind and protocol.
	if url.Kind != urlpkg.Kind_Synchronization {
		panic("non-synchronization URL dispatched to synchronization protocol handler")
	}
	// Note: Protocol check would go here once tstunnel is added to Protocol enum

	// Create a tstunnel transport.
	transport, err := tstunneltransport.NewTransport(ts_tunnel.ServerOptions{
		ServerAddr: fmt.Sprintf("%s:%d", url.Host, url.Port),
		CertFile:   url.Parameters["cert"],
		KeyFile:    url.Parameters["key"],
		CAFile:     url.Parameters["ca"],
		Insecure:   url.Parameters["insecure"] != "",
	}, prompter)
	if err != nil {
		return nil, fmt.Errorf("unable to create tstunnel transport: %w", err)
	}

	// Create a channel to deliver the dialing result.
	results := make(chan dialResult)

	// Perform dialing in a background Goroutine so that we can monitor for
	// cancellation.
	go func() {
		// Perform the dialing operation.
		stream, err := agent.Dial(logger, transport, agent.CommandSynchronizer, prompter)

		// Transmit the result or, if cancelled, close the stream.
		select {
		case results <- dialResult{stream, err}:
		case <-ctx.Done():
			if stream != nil {
				stream.Close()
			}
		}
	}()

	// Wait for dialing results or cancellation.
	var stream io.ReadWriteCloser
	select {
	case result := <-results:
		if result.error != nil {
			return nil, fmt.Errorf("unable to dial agent endpoint: %w", result.error)
		}
		stream = result.stream
	case <-ctx.Done():
		return nil, context.Canceled
	}

	// Create the endpoint.
	return remote.NewEndpoint(logger, stream, url.Path, session, version, configuration, alpha)
}

// init registers the ts-tunnel protocol handlers with mutagen.
// This must be called before using ts-tunnel transport for synchronization.
func init() {
	// Register the ts-tunnel synchronization protocol handler
	synchronization.ProtocolHandlers[urlpkg.Protocol_Tinyscale] = &ProtocolHandler{}
}
