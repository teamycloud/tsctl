// Package forwarding_protocol provides protocol handlers for connecting to remote endpoints
// via tstunnel (mTLS-enabled TCP) transport for forwarding operations.
package forwarding_protocol

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/mutagen-io/mutagen/pkg/agent"
	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/forwarding/endpoint/remote"
	"github.com/mutagen-io/mutagen/pkg/logging"
	urlpkg "github.com/mutagen-io/mutagen/pkg/url"
	forwardingurlpkg "github.com/mutagen-io/mutagen/pkg/url/forwarding"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
	tstunneltransport "github.com/teamycloud/tsctl/pkg/ts-tunnel/agent-transport"
)

// ProtocolHandler implements the forwarding.ProtocolHandler interface for
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
func (p *ProtocolHandler) Connect(
	ctx context.Context,
	logger *logging.Logger,
	url *urlpkg.URL,
	prompter string,
	session string,
	version forwarding.Version,
	configuration *forwarding.Configuration,
	source bool,
) (forwarding.Endpoint, error) {
	// Verify that the URL is of the correct kind and protocol.
	if url.Kind != urlpkg.Kind_Forwarding {
		panic("non-forwarding URL dispatched to forwarding protocol handler")
	}
	// Note: Protocol check would go here once tstunnel is added to Protocol enum

	// Parse the target specification from the URL's Path component.
	protocol, address, err := forwardingurlpkg.Parse(strings.TrimPrefix(url.Path, "/"))
	if err != nil {
		return nil, fmt.Errorf("unable to parse target specification: %w", err)
	}

	// Create a tstunnel transport.
	transport, err := tstunneltransport.NewTransport(tstunneltransport.TransportOptions{
		ServerAddr: fmt.Sprintf("%s:%d", url.Host, url.Port),
		CertFile:   url.Parameters["cert"],
		KeyFile:    url.Parameters["key"],
		CAFile:     url.Parameters["ca"],
		Insecure:   url.Parameters["insecure"] != "",
		Prompter:   prompter,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create tstunnel transport: %w", err)
	}

	// Create a channel to deliver the dialing result.
	results := make(chan dialResult)

	// Perform dialing in a background Goroutine so that we can monitor for
	// cancellation.
	go func() {
		// Perform the dialing operation.
		stream, err := agent.Dial(logger, transport, agent.CommandForwarder, prompter)

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
	return remote.NewEndpoint(logger, stream, version, configuration, protocol, address, source)
}

// init registers the ts-tunnel protocol handlers with mutagen.
// This must be called before using ts-tunnel transport for forwarding
func init() {
	// Register the ts-tunnel forwarding protocol handler
	forwarding.ProtocolHandlers[ts_tunnel.Protocol_Tstunnel] = &ProtocolHandler{}
}
