// Package ts_tunnel provides an agent transport implementation that operates
// over mTLS-enabled TCP connections. This transport is designed to work with
// a server that provides connection upgrade capabilities via HTTP UPGRADE to
// establish a raw TCP stream suitable for mutagen agent communication.
//
// The transport supports:
// - mTLS authentication using client certificates
// - SNI-based routing to different remote hosts
// - HTTP UPGRADE to establish bidirectional TCP streams
// - Standard mutagen agent operations (command execution and file copying)
//
// Note: Unlike SSH, this transport does not provide direct process execution
// capabilities. Instead, it relies on a server-side component that maintains
// persistent agent connections and routes commands accordingly.
package ts_tunnel

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	urlpkg "github.com/mutagen-io/mutagen/pkg/url"
)

const (
	// Protocol_Tstunnel is a custom protocol value for ts-tunnel transport.
	// We use value 100 to avoid conflicts with mutagen's built-in protocols (0, 1, 11).
	Protocol_Tstunnel urlpkg.Protocol = 100
)

// ParseTSTunnelURL parses a tstunnel:// URL and converts it to a mutagen URL.
// Format: tstunnel://<server-addr>/<path>?cert=<cert>&key=<key>[&ca=<ca>]
func ParseTSTunnelURL(rawURL string, kind urlpkg.Kind) (*urlpkg.URL, error) {
	// Check if this is a tstunnel URL
	if !strings.HasPrefix(rawURL, "tstunnel://") {
		// Not a tstunnel URL, parse normally
		return urlpkg.Parse(rawURL, kind, true)
	}

	// Parse the URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tstunnel URL: %w", err)
	}

	// Extract parameters from query string
	query := parsedURL.Query()
	params := make(map[string]string)
	for key, values := range query {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}

	// cert and key are optional - omit them for insecure dev/debug scenarios
	// If one is provided, both must be provided
	serverAddr := parsedURL.Host
	if serverAddr == "" {
		return nil, fmt.Errorf("tstunnel URL requires server-addr to be set")
	}

	certFile := params["cert"]
	keyFile := params["key"]
	if (certFile != "" && keyFile == "") || (certFile == "" && keyFile != "") {
		return nil, fmt.Errorf("tstunnel URL requires both 'cert' and 'key' parameters or neither")
	}

	// Construct SNI from serverName and serverAddr domain.
	port := parsedURL.Port()
	if port == "" {
		if UseTLS(certFile, keyFile, params["ca"], params["insecure"] != "") {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		portNumber = 80
	}

	mutagenURL := &urlpkg.URL{
		Kind:       kind,
		Protocol:   Protocol_Tstunnel,
		Host:       parsedURL.Hostname(),
		Port:       (uint32)(portNumber),
		Path:       parsedURL.Path,
		Parameters: params,
	}

	return mutagenURL, nil
}

func UseTLS(clientCert, clientKey, caCert string, insecure bool) bool {
	return (clientCert != "" && clientKey != "") || caCert != "" || insecure
}

func IsTLSPort(serverAddr string) bool {
	_, p, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return false
	}
	return p == "443"
}

func URLHostName(serverAddr string) string {
	h, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return ""
	}
	return h
}

func URLPort(serverAddr string) int {
	_, p, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return 0
	}
	pn, err := strconv.Atoi(p)
	if err != nil {
		return 0
	}
	return pn
}
