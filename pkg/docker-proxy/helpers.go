package docker_proxy

import (
	"net/http"
	"regexp"
)

// isConnectionUpgrade checks if the response indicates a protocol upgrade
func isConnectionUpgrade(resp *http.Response) bool {
	// Check for 101 Switching Protocols or Upgrade header
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return true
	}

	// Also check for Upgrade header in the response
	if resp.Header.Get("Upgrade") != "" {
		return true
	}

	return false
}

// shouldCloseConnection determines if the connection should be closed after the response
func shouldCloseConnection(req *http.Request, resp *http.Response) bool {
	// Check response Connection header
	if resp.Header.Get("Connection") == "close" {
		return true
	}

	// Check request Connection header
	if req.Header.Get("Connection") == "close" {
		return true
	}

	// HTTP/1.0 defaults to close unless Keep-Alive is specified
	if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
		return req.Header.Get("Connection") != "Keep-Alive"
	}

	// HTTP/1.1 defaults to keep-alive
	return false
}

// extractAPIVersion extracts the API version from a Docker API request path
// e.g., "/v1.45/containers/abc/remove" -> "1.45"
func extractAPIVersion(path string) string {
	// Match pattern like /v1.45/...
	pattern := regexp.MustCompile(`^/v([\d.]+)/`)
	matches := pattern.FindStringSubmatch(path)
	if len(matches) > 1 {
		return matches[1]
	}
	// Default to 1.45 if not found
	return "1.45"
}
