package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/docker/docker/api/types/container"
)

type DockerProxy struct {
	cfg       Config
	sshClient *SSHClient
}

func NewDockerProxy(cfg Config, sshClient *SSHClient) *DockerProxy {
	return &DockerProxy{
		cfg:       cfg,
		sshClient: sshClient,
	}
}

// HandleCreateContainer adds port-forward + bind-mount logic, then proxies.
func (p *DockerProxy) HandleCreateContainer(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		Config     container.Config     `json:"Config"`
		HostConfig container.HostConfig `json:"HostConfig"`
		// other fields omitted
	}

	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// 1. Handle port forwarding
	if err := p.setupPortForwards(&req.HostConfig); err != nil {
		http.Error(w, fmt.Sprintf("port forward error: %v", err), http.StatusInternalServerError)
		return
	}

	// 2. Handle local bind mounts -> remote paths
	newBinds, err := p.rewriteBindMounts(req.HostConfig.Binds)
	if err != nil {
		http.Error(w, fmt.Sprintf("bind rewrite error: %v", err), http.StatusInternalServerError)
		return
	}
	req.HostConfig.Binds = newBinds

	// 3. Re-marshal modified request
	newBody, err := json.Marshal(req)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}

	// 4. Proxy to remote Docker
	resp, err := p.proxyRawRequest(r.Method, r.URL, r.Header, newBody)
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	DumpResponseSafe(resp)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *DockerProxy) HandleAttach(w http.ResponseWriter, r *http.Request) {
	fmt.Println("handling attach")

	// 1. Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	// 2. Dial remote Docker via SSH
	remoteConn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		clientConn.Close()
		return
	}

	// 3. Forward the ORIGINAL request exactly as bytes
	if err := r.Write(remoteConn); err != nil {
		clientConn.Close()
		remoteConn.Close()
		return
	}

	// 4. Copy response headers from remote to client in chunks,
	//    stopping *exactly* at the end of the header section (\r\n\r\n).
	//    We don't parse; we just detect the delimiter.
	const headerTerminator = "\r\n\r\n"
	headerBuf := make([]byte, 0, 4096)
	tmp := make([]byte, 64)
	var extraBytes []byte

	for {
		n, err := remoteConn.Read(tmp)
		if n > 0 {
			headerBuf = append(headerBuf, tmp[:n]...)
			// Check if we've received the header terminator
			if idx := bytes.Index(headerBuf, []byte(headerTerminator)); idx != -1 {
				// Found the terminator at position idx
				// Split: header ends at idx + len(terminator)
				headerEnd := idx + len(headerTerminator)
				extraBytes = make([]byte, len(headerBuf)-headerEnd)
				copy(extraBytes, headerBuf[headerEnd:])
				headerBuf = headerBuf[:headerEnd]
				break
			}
		}
		if err != nil {
			// EOF before headers complete = error
			clientConn.Close()
			remoteConn.Close()
			return
		}
	}

	fmt.Println("writing response header to client, length:", len(headerBuf))
	// Write through immediately so client sees the same bytes
	if _, werr := clientConn.Write(headerBuf); werr != nil {
		clientConn.Close()
		remoteConn.Close()
		return
	}

	// If we read extra bytes beyond the header, write them to the client first
	if len(extraBytes) > 0 {
		if _, werr := clientConn.Write(extraBytes); werr != nil {
			clientConn.Close()
			remoteConn.Close()
			return
		}
	}

	pipe := func(writer, reader net.Conn) {
		defer func(writer net.Conn) {
			_ = writer.Close()
		}(writer)
		defer func(reader net.Conn) {
			_ = reader.Close()
		}(reader)

		_, err := io.Copy(writer, reader)
		if err != nil {
			fmt.Printf("port forward failed: %s\n", err)
			return
		}
	}

	// 5. From here on, it's raw multiplexed stream in both directions.
	go pipe(clientConn, remoteConn)
	go pipe(remoteConn, clientConn)
}

func (p *DockerProxy) HandleGeneric(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body error", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	resp, err := p.proxyRawRequest(r.Method, r.URL, r.Header, body)
	if err != nil {
		http.Error(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	DumpResponseSafe(resp)

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *DockerProxy) proxyRawRequest(method string, u *url.URL, hdr http.Header, body []byte) (*http.Response, error) {
	// Dial remote Docker via SSH
	conn, err := p.sshClient.DialRemoteDocker()
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return conn, nil
		},
	}

	client := &http.Client{Transport: transport}

	remoteURL := &url.URL{
		Scheme:   "http",
		Host:     "docker", // ignored due to custom DialContext
		Path:     u.Path,
		RawQuery: u.RawQuery,
	}

	req, err := http.NewRequest(method, remoteURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = hdr.Clone()

	return client.Do(req)
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
