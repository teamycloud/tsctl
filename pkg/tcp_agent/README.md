# TCP Agent - TCP-based Docker API Proxy

The `tcp_agent` package provides TCP-based proxies for Docker API over SSH tunnels with HTTP-level interception capabilities.

## Features

- **HTTP-Aware Interception**: Parse and intercept specific Docker API calls (e.g., container create)
- **Selective Transparency**: Intercept only specific endpoints while maintaining transparent TCP proxy for others
- **Docker API Dumping**: Log and inspect Docker API requests and responses
- **Transparent Fallback**: Automatically falls back to transparent TCP proxy for non-HTTP traffic
- **SSH Tunneling**: Secure connection to remote Docker daemons

## Architecture

```
┌─────────────┐       ┌──────────────┐       ┌─────────┐       ┌──────────────┐
│ Docker CLI  │──TCP─→│  TCP Proxy   │──SSH─→│ Remote  │──────→│ Docker       │
│             │       │  (HTTP-Aware)│       │ Host    │       │ Daemon       │
└─────────────┘       └──────────────┘       └─────────┘       └──────────────┘
                            │
                            ├─ Parse HTTP requests
                            ├─ Intercept specific endpoints
                            ├─ Dump request/response
                            └─ Transparent proxy for others
```

## Components

### 1. HTTP-Aware TCP Proxy (`tcp_proxy.go`)

A smart proxy that can parse HTTP traffic and intercept specific Docker API calls while maintaining transparent proxy behavior for other requests.

**Key capabilities**:
- **HTTP Keep-Alive Support**: Handles multiple HTTP requests on the same TCP connection
- Parses HTTP requests on the fly
- Intercepts specific Docker API endpoints (e.g., `/containers/create`)
- Dumps intercepted requests for debugging/logging
- Falls back to transparent TCP proxy for non-HTTP traffic
- Detects protocol upgrades (e.g., Docker attach with `101 Switching Protocols`)
- Properly handles connection lifecycle (keep-alive vs close)

**Use case**: When you need to inspect, log, or modify specific Docker API calls while keeping everything else transparent.

**How it works**:
1. Accepts TCP connection from Docker client
2. Parses incoming data as HTTP requests
3. For each request on the connection:
   - If it matches an intercepted endpoint → logs/dumps the request
   - Forwards request to remote Docker daemon
   - Forwards response back to client
4. Handles multiple requests on same connection (HTTP/1.1 Keep-Alive)
5. Switches to transparent TCP proxy mode for protocol upgrades (attach, exec)

```go
cfg := tcp_agent.Config{
    ListenAddr:      "127.0.0.1:2375",
    RemoteAddress:   "remote.example.com:2376",  // or unix socket path
}

proxy, err := tcp_agent.NewTCPProxy(cfg)
if err != nil {
    log.Fatal(err)
}
defer proxy.Close()

if err := proxy.ListenAndServe(); err != nil {
    log.Fatal(err)
}
```

**Intercepted endpoints** (currently):
- `POST /v*/containers/create` - Container creation requests

**Example output** when intercepting a container create:
```
!!! INTERCEPTING: POST /v1.45/containers/create !!!
=== INTERCEPTED HTTP REQUEST ===
POST /v1.45/containers/create HTTP/1.1
Host: 127.0.0.1:2375
Content-Type: application/json
...
Body:
{"Image":"hello-world","HostConfig":{"PortBindings":{...}},...}
================================
Proxying: POST /v1.45/containers/eed15a.../wait?condition=next-exit
Waiting for next request on connection from 127.0.0.1:61274
```

Note: The same TCP connection (identified by source port) can carry multiple Docker API requests. The proxy correctly handles this HTTP Keep-Alive behavior.

You can easily add more endpoints by modifying the `shouldInterceptRequest()` function.

### 2. Docker-aware TCP Proxy (`docker_tcp_proxy.go`)

An HTTP-aware proxy that can parse Docker API requests and responses, allowing interception and modification.

**Use case**: When you need to intercept container creation, modify port mappings, adjust volumes, or add custom logic to Docker API calls.

```go
cfg := tcp_agent.Config{
    ListenAddr:      "127.0.0.1:2375",
    SSHUser:         "root",
    SSHHost:         "remote.example.com:22",
    SSHKeyPath:      "/home/user/.ssh/id_rsa",
    RemoteDockerURL: "unix:///var/run/docker.sock",
}

proxy, err := tcp_agent.NewDockerTCPProxy(cfg)
if err != nil {
    log.Fatal(err)
}
defer proxy.Close()

// Enable container creation interception
proxy.InterceptCreateContainer()

// Add custom request hook
proxy.SetBeforeRequestHook(func(req *http.Request) error {
    log.Printf("Intercepting: %s %s", req.Method, req.URL.Path)
    // Modify request here
    return nil
})

// Add custom response hook
proxy.SetAfterResponseHook(func(resp *http.Response) error {
    log.Printf("Response status: %d", resp.StatusCode)
    // Process response here
    return nil
})

if err := proxy.ListenAndServe(); err != nil {
    log.Fatal(err)
}
```

## Configuration

```go
type Config struct {
    ListenAddr      string // Local address to listen on (e.g., "127.0.0.1:2375")
    SSHUser         string // SSH username
    SSHHost         string // SSH host:port (e.g., "remote.example.com:22")
    SSHKeyPath      string // Path to SSH private key
    RemoteDockerURL string // Remote Docker socket (e.g., "unix:///var/run/docker.sock" or "tcp://localhost:2376")
}
```

## Usage with Docker CLI

Once the proxy is running, configure your Docker CLI to use it:

```bash
export DOCKER_HOST=tcp://127.0.0.1:2375
docker ps
docker run -it ubuntu bash
```

## Key Differences from HTTP Agent

| Feature | HTTP Agent (`pkg/agent`) | TCP Agent (`pkg/tcp_agent`) |
|---------|-------------------------|----------------------------|
| Protocol | HTTP only | TCP (transparent) |
| Interception | HTTP handlers | Stream parsing |
| Flexibility | More structured | More transparent |
| Overhead | Higher (HTTP routing) | Lower (direct TCP) |
| Use Case | Complex API modifications | Simple forwarding or lightweight interception |

## Implementation Details

### Transparent Proxy

- Accepts TCP connections on local port
- Establishes SSH connection to remote host
- Dials remote Docker socket through SSH tunnel
- Bidirectional `io.Copy` between client and remote

### Docker-aware Proxy

- Same as transparent proxy, but with HTTP parsing
- Uses `bufio.Reader` to parse HTTP requests/responses
- Calls hooks before/after forwarding
- Falls back to transparent mode if HTTP parsing fails

## Future Enhancements

- [ ] Connection pooling for better performance
- [ ] TLS support for local connections
- [ ] Metrics and monitoring hooks
- [ ] Request/response logging options
- [ ] Support for WebSocket/hijacked connections (exec, attach, logs -f)
- [ ] Automatic port forwarding setup
- [ ] Volume path translation for bind mounts

## See Also

- `pkg/agent` - HTTP-based Docker API proxy with more sophisticated features
- `ssh_client.go` - SSH client implementation
