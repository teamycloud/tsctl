package main

import (
    "log"
    "os"

    "github.com/teamycloud/remote-docker-agent/pkg/agent"
)

func main() {
    cfg := agent.Config{
        ListenAddr:   getenv("AGENT_LISTEN_ADDR", "127.0.0.1:23750"),
        SSHUser:      getenv("AGENT_SSH_USER", "root"),
        SSHHost:      getenv("AGENT_SSH_HOST", "remote.example.com:22"),
        SSHKeyPath:   getenv("AGENT_SSH_KEY_PATH", os.ExpandEnv("$HOME/.ssh/id_rsa")),
        RemoteDocker: "unix:///var/run/docker.sock",
    }

    s, err := agent.NewServer(cfg)
    if err != nil {
        log.Fatalf("failed to create server: %v", err)
    }

    log.Printf("remote-docker-agent listening on %s, proxying to %s via %s@%s",
        cfg.ListenAddr, cfg.RemoteDocker, cfg.SSHUser, cfg.SSHHost)

    if err := s.ListenAndServe(); err != nil {
        log.Fatalf("server error: %v", err)
    }
}

func getenv(key, def string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return def
}
