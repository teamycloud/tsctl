package docker_proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/teamycloud/tsctl/pkg/docker-proxy/mutagen-bridge"
	"github.com/teamycloud/tsctl/pkg/docker-proxy/types"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
)

// rewriteBindMount rewrites a bind mount string by replacing the host path with a remote sync path
// Input format: "source:target[:ro]"
// Output format: "/opt/container-mount-sync/target:target[:ro]"
func rewriteBindMount(bind string, basePath string) string {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 {
		// Invalid format, return as-is
		return bind
	}

	// parts[0] = source (host path)
	// parts[1] = target (container path)
	// parts[2+] = optional flags (e.g., "ro")

	source := parts[0]
	target := parts[1]
	newSource := fmt.Sprintf("%s%s", basePath, source)

	if len(parts) == 2 {
		return fmt.Sprintf("%s:%s", newSource, target)
	} else {
		// Preserve any additional flags
		flags := strings.Join(parts[2:], ":")
		return fmt.Sprintf("%s:%s:%s", newSource, target, flags)
	}
}

// createRemoteMountDirectories creates all mount directories on the remote host
// It resolves original local paths and creates directories based on whether they are
// directories or files (creating parent directory for files)
func (p *DockerAPIProxy) createRemoteMountDirectories(mounts *mutagen_bridge.ContainerMounts) error {
	log.Printf("Creating remote mount directories for container")

	var remotePaths []string

	for _, mount := range mounts.Mounts {
		// Get the original local path
		localPath := mount.HostPath

		// Determine the remote path based on the sync base path
		// The remote path is: SyncBasePath + localPath
		remotePath := fmt.Sprintf("%s%s", mutagen_bridge.SyncBasePath, localPath)

		// Check if the local path is a directory or file
		info, err := os.Stat(localPath)
		if err != nil {
			log.Printf("Warning: cannot stat local path %s: %v", localPath, err)
			continue
		}

		var dirToCreate string
		if info.IsDir() {
			// If it's a directory, create it on remote
			dirToCreate = remotePath
			log.Printf("Local path %s is a directory, will create %s on remote", localPath, dirToCreate)
		} else {
			// If it's a file, create its parent directory on remote
			dirToCreate = filepath.Dir(remotePath)
			log.Printf("Local path %s is a file, will create parent directory %s on remote", localPath, dirToCreate)
		}

		cmd := fmt.Sprintf("mkdir -p '%s'", dirToCreate)
		log.Printf("Executing on remote host: %s", cmd)
		if p.cfg.TransportType == types.TransportSSH {
			if output, err := p.sshClient.ExecuteCommand(cmd); err != nil {
				log.Printf("Failed to create directory %s on remote host: %v, output: %s", dirToCreate, err, output)
				// Continue with other mounts even if one fails
				continue
			}
		} else {
			remotePaths = append(remotePaths, dirToCreate)
		}

		log.Printf("Successfully created directory %s on remote host", dirToCreate)

	}

	if p.cfg.TransportType == types.TransportTSTunnel && len(remotePaths) > 0 {
		if err := p.createDirsByTsTunnel(remotePaths); err != nil {
			return err
		}
	}

	return nil
}

// createDirsByTsTunnel create the directories on the remote container engine host
func (p *DockerAPIProxy) createDirsByTsTunnel(dirsToCreate []string) error {
	conn, err := p.dialRemote()
	if err != nil {
		return fmt.Errorf("failed to dial remote host: %v", err)
	}
	defer conn.Close()

	// Build the inspect request
	requestPath := "/tinyscale/v1/host-exec/directories"
	req, err := http.NewRequest("POST", requestPath, nil)
	if err != nil {
		return fmt.Errorf("failed to create directories on remote host: %v", err)
	}
	req.Host = ts_tunnel.URLHostName(p.tsTunnelOpts.ServerAddr)
	req.Header.Set("User-Agent", "tsctl/1.0.0")
	req.Header.Set("Content-Type", "application/json")

	reqBody, _ := json.Marshal(dirsToCreate)
	req.ContentLength = int64(len(reqBody))
	req.Body = io.NopCloser(bytes.NewReader(reqBody))

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("failed to send directories creation request: %v", err)
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return fmt.Errorf("failed to read directories creation response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read directories creation response body: %v", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("directories creation request returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
