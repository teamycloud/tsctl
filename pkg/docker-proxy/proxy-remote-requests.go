package docker_proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

// getContainerID fetches the full container ID from Docker API given a name or short ID
func (p *DockerAPIProxy) getContainerID(apiVersion string, containerIDOrName string) string {
	// Create a new connection to query container info
	conn, err := p.dialRemote()
	if err != nil {
		log.Printf("Failed to dial remote Docker for container ID lookup: %v", err)
		return ""
	}
	defer conn.Close()

	// Build the inspect request
	requestPath := fmt.Sprintf("/v%s/containers/%s/json", apiVersion, containerIDOrName)
	req, err := http.NewRequest("GET", requestPath, nil)
	if err != nil {
		log.Printf("Failed to create container inspect request: %v", err)
		return ""
	}
	req.Host = "docker.example.com"
	req.Header.Set("User-Agent", "tsctl/1.0.0")

	// Send the request
	if err := req.Write(conn); err != nil {
		log.Printf("Failed to send container inspect request: %v", err)
		return ""
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Failed to read container inspect response: %v", err)
		return ""
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		log.Printf("Container inspect returned status %d for %s (container may not exist)", resp.StatusCode, containerIDOrName)
		return ""
	}

	// Parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read container inspect response body: %v", err)
		return ""
	}

	// Parse JSON to get container ID
	var inspectResp struct {
		Id string `json:"Id"`
	}

	if err := json.Unmarshal(body, &inspectResp); err != nil {
		log.Printf("Failed to parse container inspect response: %v", err)
		return ""
	}

	return inspectResp.Id
}

// isContainerRunning checks if a container exists and is running on the remote host
func (p *DockerAPIProxy) isContainerRunning(containerID string) bool {
	// Create a new connection to query container state
	conn, err := p.dialRemote()
	if err != nil {
		log.Printf("Failed to dial remote Docker for container check: %v", err)
		return false
	}
	defer conn.Close()

	// Build the inspect request
	req, err := http.NewRequest("GET", fmt.Sprintf("/containers/%s/json", containerID), nil)
	if err != nil {
		log.Printf("Failed to create inspect request: %v", err)
		return false
	}
	req.Host = "docker.example.com"
	req.Header.Set("User-Agent", "tsctl/1.0.0")

	// Send the request
	if err := req.Write(conn); err != nil {
		log.Printf("Failed to send inspect request: %v", err)
		return false
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Failed to read inspect response: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		log.Printf("Container %s does not exist (status %d)", containerID, resp.StatusCode)
		return false
	}

	// Parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read inspect response body: %v", err)
		return false
	}

	// Parse JSON to get container state
	var inspectResp struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}

	if err := json.Unmarshal(body, &inspectResp); err != nil {
		log.Printf("Failed to parse inspect response: %v", err)
		return false
	}

	isRunning := inspectResp.State.Running
	log.Printf("Container %s state: Running=%v, Status=%s", containerID, inspectResp.State.Running, inspectResp.State.Status)

	return isRunning
}

// isContainerStopped checks if a container is actually stopped by inspecting its state
func (p *DockerAPIProxy) isContainerStopped(containerID string) bool {
	// Create a new connection to query container state
	conn, err := p.dialRemote()
	if err != nil {
		log.Printf("Failed to dial remote Docker for state check: %v", err)
		return false
	}
	defer conn.Close()

	// Build the inspect request
	req, err := http.NewRequest("GET", fmt.Sprintf("/containers/%s/json", containerID), nil)
	if err != nil {
		log.Printf("Failed to create inspect request: %v", err)
		return false
	}
	req.Host = "localhost"

	// Send the request
	if err := req.Write(conn); err != nil {
		log.Printf("Failed to send inspect request: %v", err)
		return false
	}

	// Read the response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		log.Printf("Failed to read inspect response: %v", err)
		return false
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		log.Printf("Container inspect returned status %d (container may be removed)", resp.StatusCode)
		return true // If container doesn't exist, consider it stopped
	}

	// Parse the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read inspect response body: %v", err)
		return false
	}

	// Parse JSON to get container state
	var inspectResp struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}

	if err := json.Unmarshal(body, &inspectResp); err != nil {
		log.Printf("Failed to parse inspect response: %v", err)
		return false
	}

	// Container is stopped if not running
	isStopped := !inspectResp.State.Running
	log.Printf("Container %s state: Running=%v, Status=%s", containerID, inspectResp.State.Running, inspectResp.State.Status)

	return isStopped
}
