package commands_guest

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CommandRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Envs    []string `json:"envs,omitempty"`
}

func handleCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check for Upgrade header
	if strings.ToLower(r.Header.Get("Upgrade")) != "tcp" {
		http.Error(w, "Upgrade: tcp header required", http.StatusBadRequest)
		return
	}

	// Parse JSON request body
	var cmdReq CommandRequest
	if err := json.NewDecoder(r.Body).Decode(&cmdReq); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if cmdReq.Command == "" {
		http.Error(w, "Command is required", http.StatusBadRequest)
		return
	}

	if existStatus := commandExists(cmdReq.Command); existStatus != http.StatusOK {
		http.Error(w, fmt.Sprintf("Command not found or not executable"), existStatus)
		return
	}

	runCommand(&cmdReq, w)
}

func runCommand(cmdReq *CommandRequest, w http.ResponseWriter) {
	// Hijack the connection to upgrade to TCP
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("Hijack failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Send 101 Switching Protocols response
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: tcp\r\n" +
		"Connection: Upgrade\r\n" +
		"\r\n"

	if _, err := bufrw.WriteString(response); err != nil {
		log.Printf("Failed to write upgrade response: %v", err)
		return
	}
	if err := bufrw.Flush(); err != nil {
		log.Printf("Failed to flush upgrade response: %v", err)
		return
	}

	// Register the connection
	processRegistry.AddConnection(conn)
	defer processRegistry.RemoveConnection(conn)

	// Start the process
	cmd := exec.Command(cmdReq.Command, cmdReq.Args...)

	// Set environment variables if provided
	if len(cmdReq.Envs) > 0 {
		// Start with the current environment
		cmd.Env = os.Environ()
		// Append the custom environment variables
		cmd.Env = append(cmd.Env, cmdReq.Envs...)
	}

	// Get stdin pipe
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("Failed to create stdin pipe: %v", err)
		return
	}

	// Get stdout pipe
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		return
	}

	log.Printf("Running command: %s %s", cmdReq.Command, strings.Join(cmdReq.Args, " "))
	// Start the command
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start command: %v", err)
		return
	}

	// Register the process for graceful termination
	processRegistry.AddProcess(cmd.Process)
	defer processRegistry.RemoveProcess(cmd.Process)

	// Pipe connection to stdin
	go func() {
		_, _ = io.Copy(stdin, conn)
		_ = stdin.Close()
	}()

	// Pipe stdout to connection
	go func() {
		_, _ = io.Copy(conn, stdout)
	}()

	// we don't pipe stderr (just ignore it)

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		log.Printf("Command finished with error: %v", err)
	}
}

func commandExists(cmd string) int {
	if _, err := exec.LookPath(cmd); err != nil {
		// If LookPath fails, try to check if it's an absolute path
		if filepath.IsAbs(cmd) {
			info, statErr := os.Stat(cmd)
			if statErr != nil {
				return http.StatusNotFound
			}
			// Check if it's executable (on Unix-like systems)
			if info.Mode()&0111 == 0 {
				return http.StatusForbidden
			}
		} else {
			return http.StatusNotFound
		}
	}

	return http.StatusOK
}
