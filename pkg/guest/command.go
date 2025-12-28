package guest

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/teamycloud/tsctl/pkg/utils"
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
		http.Error(w, "Command not found or not executable", existStatus)
		return
	}

	runCommand(&cmdReq, w)
}

func runCommand(cmdReq *CommandRequest, w http.ResponseWriter) {
	// 仅允许运行 mutagen agent
	// todo: 处理自动安装逻辑（从待运行的路径中，获取版本，并自动从指定的服务器下载安装）

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
	cmdStdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("Failed to create stdin pipe: %v", err)
		return
	}

	// Get stdout pipe
	cmdStdout, err := cmd.StdoutPipe()
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

	_ = utils.CopyWithSplitMerge(conn, cmdStdout, cmdStdin)

	// we don't pipe stderr (just ignore it), because mutagen doesn't care it

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		log.Printf("Command finished with error: %v", err)
	}
}

func commandExists(cmd string) int {
	// First check if the command is allowed (within executable directory tree)
	allowedPath, allowed := isCommandAllowed(cmd)
	if !allowed {
		log.Printf("Command not allowed: %s", cmd)
		return http.StatusForbidden
	}

	// Check if the command exists and is executable
	info, err := os.Stat(allowedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return http.StatusNotFound
		}
		return http.StatusForbidden
	}

	// Check if it's executable (on Unix-like systems)
	if info.Mode()&0111 == 0 {
		return http.StatusForbidden
	}

	return http.StatusOK
}

// getExecutableDir returns the directory containing the current executable
func getExecutableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	// Resolve symlinks to get the real path
	realPath, err := filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", err
	}
	return filepath.Dir(realPath), nil
}

// isCommandAllowed checks if the command path is within the executable's directory tree
func isCommandAllowed(cmd string) (string, bool) {
	execDir, err := getExecutableDir()
	if err != nil {
		log.Printf("Failed to get executable directory: %v", err)
		return "", false
	}

	var cmdPath string
	if filepath.IsAbs(cmd) {
		// Absolute path: resolve and use directly
		cmdPath = filepath.Clean(cmd)
	} else {
		// Relative path: resolve relative to executable directory
		cmdPath = filepath.Clean(filepath.Join(execDir, cmd))
	}

	// Resolve symlinks to get the real path
	realCmdPath, err := filepath.EvalSymlinks(cmdPath)
	if err != nil {
		// If symlink resolution fails, use the cleaned path
		realCmdPath = cmdPath
	}

	// Check if the real command path is within the executable directory tree
	relPath, err := filepath.Rel(execDir, realCmdPath)
	if err != nil {
		return "", false
	}

	// If the relative path starts with "..", it's outside the directory tree
	if strings.HasPrefix(relPath, "..") || strings.HasPrefix(relPath, string(filepath.Separator)+"..") {
		return "", false
	}

	return realCmdPath, true
}
