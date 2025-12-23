package commands_guest

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func handleCopy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/octet-stream" {
		http.Error(w, "Content-Type must be application/octet-stream", http.StatusBadRequest)
		return
	}

	// Get the file path from query parameters
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Path query parameter is required", http.StatusBadRequest)
		return
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("Failed to create directory: %v", err), http.StatusInternalServerError)
		return
	}

	// Create the file (replace if exists)
	file, err := os.Create(filePath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create file: %v", err), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get the reader (handle gzip if needed)
	var reader io.Reader = r.Body
	contentEncoding := r.Header.Get("Content-Encoding")
	if strings.ToLower(contentEncoding) == "gzip" {
		gzipReader, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to create gzip reader: %v", err), http.StatusBadRequest)
			return
		}
		defer gzipReader.Close()
		reader = gzipReader
	}

	// Copy data from request body to file
	written, err := io.Copy(file, reader)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to write file: %v", err), http.StatusInternalServerError)
		return
	}

	log.Printf("Successfully wrote %d bytes to %s", written, filePath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}
