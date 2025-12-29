package guest

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func handleCreateDirectories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Invalid request content", http.StatusBadRequest)
		return
	}

	var paths []string
	if err = json.Unmarshal(body, &paths); err != nil {
		http.Error(w, "Invalid request JSON content", http.StatusBadRequest)
		return
	}

	for _, path := range paths {
		if err := os.MkdirAll(path, 0755); err != nil {
			e := fmt.Sprintf("Failed to create directory '%s': %v", path, err)
			log.Printf(e)
			http.Error(w, e, http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Created directory: %s\n", path)
	}
}
