package commands_guest

import (
	"fmt"
	"log"
	"net/http"
)

func RunServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/command", handleCommand)
	mux.HandleFunc("/copy", handleCopy)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting guest agent on %s", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
