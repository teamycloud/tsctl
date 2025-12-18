package agent

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"regexp"
)

var (
	// Pattern to match /containers/{id}/attach
	attachPathPattern = regexp.MustCompile(`^/v[\d.]+/containers/[^/]+/attach$`)
	// Pattern to match /containers/{id}/start
	startPathPattern = regexp.MustCompile(`^/v[\d.]+/containers/[^/]+/start$`)
)

func NewRouter(proxy *DockerProxy) http.Handler {
	mux := http.NewServeMux()

	// Generic catch-all, proxy to Docker API, but with special handling
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		DumpRequestSafe(r)
		log.Printf(">>> Handler START: %s %s", r.Method, r.URL.Path)
		defer log.Printf("<<< Handler END: %s %s\n", r.Method, r.URL.Path)

		// Log if this is a start request
		if startPathPattern.MatchString(r.URL.Path) {
			log.Printf("!!! DETECTED START REQUEST !!!")
		}

		switch {
		//case r.Method == http.MethodPost && r.URL.Path == "/containers/create":
		//	proxy.HandleCreateContainer(w, r)
		case r.Method == http.MethodPost && attachPathPattern.MatchString(r.URL.Path):
			proxy.HandleAttach(w, r)
		default:
			proxy.HandleGeneric(w, r)
		}
	})

	return mux
}

func DumpRequestSafe(r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	b, err := httputil.DumpRequest(r, false) // headers only
	if err != nil {
		log.Printf("dump request error: %v", err)
		return
	}

	log.Printf("HTTP request:\n%s", b)
	log.Printf("HTTP body:\n%s", body)

	// restore again in case DumpRequest touched it
	r.Body = io.NopCloser(bytes.NewReader(body))
	log.Printf("\n===================================\n")
}

func DumpResponseSafe(resp *http.Response) {
	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}

	b, err := httputil.DumpResponse(resp, false) // headers only
	if err != nil {
		log.Printf("dump response error: %v", err)
		return
	}

	log.Printf("HTTP response:\n%s", b)
	log.Printf("Response body:\n%s", body)

	// restore again in case DumpResponse touched it
	resp.Body = io.NopCloser(bytes.NewReader(body))
	log.Printf("\n===================================\n")
}
