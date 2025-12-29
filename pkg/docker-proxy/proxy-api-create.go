package docker_proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	mutagen_bridge "github.com/teamycloud/tsctl/pkg/docker-proxy/mutagen-bridge"
)

type ContainerCreateResponse struct {
	Id       string   `json:"Id,omitempty"`
	Warnings []string `json:"Warnings,omitempty"`
	Message  string   `json:"Message,omitempty"`
}

// handleContainerCreate extracts port bindings from container create request and stores them
func (p *DockerAPIProxy) handleContainerCreateRequest(req *http.Request) {
	var originalReqBody []byte
	var replacedReqBody []byte

	defer func() {
		if replacedReqBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(replacedReqBody))
			//req.Header.Set("Content-Length", strconv.Itoa(len(replacedReqBody)))
			req.ContentLength = int64(len(replacedReqBody))
			req.Header.Del("Content-Length")
		} else if originalReqBody != nil {
			req.Body = io.NopCloser(bytes.NewReader(originalReqBody))
		}
	}()

	if req.Body != nil {
		rBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Printf("Error reading container create request body: %v", err)
			return
		}
		originalReqBody = rBytes
	}

	// Parse request JSON to get port bindings and bind mounts
	var createReq struct {
		HostConfig struct {
			PortBindings map[string][]struct {
				HostIp   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"PortBindings"`
			Binds  []string `json:"Binds"`
			Mounts []struct {
				Type     string `json:"Type"`
				Source   string `json:"Source"`
				Target   string `json:"Target"`
				ReadOnly bool   `json:"ReadOnly,omitempty"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
	}

	if err := json.Unmarshal(originalReqBody, &createReq); err != nil {
		log.Printf("Failed to parse container create request: %v", err)
		return
	}

	// Extract port bindings
	portBindings := make(map[string][]string)
	for containerPort, bindings := range createReq.HostConfig.PortBindings {
		hostPorts := make([]string, 0)
		for _, binding := range bindings {
			if binding.HostPort != "" {
				hostPorts = append(hostPorts, binding.HostPort)
			}
		}
		if len(hostPorts) > 0 {
			portBindings[containerPort] = hostPorts
			log.Printf("Port binding found: %s -> %v", containerPort, hostPorts)
		}
	}

	if len(portBindings) > 0 {
		p.portForwardMgr.StorePortBindingsStart(req, portBindings)
	}

	mounts := make([]string, 0)
	if len(createReq.HostConfig.Binds) > 0 {
		mounts = append(mounts, createReq.HostConfig.Binds...)
		// insert SyncBasePath into the Binds
	}
	if len(createReq.HostConfig.Mounts) > 0 {
		for _, mount := range createReq.HostConfig.Mounts {
			if mount.Type == "bind" {
				m := fmt.Sprintf("%s:%s", mount.Source, mount.Target)
				if mount.ReadOnly {
					m = fmt.Sprintf("%s:ro", m)
				}
				mounts = append(mounts, m)
			}
		}
		// insert SyncBasePath into the Mounts
	}

	if len(mounts) > 0 {
		log.Printf("Bind mounts found: %d mounts", len(mounts))

		p.fileSyncMgr.StoreBindMountsStart(req, mounts)
		parsedMounts := p.fileSyncMgr.GetMounts(req)
		if parsedMounts != nil && len(parsedMounts.Mounts) > 0 {
			// Create mount directories on remote host before starting
			if err := p.createRemoteMountDirectories(parsedMounts); err != nil {
				log.Printf("Failed to create remote mount directories: %v", err)
			}
		}

		// Rewrite mount paths in the request body using generic map manipulation
		// to preserve all unknown fields
		var createReqMap map[string]interface{}
		if err := json.Unmarshal(originalReqBody, &createReqMap); err != nil {
			log.Printf("Failed to parse request for mount rewriting: %v", err)
		} else {
			needsRewrite := false

			if hostConfig, ok := createReqMap["HostConfig"].(map[string]interface{}); ok {
				// Rewrite HostConfig.Binds (string array format)
				if binds, ok := hostConfig["Binds"].([]interface{}); ok && len(binds) > 0 {
					newBinds := make([]interface{}, 0, len(binds))
					for _, bindIface := range binds {
						if bind, ok := bindIface.(string); ok {
							newBind := rewriteBindMount(bind, mutagen_bridge.SyncBasePath)
							newBinds = append(newBinds, newBind)
							if newBind != bind {
								needsRewrite = true
								log.Printf("Rewriting bind mount: %s -> %s", bind, newBind)
							}
						}
					}
					hostConfig["Binds"] = newBinds
				}

				// Rewrite HostConfig.Mounts (object array format)
				if mountsArray, ok := hostConfig["Mounts"].([]interface{}); ok && len(mountsArray) > 0 {
					for _, mountIface := range mountsArray {
						if mount, ok := mountIface.(map[string]interface{}); ok {
							mountType, _ := mount["Type"].(string)
							if mountType == "bind" {
								source, _ := mount["Source"].(string)
								target, _ := mount["Target"].(string)

								if source != "" && target != "" {
									newSource := fmt.Sprintf("%s%s", mutagen_bridge.SyncBasePath, source)
									if newSource != source {
										mount["Source"] = newSource
										needsRewrite = true
										log.Printf("Rewriting mount source: %s -> %s", source, newSource)
									}
								}
							}
						}
					}
				}
			}

			// Marshal back if we made changes
			if needsRewrite {
				modifiedBody, err := json.Marshal(createReqMap)
				if err != nil {
					log.Printf("Failed to marshal modified request: %v", err)
				} else {
					replacedReqBody = modifiedBody
					log.Printf("Request body rewritten with sync base path modifications")
				}
			}
		}
	}
}

func (p *DockerAPIProxy) handleContainerCreateResponse(req *http.Request, resp *http.Response) {
	if resp.StatusCode != 201 {
		log.Printf("Container create detected with unexpected status code: %d", resp.StatusCode)
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	createResp, err := dumpContainerResponseAndWrite(resp)
	if err != nil || createResp == nil {
		if err != nil {
			log.Printf("Failed to get container create response: %v", err)
		}
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	if createResp.Id == "" {
		log.Printf("No container ID in create response")
		p.portForwardMgr.StorePortBindingsEnd(req, "")
		p.fileSyncMgr.StoreBindMountsEnd(req, "")
		return
	}

	log.Printf("Container created with ID: %s", createResp.Id)
	p.portForwardMgr.StorePortBindingsEnd(req, createResp.Id)
	p.fileSyncMgr.StoreBindMountsEnd(req, createResp.Id)
}

// handleContainerCreate extracts port bindings from container create request and stores them
func dumpContainerResponseAndWrite(resp *http.Response) (*ContainerCreateResponse, error) {
	// Read response body to get container ID
	var respBody bytes.Buffer
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf("Internal agent error: %v", err))))
			return nil, err
		}

		respBody.Write(body)
		resp.Body = io.NopCloser(bytes.NewReader(body))

		respObj := ContainerCreateResponse{}
		if err := json.Unmarshal(respBody.Bytes(), &respObj); err != nil {
			return nil, err
		}
		return &respObj, nil
	}

	// empty response body
	return nil, nil
}
