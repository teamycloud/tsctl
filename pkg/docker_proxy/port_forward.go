package docker_proxy

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"

	"github.com/mutagen-io/mutagen/pkg/configuration/global"
	"github.com/mutagen-io/mutagen/pkg/filesystem"
	"github.com/mutagen-io/mutagen/pkg/forwarding"
	"github.com/mutagen-io/mutagen/pkg/selection"
	forwardingsvc "github.com/mutagen-io/mutagen/pkg/service/forwarding"
	"github.com/mutagen-io/mutagen/pkg/url"
	ts_tunnel "github.com/teamycloud/tsctl/pkg/ts-tunnel"
)

// PortBinding represents a port mapping from local to remote
type PortBinding struct {
	HostPort      string // Local port (e.g., "8080")
	ContainerPort string // Container port with protocol (e.g., "80/tcp")
	Protocol      string // tcp or udp
	Listener      net.Listener
	SessionID     string
	StopCh        chan struct{}
}

// ContainerPorts tracks port forwards for a specific container
type ContainerPorts struct {
	ContainerID string
	Bindings    []*PortBinding
}

// PortForwardManager manages port forwards for all containers
type PortForwardManager struct {
	mu                sync.RWMutex
	containers        map[*http.Request]*ContainerPorts // httpPort -> ports
	containerPorts    map[string]*ContainerPorts        // containerID -> ports
	transportConfig   Config
	mutagenForwardMgr *forwarding.Manager
}

// NewPortForwardManager creates a new port forward manager
func NewPortForwardManager(transportConfig Config, forwardingManager *forwarding.Manager) *PortForwardManager {
	return &PortForwardManager{
		containers:        make(map[*http.Request]*ContainerPorts),
		containerPorts:    make(map[string]*ContainerPorts),
		transportConfig:   transportConfig,
		mutagenForwardMgr: forwardingManager,
	}
}

// StorePortBindingsStart stores the port bindings for a container (before it's created)
func (m *PortForwardManager) StorePortBindingsStart(req *http.Request, hostPorts map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bindings := make([]*PortBinding, 0)
	for containerPort, hostPortList := range hostPorts {
		if len(hostPortList) == 0 {
			continue
		}

		// Extract protocol from container port (e.g., "80/tcp" -> "tcp")
		parts := strings.Split(containerPort, "/")
		port := containerPort
		protocol := "tcp"
		if len(parts) == 2 {
			port = parts[0]
			protocol = parts[1]
		}

		// For now, take the first host port binding
		for _, hostPort := range hostPortList {
			if hostPort == "" {
				continue
			}

			binding := &PortBinding{
				HostPort:      hostPort,
				ContainerPort: port,
				Protocol:      protocol,
				StopCh:        make(chan struct{}),
			}
			bindings = append(bindings, binding)
			log.Printf("Stored port bindings: %s:%s -> %s/%s",
				hostPort, port, port, protocol)
		}
	}

	if len(bindings) > 0 {
		m.containers[req] = &ContainerPorts{
			Bindings: bindings,
		}
	}
}

// StorePortBindingsEnd stores container id found from the container create request
func (m *PortForwardManager) StorePortBindingsEnd(req *http.Request, containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if portBindings, ok := m.containers[req]; ok {
		if containerID != "" {
			m.containerPorts[containerID] = portBindings
		}
	}
	delete(m.containers, req)
}

// SetupForwards sets up SSH port forwards for a container
func (m *PortForwardManager) SetupForwards(containerID string, promptIdentifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	containerPorts, exists := m.containerPorts[containerID]
	if !exists {
		log.Printf("No port bindings found for container %s", containerID)
		return nil
	}

	log.Printf("Setting up port forwards for container %s", containerID)

	for _, binding := range containerPorts.Bindings {
		sessionID, err := m.setupSingleForward(containerID, binding, promptIdentifier)
		if err != nil {
			log.Printf("Failed to setup port forward %s: %v", binding.HostPort, err)
			// Continue with other ports even if one fails
		}
		binding.SessionID = sessionID
	}

	return nil
}

// pfCreateConfiguration stores configuration for the create command.
var pfCreateConfiguration struct {
	// help indicates whether or not to show help information and exit.
	help bool
	// name is the name specification for the session.
	name string
	// labels are the label specifications for the session.
	labels []string
	// paused indicates whether or not to create the session in a pre-paused
	// state.
	paused bool
	// noGlobalConfiguration specifies whether or not the global configuration
	// file should be ignored.
	noGlobalConfiguration bool
	// configurationFiles stores paths of additional files from which to load
	// default configuration.
	configurationFiles []string
	// socketOverwriteMode specifies the socket overwrite mode to use for the
	// session.
	socketOverwriteMode string
	// socketOverwriteModeSource specifies the socket overwrite mode to use for
	// the session, taking priority over socketOverwriteMode on source if
	// specified.
	socketOverwriteModeSource string
	// socketOverwriteModeDestination specifies the socket overwrite mode to use
	// for the session, taking priority over socketOverwriteMode on destination
	// if specified.
	socketOverwriteModeDestination string
	// socketOwner specifies the socket owner identifier to use new Unix domain
	// socket listeners, with endpoint-specific specifications taking priority.
	socketOwner string
	// socketOwnerSource specifies the socket owner identifier to use new Unix
	// domain socket listeners, taking priority over socketOwner on source if
	// specified.
	socketOwnerSource string
	// socketOwnerDestination specifies the socket owner identifier to use new
	// Unix domain socket listeners, taking priority over socketOwner on
	// destination if specified.
	socketOwnerDestination string
	// socketGroup specifies the socket owner identifier to use new Unix domain
	// socket listeners, with endpoint-specific specifications taking priority.
	socketGroup string
	// socketGroupSource specifies the socket owner identifier to use new Unix
	// domain socket listeners, taking priority over socketGroup on source if
	// specified.
	socketGroupSource string
	// socketGroupDestination specifies the socket owner identifier to use new
	// Unix domain socket listeners, taking priority over socketGroup on
	// destination if specified.
	socketGroupDestination string
	// socketPermissionMode specifies the socket permission mode to use for new
	// Unix domain socket listeners, with endpoint-specific specifications
	// taking priority.
	socketPermissionMode string
	// socketPermissionModeSource specifies the socket permission mode to use
	// for new Unix domain socket listeners on source, taking priority over
	// socketPermissionMode on source if specified.
	socketPermissionModeSource string
	// socketPermissionModeDestination specifies the socket permission mode to
	// use for new Unix domain socket listeners on destination, taking priority
	// over socketPermissionMode on destination if specified.
	socketPermissionModeDestination string
}

// loadAndValidateGlobalSynchronizationConfiguration loads a YAML-based global
// configuration, extracts the forwarding component, converts it to a Protocol
// Buffers session configuration, and validates it.
func loadAndValidateGlobalForwardingConfiguration(path string) (*forwarding.Configuration, error) {
	// Load the YAML configuration.
	yamlConfiguration, err := global.LoadConfiguration(path)
	if err != nil {
		return nil, err
	}

	// Convert the YAML configuration to a Protocol Buffers representation and
	// validate it.
	configuration := yamlConfiguration.Forwarding.Defaults.ToInternal()
	if err := configuration.EnsureValid(false); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Success.
	return configuration, nil
}

// setupSingleForward sets up a single SSH port forward
func (m *PortForwardManager) setupSingleForward(containerID string, binding *PortBinding, promptIdentifier string) (string, error) {
	pfCreateConfiguration.name = fmt.Sprintf("forward-%s-%s", containerID[:8], binding.HostPort)
	pfCreateConfiguration.labels = nil
	pfCreateConfiguration.paused = false
	pfCreateConfiguration.noGlobalConfiguration = false
	pfCreateConfiguration.configurationFiles = nil

	pfCreateConfiguration.socketOverwriteMode = ""
	pfCreateConfiguration.socketOverwriteModeSource = ""
	pfCreateConfiguration.socketOverwriteModeDestination = ""

	pfCreateConfiguration.socketOwner = ""
	pfCreateConfiguration.socketOwnerSource = ""
	pfCreateConfiguration.socketOwnerDestination = ""

	pfCreateConfiguration.socketGroup = ""
	pfCreateConfiguration.socketGroupSource = ""
	pfCreateConfiguration.socketGroupDestination = ""

	pfCreateConfiguration.socketPermissionMode = ""
	pfCreateConfiguration.socketPermissionModeSource = ""
	pfCreateConfiguration.socketPermissionModeDestination = ""

	forwardSource := fmt.Sprintf("tcp:localhost:%s", binding.HostPort)

	var destination *url.URL
	var err error

	// Build destination URL based on transport type
	if m.transportConfig.TransportType == TransportTSTunnel {
		forwardDest := fmt.Sprintf("ts://%s/tcp:localhost:%s?a=a",
			m.transportConfig.TSTunnelServer,
			binding.HostPort,
		)
		if m.transportConfig.TSTunnelCertFile != "" && m.transportConfig.TSTunnelKeyFile != "" {
			forwardDest = forwardDest + "&cert=" + neturl.QueryEscape(m.transportConfig.TSTunnelCertFile) + "&key=" + neturl.QueryEscape(m.transportConfig.TSTunnelKeyFile)
		}

		if m.transportConfig.TSTunnelCAFile != "" {
			forwardDest = forwardDest + "&ca=" + neturl.QueryEscape(m.transportConfig.TSTunnelCAFile)
		}
		if m.transportConfig.TSInsecure {
			forwardDest = forwardDest + "&insecure=true"
		}
		destination, err = ts_tunnel.ParseTSTunnelURL(forwardDest, url.Kind_Forwarding)
	} else {
		// Default to SSH: user@host:port:tcp:localhost:<port>
		forwardDest := fmt.Sprintf("%s@%s:tcp:localhost:%s",
			m.transportConfig.SSHUser, m.transportConfig.SSHHost, binding.HostPort)
		destination, err = url.Parse(forwardDest, url.Kind_Forwarding, true)
	}
	if err != nil {
		return "", fmt.Errorf("invalid forwarding destination: %w", err)
	}

	source, err := url.Parse(forwardSource, url.Kind_Forwarding, true)
	if err != nil {
		return "", fmt.Errorf("invalid forwarding source: %w", err)
	}

	if err := selection.EnsureNameValid(pfCreateConfiguration.name); err != nil {
		return "", fmt.Errorf("invalid session name: %w", err)
	}

	labels := make(map[string]string)
	for _, label := range pfCreateConfiguration.labels {
		components := strings.SplitN(label, "=", 2)
		var key, value string
		key = components[0]
		if len(components) == 2 {
			value = components[1]
		}
		if err := selection.EnsureLabelKeyValid(key); err != nil {
			return "", fmt.Errorf("invalid label key: %w", err)
		} else if err := selection.EnsureLabelValueValid(value); err != nil {
			return "", fmt.Errorf("invalid label value: %w", err)
		}
		labels[key] = value
	}
	labels["container-id"] = compressContainerID(containerID)

	// Create a default session configuration that will form the basis of our
	// cumulative configuration.
	configuration := &forwarding.Configuration{}

	// Unless disabled, attempt to load configuration from the global
	// configuration file and merge it into our cumulative configuration.
	if !pfCreateConfiguration.noGlobalConfiguration {
		// Compute the path to the global configuration file.
		globalConfigurationPath, err := global.ConfigurationPath()
		if err != nil {
			return "", fmt.Errorf("unable to compute path to global configuration file: %w", err)
		}

		// Attempt to load the file. We allow it to not exist.
		globalConfiguration, err := loadAndValidateGlobalForwardingConfiguration(globalConfigurationPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("unable to load global configuration: %w", err)
			}
		} else {
			configuration = forwarding.MergeConfigurations(configuration, globalConfiguration)
		}
	}

	// If additional default configuration files have been specified, then load
	// them and merge them into the cumulative configuration.
	for _, configurationFile := range pfCreateConfiguration.configurationFiles {
		if c, err := loadAndValidateGlobalForwardingConfiguration(configurationFile); err != nil {
			return "", fmt.Errorf("unable to load configuration file (%s): %w", configurationFile, err)
		} else {
			configuration = forwarding.MergeConfigurations(configuration, c)
		}
	}

	// Validate and convert socket overwrite mode specifications.
	var socketOverwriteMode, socketOverwriteModeSource, socketOverwriteModeDestination forwarding.SocketOverwriteMode
	if pfCreateConfiguration.socketOverwriteMode != "" {
		if err := socketOverwriteMode.UnmarshalText([]byte(pfCreateConfiguration.socketOverwriteMode)); err != nil {
			return "", fmt.Errorf("unable to socket overwrite mode: %w", err)
		}
	}
	if pfCreateConfiguration.socketOverwriteModeSource != "" {
		if err := socketOverwriteModeSource.UnmarshalText([]byte(pfCreateConfiguration.socketOverwriteModeSource)); err != nil {
			return "", fmt.Errorf("unable to socket overwrite mode for source: %w", err)
		}
	}
	if pfCreateConfiguration.socketOverwriteModeDestination != "" {
		if err := socketOverwriteModeDestination.UnmarshalText([]byte(pfCreateConfiguration.socketOverwriteModeDestination)); err != nil {
			return "", fmt.Errorf("unable to socket overwrite mode for destination: %w", err)
		}
	}

	// Validate socket owner specifications.
	if pfCreateConfiguration.socketOwner != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketOwner,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket ownership specification")
		}
	}
	if pfCreateConfiguration.socketOwnerSource != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketOwnerSource,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket ownership specification for source")
		}
	}
	if pfCreateConfiguration.socketOwnerDestination != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketOwnerDestination,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket ownership specification for destination")
		}
	}

	// Validate socket group specifications.
	if pfCreateConfiguration.socketGroup != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketGroup,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket group specification")
		}
	}
	if pfCreateConfiguration.socketGroupSource != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketGroupSource,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket group specification for source")
		}
	}
	if pfCreateConfiguration.socketGroupDestination != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			pfCreateConfiguration.socketGroupDestination,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", errors.New("invalid socket group specification for destination")
		}
	}

	// Validate and convert socket permission mode specifications.
	var socketPermissionMode, socketPermissionModeSource, socketPermissionModeDestination filesystem.Mode
	if pfCreateConfiguration.socketPermissionMode != "" {
		if err := socketPermissionMode.UnmarshalText([]byte(pfCreateConfiguration.socketPermissionMode)); err != nil {
			return "", fmt.Errorf("unable to parse socket permission mode: %w", err)
		}
	}
	if pfCreateConfiguration.socketPermissionModeSource != "" {
		if err := socketPermissionModeSource.UnmarshalText([]byte(pfCreateConfiguration.socketPermissionModeSource)); err != nil {
			return "", fmt.Errorf("unable to parse socket permission mode for source: %w", err)
		}
	}
	if pfCreateConfiguration.socketPermissionModeDestination != "" {
		if err := socketPermissionModeDestination.UnmarshalText([]byte(pfCreateConfiguration.socketPermissionModeDestination)); err != nil {
			return "", fmt.Errorf("unable to parse socket permission mode for destination: %w", err)
		}
	}

	// Create the command line configuration and merge it into our cumulative
	// configuration.
	configuration = forwarding.MergeConfigurations(configuration, &forwarding.Configuration{
		SocketOverwriteMode:  socketOverwriteMode,
		SocketOwner:          pfCreateConfiguration.socketOwner,
		SocketGroup:          pfCreateConfiguration.socketGroup,
		SocketPermissionMode: uint32(socketPermissionMode),
	})

	// Create the creation specification.
	specification := &forwardingsvc.CreationSpecification{
		Source:        source,
		Destination:   destination,
		Configuration: configuration,
		ConfigurationSource: &forwarding.Configuration{
			SocketOverwriteMode:  socketOverwriteModeSource,
			SocketOwner:          pfCreateConfiguration.socketOwnerSource,
			SocketGroup:          pfCreateConfiguration.socketGroupSource,
			SocketPermissionMode: uint32(socketPermissionModeSource),
		},
		ConfigurationDestination: &forwarding.Configuration{
			SocketOverwriteMode:  socketOverwriteModeDestination,
			SocketOwner:          pfCreateConfiguration.socketOwnerDestination,
			SocketGroup:          pfCreateConfiguration.socketGroupDestination,
			SocketPermissionMode: uint32(socketPermissionModeDestination),
		},
		Name:   pfCreateConfiguration.name,
		Labels: labels,
		Paused: pfCreateConfiguration.paused,
	}

	session, err := m.mutagenForwardMgr.Create(context.Background(), specification.Source,
		specification.Destination,
		specification.Configuration,
		specification.ConfigurationSource,
		specification.ConfigurationDestination,
		specification.Name,
		specification.Labels,
		specification.Paused,
		promptIdentifier,
	)
	return session, nil
}

// TeardownForwards tears down port forwards for a container
func (m *PortForwardManager) TeardownForwards(containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if containerPorts, exists := m.containerPorts[containerID]; exists {
		for _, binding := range containerPorts.Bindings {
			close(binding.StopCh)
			if binding.Listener != nil {
				_ = binding.Listener.Close()
				log.Printf("✗ Closed port forward: localhost:%s", binding.HostPort)
			}
		}
		delete(m.containerPorts, containerID)
	}

	log.Printf("Tearing down port forwards for container %s", containerID)
	selected := &selection.Selection{
		All:            false,
		Specifications: []string{},
		LabelSelector:  fmt.Sprintf("container-id=%s", compressContainerID(containerID)),
	}
	err := m.mutagenForwardMgr.Terminate(context.Background(), selected, "")
	if err != nil {
		log.Printf("Error terminating port forwards: %s", err)
	}
}

// ListSessions lists all existing port forward sessions and returns a map of container IDs
func (m *PortForwardManager) ListSessions() (map[string]bool, error) {
	// Query all port forwarding sessions from mutagen
	sel := &selection.Selection{
		All: true,
	}

	_, states, err := m.mutagenForwardMgr.List(context.Background(), sel, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to list forwarding sessions: %w", err)
	}

	// Extract unique container IDs from session labels
	containerIDs := make(map[string]bool)
	for _, state := range states {
		if state.Session.Labels != nil {
			if compressedID, ok := state.Session.Labels["container-id"]; ok {
				// Decompress the container ID back to full form
				containerID := decompressContainerID(compressedID)
				if containerID != "" {
					containerIDs[containerID] = true
					log.Printf("Found existing port forward session for container %s (session: %s)",
						containerID, state.Session.Identifier)
				}
			}
		}
	}

	return containerIDs, nil
}

// TeardownAll tears down all port forwards
func (m *PortForwardManager) TeardownAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Tearing down all port forwards")

	for containerID, containerPorts := range m.containerPorts {
		for _, binding := range containerPorts.Bindings {
			close(binding.StopCh)
			if binding.Listener != nil {
				binding.Listener.Close()
			}

			selected := &selection.Selection{
				All:            true,
				Specifications: []string{},
				LabelSelector:  "",
			}
			err := m.mutagenForwardMgr.Terminate(context.Background(), selected, "")
			if err != nil {
				log.Printf("Error terminating port forwards: %s", err)
			}
		}
		delete(m.containerPorts, containerID)
	}
}

func compressContainerID(rawContainerId string) string {
	bytes, err := hex.DecodeString(rawContainerId)
	if err != nil {
		panic(fmt.Sprintf("Could not compress container ID: %s", rawContainerId))
	}

	base64Str := base64.StdEncoding.EncodeToString(bytes)
	// mutagen allows these chars, so we use them to make sure the converted value is able to convert back to base64
	base64Str = strings.ReplaceAll(base64Str, "=", "-")
	base64Str = strings.ReplaceAll(base64Str, "+", "_")
	base64Str = strings.ReplaceAll(base64Str, "/", ".")
	return fmt.Sprintf("0%s0", base64Str) // make sure the value begins and ends with a number
}

func decompressContainerID(compressedID string) string {
	// Remove the leading and trailing '0' added during compression
	if len(compressedID) < 2 || compressedID[0] != '0' || compressedID[len(compressedID)-1] != '0' {
		log.Printf("Invalid compressed container ID format: %s", compressedID)
		return ""
	}
	base64Str := compressedID[1 : len(compressedID)-1]

	// Reverse the character replacements
	base64Str = strings.ReplaceAll(base64Str, "-", "=")
	base64Str = strings.ReplaceAll(base64Str, "_", "+")
	base64Str = strings.ReplaceAll(base64Str, ".", "/")

	// Decode from base64
	bytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		log.Printf("Failed to decode base64 container ID: %v", err)
		return ""
	}

	// Encode to hex string
	return hex.EncodeToString(bytes)
}
