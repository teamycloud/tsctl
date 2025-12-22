package tcp_agent

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dustin/go-humanize"
	"github.com/mutagen-io/mutagen/pkg/configuration/global"
	"github.com/mutagen-io/mutagen/pkg/filesystem"
	"github.com/mutagen-io/mutagen/pkg/filesystem/behavior"
	"github.com/mutagen-io/mutagen/pkg/selection"
	synchronizationsvc "github.com/mutagen-io/mutagen/pkg/service/synchronization"
	"github.com/mutagen-io/mutagen/pkg/synchronization"
	"github.com/mutagen-io/mutagen/pkg/synchronization/compression"
	"github.com/mutagen-io/mutagen/pkg/synchronization/core"
	"github.com/mutagen-io/mutagen/pkg/synchronization/core/ignore"
	"github.com/mutagen-io/mutagen/pkg/synchronization/hashing"
	"github.com/mutagen-io/mutagen/pkg/url"
)

// BindMount represents a volume mount from local to remote
type BindMount struct {
	HostPath      string // Local path (e.g., "/Users/user/project")
	ContainerPath string // Container path (e.g., "/app")
	ReadOnly      bool   // Whether the mount is read-only
	SessionID     string // Mutagen sync session ID
}

// ContainerMounts tracks bind mounts for a specific container
type ContainerMounts struct {
	ContainerID string
	Mounts      []*BindMount
}

// FileSyncManager manages file synchronization for bind mounts
type FileSyncManager struct {
	mu              sync.RWMutex
	containers      map[*http.Request]*ContainerMounts // httpReq -> mounts
	containerMounts map[string]*ContainerMounts        // containerID -> mounts
	sshConfig       Config
	mutagenSyncMgr  *synchronization.Manager
}

// NewFileSyncManager creates a new file sync manager
func NewFileSyncManager(sshConfig Config, synchronizationManager *synchronization.Manager) *FileSyncManager {
	return &FileSyncManager{
		containers:      make(map[*http.Request]*ContainerMounts),
		containerMounts: make(map[string]*ContainerMounts),
		sshConfig:       sshConfig,
		mutagenSyncMgr:  synchronizationManager,
	}
}

// StoreBindMountsStart stores the bind mounts for a container (before it's created)
func (m *FileSyncManager) StoreBindMountsStart(req *http.Request, binds []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	mounts := make([]*BindMount, 0)
	for _, bind := range binds {
		// Parse bind mount syntax: /host/path:/container/path[:ro]
		parts := strings.Split(bind, ":")
		if len(parts) < 2 {
			log.Printf("Invalid bind mount format: %s", bind)
			continue
		}

		hostPath := parts[0]
		containerPath := parts[1]
		readOnly := false

		if len(parts) >= 3 && parts[2] == "ro" {
			readOnly = true
		}

		// Expand host path to absolute path
		absHostPath, err := filepath.Abs(hostPath)
		if err != nil {
			log.Printf("Failed to resolve host path %s: %v", hostPath, err)
			continue
		}

		// Check if the host path exists
		if _, err := os.Stat(absHostPath); err != nil {
			log.Printf("Host path does not exist: %s", absHostPath)
			continue
		}

		mount := &BindMount{
			HostPath:      absHostPath,
			ContainerPath: containerPath,
			ReadOnly:      readOnly,
		}
		mounts = append(mounts, mount)
		log.Printf("Stored bind mount: %s -> %s (ro=%v)", absHostPath, containerPath, readOnly)
	}

	if len(mounts) > 0 {
		m.containers[req] = &ContainerMounts{
			Mounts: mounts,
		}
	}
}

// StoreBindMountsEnd stores container id found from the container create response
func (m *FileSyncManager) StoreBindMountsEnd(req *http.Request, containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if mounts, ok := m.containers[req]; ok {
		if containerID != "" {
			mounts.ContainerID = containerID
			m.containerMounts[containerID] = mounts
		}
	}
	delete(m.containers, req)
}

// SetupSyncs sets up file synchronization sessions for a container
func (m *FileSyncManager) SetupSyncs(containerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	containerMounts, exists := m.containerMounts[containerID]
	if !exists {
		log.Printf("No bind mounts found for container %s", containerID)
		return nil
	}

	log.Printf("Setting up file syncs for container %s", containerID)

	for _, mount := range containerMounts.Mounts {
		sessionID, err := m.setupSingleSync(containerID, mount)
		if err != nil {
			log.Printf("Failed to setup file sync %s: %v", mount.HostPath, err)
			// Continue with other mounts even if one fails
		}
		mount.SessionID = sessionID
	}

	return nil
}

// fsCreateConfiguration stores configuration for the sync session
var fsCreateConfiguration struct {
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
	// synchronizationMode specifies the synchronization mode for the session.
	synchronizationMode string
	// hash specifies the hashing algorithm to use for the session.
	hash string
	// maximumEntryCount specifies the maximum number of filesystem entries that
	// endpoints will tolerate managing.
	maximumEntryCount uint64
	// maximumStagingFileSize is the maximum file size that endpoints will
	// stage. It can be specified in human-friendly units.
	maximumStagingFileSize string
	// probeMode specifies the filesystem probing mode to use for the session.
	probeMode string
	// probeModeAlpha specifies the filesystem probing mode to use for the
	// session, taking priority over probeMode on alpha if specified.
	probeModeAlpha string
	// probeModeBeta specifies the filesystem probing mode to use for the
	// session, taking priority over probeMode on beta if specified.
	probeModeBeta string
	// scanMode specifies the scan mode to use for the session.
	scanMode string
	// scanModeAlpha specifies the scan mode to use for the session, taking
	// priority over scanMode on alpha if specified.
	scanModeAlpha string
	// scanModeBeta specifies the scan mode to use for the session, taking
	// priority over scanMode on beta if specified.
	scanModeBeta string
	// stageMode specifies the file staging mode to use for the session.
	stageMode string
	// stageModeAlpha specifies the file staging mode to use for the session,
	// taking priority over stageMode on alpha if specified.
	stageModeAlpha string
	// stageModeBeta specifies the file staging mode to use for the session,
	// taking priority over stageMode on beta if specified.
	stageModeBeta string
	// symbolicLinkMode specifies the symbolic link handling mode to use for
	// the session.
	symbolicLinkMode string
	// watchMode specifies the filesystem watching mode to use for the session.
	watchMode string
	// watchModeAlpha specifies the filesystem watching mode to use for the
	// session, taking priority over watchMode on alpha if specified.
	watchModeAlpha string
	// watchModeBeta specifies the filesystem watching mode to use for the
	// session, taking priority over watchMode on beta if specified.
	watchModeBeta string
	// watchPollingInterval specifies the polling interval to use if using
	// poll-based or hybrid watching.
	watchPollingInterval uint32
	// watchPollingIntervalAlpha specifies the polling interval to use if using
	// poll-based or hybrid watching, taking priority over watchPollingInterval
	// on alpha if specified.
	watchPollingIntervalAlpha uint32
	// watchPollingIntervalBeta specifies the polling interval to use if using
	// poll-based or hybrid watching, taking priority over watchPollingInterval
	// on beta if specified.
	watchPollingIntervalBeta uint32
	// ignoreSyntax specifies the ignore syntax and semantics for the session.
	ignoreSyntax string
	// ignores is the list of ignore specifications for the session.
	ignores []string
	// ignoreVCS specifies whether or not to enable VCS ignores for the session.
	ignoreVCS bool
	// noIgnoreVCS specifies whether or not to disable VCS ignores for the
	// session.
	noIgnoreVCS bool
	// permissionsMode specifies the permissions mode to use for the session.
	permissionsMode string
	// defaultFileMode specifies the default permission mode to use for new
	// files in "portable" permission propagation mode, with endpoint-specific
	// specifications taking priority.
	defaultFileMode string
	// defaultFileModeAlpha specifies the default permission mode to use for new
	// files on alpha in "portable" permission propagation mode, taking priority
	// over defaultFileMode on alpha if specified.
	defaultFileModeAlpha string
	// defaultFileModeBeta specifies the default permission mode to use for new
	// files on beta in "portable" permission propagation mode, taking priority
	// over defaultFileMode on beta if specified.
	defaultFileModeBeta string
	// defaultDirectoryMode specifies the default permission mode to use for new
	// directories in "portable" permission propagation mode, with endpoint-
	// specific specifications taking priority.
	defaultDirectoryMode string
	// defaultDirectoryModeAlpha specifies the default permission mode to use
	// for new directories on alpha in "portable" permission propagation mode,
	// taking priority over defaultDirectoryMode on alpha if specified.
	defaultDirectoryModeAlpha string
	// defaultDirectoryModeBeta specifies the default permission mode to use for
	// new directories on beta in "portable" permission propagation mode, taking
	// priority over defaultDirectoryMode on beta if specified.
	defaultDirectoryModeBeta string
	// defaultOwner specifies the default owner identifier to use when setting
	// ownership of new files and directories in "portable" permission
	// propagation mode, with endpoint-specific specifications taking priority.
	defaultOwner string
	// defaultOwnerAlpha specifies the default owner identifier to use when
	// setting ownership of new files and directories on alpha in "portable"
	// permission propagation mode, taking priority over defaultOwner on alpha
	// if specified.
	defaultOwnerAlpha string
	// defaultOwnerBeta specifies the default owner identifier to use when
	// setting ownership of new files and directories on beta in "portable"
	// permission propagation mode, taking priority over defaultOwner on beta if
	// specified.
	defaultOwnerBeta string
	// defaultGroup specifies the default group identifier to use when setting
	// ownership of new files and directories in "portable" permission
	// propagation mode, with endpoint-specific specifications taking priority.
	defaultGroup string
	// defaultGroupAlpha specifies the default group identifier to use when
	// setting ownership of new files and directories on alpha in "portable"
	// permission propagation mode, taking priority over defaultGroup on alpha
	// if specified.
	defaultGroupAlpha string
	// defaultGroupBeta specifies the default group identifier to use when
	// setting ownership of new files and directories on beta in "portable"
	// permission propagation mode, taking priority over defaultGroup on beta if
	// specified.
	defaultGroupBeta string
	// compression specifies the compression algorithm to use when communicating
	// with remote endpoints.
	compression string
	// compressionAlpha specifies the compression algorithm to use when
	// communicating with a remote alpha endpoint.
	compressionAlpha string
	// compressionBeta specifies the compression algorithm to use when
	// communicating with a remote beta endpoint.
	compressionBeta string
	// Add more configuration options as needed
}

// loadAndValidateGlobalSynchronizationConfiguration loads a YAML-based global
// configuration, extracts the synchronization component, converts it to a
// Protocol Buffers session configuration, and validates it.
func loadAndValidateGlobalSynchronizationConfiguration(path string) (*synchronization.Configuration, error) {
	// Load the YAML configuration.
	yamlConfiguration, err := global.LoadConfiguration(path)
	if err != nil {
		return nil, err
	}

	// Convert the YAML configuration to a Protocol Buffers representation and
	// validate it.
	configuration := yamlConfiguration.Synchronization.Defaults.ToInternal()
	if err := configuration.EnsureValid(false); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Success.
	return configuration, nil
}

// setupSingleSync sets up a single file synchronization session
func (m *FileSyncManager) setupSingleSync(containerID string, mount *BindMount) (string, error) {
	fsCreateConfiguration.help = false
	fsCreateConfiguration.name = fmt.Sprintf("sync-%s-%s", containerID[:8], filepath.Base(mount.HostPath))
	fsCreateConfiguration.labels = nil
	fsCreateConfiguration.paused = false
	fsCreateConfiguration.noGlobalConfiguration = false
	fsCreateConfiguration.configurationFiles = nil
	fsCreateConfiguration.synchronizationMode = ""
	fsCreateConfiguration.hash = "" // can be sha1|sha256

	fsCreateConfiguration.maximumEntryCount = 0
	fsCreateConfiguration.maximumStagingFileSize = ""

	fsCreateConfiguration.probeMode = ""
	fsCreateConfiguration.probeModeAlpha = ""
	fsCreateConfiguration.probeModeBeta = ""

	fsCreateConfiguration.scanMode = ""
	fsCreateConfiguration.scanModeAlpha = ""
	fsCreateConfiguration.scanModeBeta = ""

	fsCreateConfiguration.stageMode = ""
	fsCreateConfiguration.stageModeAlpha = ""
	fsCreateConfiguration.stageModeBeta = ""

	fsCreateConfiguration.symbolicLinkMode = ""

	fsCreateConfiguration.watchMode = ""
	fsCreateConfiguration.watchModeAlpha = ""
	fsCreateConfiguration.watchModeBeta = ""

	fsCreateConfiguration.watchPollingInterval = 0
	fsCreateConfiguration.watchPollingIntervalAlpha = 0
	fsCreateConfiguration.watchPollingIntervalBeta = 0

	fsCreateConfiguration.ignoreSyntax = "" // could be mutagen|docker
	fsCreateConfiguration.ignores = nil
	fsCreateConfiguration.ignoreVCS = false
	fsCreateConfiguration.noIgnoreVCS = false

	fsCreateConfiguration.permissionsMode = ""
	fsCreateConfiguration.defaultFileMode = ""
	fsCreateConfiguration.defaultFileModeAlpha = ""
	fsCreateConfiguration.defaultFileModeBeta = ""
	fsCreateConfiguration.defaultDirectoryMode = ""
	fsCreateConfiguration.defaultDirectoryModeAlpha = ""
	fsCreateConfiguration.defaultDirectoryModeBeta = ""

	fsCreateConfiguration.defaultOwner = ""
	fsCreateConfiguration.defaultOwnerAlpha = ""
	fsCreateConfiguration.defaultOwnerBeta = ""

	fsCreateConfiguration.defaultGroup = ""
	fsCreateConfiguration.defaultGroupAlpha = ""
	fsCreateConfiguration.defaultGroupBeta = ""

	fsCreateConfiguration.compression = "" // can be none|deflate
	fsCreateConfiguration.compressionAlpha = ""
	fsCreateConfiguration.compressionBeta = ""

	alpha, err := url.Parse(mount.HostPath, url.Kind_Synchronization, true)
	if err != nil {
		return "", fmt.Errorf("invalid sync source: %w", err)
	}

	// Destination: remote path via SSH
	// user@example.org:23:relative/path
	// The path will be something like /opt/remote-docker-agent/{containerID}/{mount-path}
	remotePath := fmt.Sprintf("/opt/remote-docker-agent/%s%s", containerID, mount.ContainerPath)
	syncDest := fmt.Sprintf("%s@%s:%s",
		m.sshConfig.SSHUser, m.sshConfig.SSHHost, remotePath)
	beta, err := url.Parse(syncDest, url.Kind_Synchronization, true)
	if err != nil {
		return "", fmt.Errorf("invalid sync destination: %w", err)
	}

	// Validate the name.
	if err := selection.EnsureNameValid(fsCreateConfiguration.name); err != nil {
		return "", fmt.Errorf("invalid session name: %w", err)
	}

	// Parse, validate, and record labels.
	labels := make(map[string]string)
	for _, label := range fsCreateConfiguration.labels {
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
	configuration := &synchronization.Configuration{}

	// Unless disabled, attempt to load configuration from the global
	// configuration file and merge it into our cumulative configuration.
	if !fsCreateConfiguration.noGlobalConfiguration {
		// Compute the path to the global configuration file.
		globalConfigurationPath, err := global.ConfigurationPath()
		if err != nil {
			return "", fmt.Errorf("unable to compute path to global configuration file: %w", err)
		}

		// Attempt to load the file. We allow it to not exist.
		globalConfiguration, err := loadAndValidateGlobalSynchronizationConfiguration(globalConfigurationPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("unable to load global configuration: %w", err)
			}
		} else {
			configuration = synchronization.MergeConfigurations(configuration, globalConfiguration)
		}
	}

	// If additional default configuration files have been specified, then load
	// them and merge them into the cumulative configuration.
	for _, configurationFile := range fsCreateConfiguration.configurationFiles {
		if c, err := loadAndValidateGlobalSynchronizationConfiguration(configurationFile); err != nil {
			return "", fmt.Errorf("unable to load configuration file (%s): %w", configurationFile, err)
		} else {
			configuration = synchronization.MergeConfigurations(configuration, c)
		}
	}

	// Validate and convert the synchronization mode specification.
	var synchronizationMode core.SynchronizationMode
	if fsCreateConfiguration.synchronizationMode != "" {
		if err := synchronizationMode.UnmarshalText([]byte(fsCreateConfiguration.synchronizationMode)); err != nil {
			return "", fmt.Errorf("unable to parse synchronization mode: %w", err)
		}
	}

	// Validate and convert the hashing algorithm specification.
	var hashingAlgorithm hashing.Algorithm
	if fsCreateConfiguration.hash != "" {
		if err := hashingAlgorithm.UnmarshalText([]byte(fsCreateConfiguration.hash)); err != nil {
			return "", fmt.Errorf("unable to parse hashing algorithm: %w", err)
		}
	}

	// There's no need to validate the maximum entry count - any uint64 value is
	// valid.

	// Validate and convert the maximum staging file size.
	var maximumStagingFileSize uint64
	if fsCreateConfiguration.maximumStagingFileSize != "" {
		if s, err := humanize.ParseBytes(fsCreateConfiguration.maximumStagingFileSize); err != nil {
			return "", fmt.Errorf("unable to parse maximum staging file size: %w", err)
		} else {
			maximumStagingFileSize = s
		}
	}

	// Validate and convert probe mode specifications.
	var probeMode, probeModeAlpha, probeModeBeta behavior.ProbeMode
	if fsCreateConfiguration.probeMode != "" {
		if err := probeMode.UnmarshalText([]byte(fsCreateConfiguration.probeMode)); err != nil {
			return "", fmt.Errorf("unable to parse probe mode: %w", err)
		}
	}
	if fsCreateConfiguration.probeModeAlpha != "" {
		if err := probeModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.probeModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse probe mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.probeModeBeta != "" {
		if err := probeModeBeta.UnmarshalText([]byte(fsCreateConfiguration.probeModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse probe mode for beta: %w", err)
		}
	}

	// Validate and convert scan mode specifications.
	var scanMode, scanModeAlpha, scanModeBeta synchronization.ScanMode
	if fsCreateConfiguration.scanMode != "" {
		if err := scanMode.UnmarshalText([]byte(fsCreateConfiguration.scanMode)); err != nil {
			return "", fmt.Errorf("unable to parse scan mode: %w", err)
		}
	}
	if fsCreateConfiguration.scanModeAlpha != "" {
		if err := scanModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.scanModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse scan mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.scanModeBeta != "" {
		if err := scanModeBeta.UnmarshalText([]byte(fsCreateConfiguration.scanModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse scan mode for beta: %w", err)
		}
	}

	// Validate and convert staging mode specifications.
	var stageMode, stageModeAlpha, stageModeBeta synchronization.StageMode
	if fsCreateConfiguration.stageMode != "" {
		if err := stageMode.UnmarshalText([]byte(fsCreateConfiguration.stageMode)); err != nil {
			return "", fmt.Errorf("unable to parse staging mode: %w", err)
		}
	}
	if fsCreateConfiguration.stageModeAlpha != "" {
		if err := stageModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.stageModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse staging mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.stageModeBeta != "" {
		if err := stageModeBeta.UnmarshalText([]byte(fsCreateConfiguration.stageModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse staging mode for beta: %w", err)
		}
	}

	// Validate and convert the symbolic link mode specification.
	var symbolicLinkMode core.SymbolicLinkMode
	if fsCreateConfiguration.symbolicLinkMode != "" {
		if err := symbolicLinkMode.UnmarshalText([]byte(fsCreateConfiguration.symbolicLinkMode)); err != nil {
			return "", fmt.Errorf("unable to parse symbolic link mode: %w", err)
		}
	}

	// Validate and convert watch mode specifications.
	var watchMode, watchModeAlpha, watchModeBeta synchronization.WatchMode
	if fsCreateConfiguration.watchMode != "" {
		if err := watchMode.UnmarshalText([]byte(fsCreateConfiguration.watchMode)); err != nil {
			return "", fmt.Errorf("unable to parse watch mode: %w", err)
		}
	}
	if fsCreateConfiguration.watchModeAlpha != "" {
		if err := watchModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.watchModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse watch mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.watchModeBeta != "" {
		if err := watchModeBeta.UnmarshalText([]byte(fsCreateConfiguration.watchModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse watch mode for beta: %w", err)
		}
	}

	// There's no need to validate the watch polling intervals - any uint32
	// values are valid.

	// Validate and convert the ignore syntax specification.
	var ignoreSyntax ignore.Syntax
	if fsCreateConfiguration.ignoreSyntax != "" {
		if err := ignoreSyntax.UnmarshalText([]byte(fsCreateConfiguration.ignoreSyntax)); err != nil {
			return "", fmt.Errorf("unable to parse ignore syntax: %w", err)
		}
	}

	// Unfortunately we can't validate ignore specifications in any meaningful
	// way because we don't yet know the ignore syntax being used. This could be
	// specified by the global YAML configuration or (more likely) determined by
	// the default session version within the daemon. These ignores will
	// eventually be validated at endpoint initialization time, but there's no
	// convenient way to do it earlier in the session creation process.

	// Validate and convert the VCS ignore mode specification.
	var ignoreVCSMode ignore.IgnoreVCSMode
	if fsCreateConfiguration.ignoreVCS && fsCreateConfiguration.noIgnoreVCS {
		return "", fmt.Errorf("conflicting VCS ignore behavior specified")
	} else if fsCreateConfiguration.ignoreVCS {
		ignoreVCSMode = ignore.IgnoreVCSMode_IgnoreVCSModeIgnore
	} else if fsCreateConfiguration.noIgnoreVCS {
		ignoreVCSMode = ignore.IgnoreVCSMode_IgnoreVCSModePropagate
	}

	// Validate and convert the permissions mode specification.
	var permissionsMode core.PermissionsMode
	if fsCreateConfiguration.permissionsMode != "" {
		if err := permissionsMode.UnmarshalText([]byte(fsCreateConfiguration.permissionsMode)); err != nil {
			return "", fmt.Errorf("unable to parse permissions mode: %w", err)
		}
	}

	// Compute the effective permissions mode.
	// HACK: We technically don't know the daemon's default session version, so
	// we compute the default permissions mode using the default session version
	// for this executable, which (given our current distribution strategy) will
	// be the same as that of the daemon. Of course, the daemon API will
	// re-validate this, so validation here is merely best-effort and
	// informational in any case. For more information on the reasoning behind
	// this, see the note in synchronization.Version.DefaultPermissionsMode.
	effectivePermissionsMode := permissionsMode
	if effectivePermissionsMode.IsDefault() {
		effectivePermissionsMode = synchronization.DefaultVersion.DefaultPermissionsMode()
	}

	// Validate and convert default file mode specifications.
	var defaultFileMode, defaultFileModeAlpha, defaultFileModeBeta filesystem.Mode
	if fsCreateConfiguration.defaultFileMode != "" {
		if err := defaultFileMode.UnmarshalText([]byte(fsCreateConfiguration.defaultFileMode)); err != nil {
			return "", fmt.Errorf("unable to parse default file mode: %w", err)
		} else if err = core.EnsureDefaultFileModeValid(effectivePermissionsMode, defaultFileMode); err != nil {
			return "", fmt.Errorf("invalid default file mode: %w", err)
		}
	}
	if fsCreateConfiguration.defaultFileModeAlpha != "" {
		if err := defaultFileModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.defaultFileModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse default file mode for alpha: %w", err)
		} else if err = core.EnsureDefaultFileModeValid(effectivePermissionsMode, defaultFileModeAlpha); err != nil {
			return "", fmt.Errorf("invalid default file mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.defaultFileModeBeta != "" {
		if err := defaultFileModeBeta.UnmarshalText([]byte(fsCreateConfiguration.defaultFileModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse default file mode for beta: %w", err)
		} else if err = core.EnsureDefaultFileModeValid(effectivePermissionsMode, defaultFileModeBeta); err != nil {
			return "", fmt.Errorf("invalid default file mode for beta: %w", err)
		}
	}

	// Validate and convert default directory mode specifications.
	var defaultDirectoryMode, defaultDirectoryModeAlpha, defaultDirectoryModeBeta filesystem.Mode
	if fsCreateConfiguration.defaultDirectoryMode != "" {
		if err := defaultDirectoryMode.UnmarshalText([]byte(fsCreateConfiguration.defaultDirectoryMode)); err != nil {
			return "", fmt.Errorf("unable to parse default directory mode: %w", err)
		} else if err = core.EnsureDefaultDirectoryModeValid(effectivePermissionsMode, defaultDirectoryMode); err != nil {
			return "", fmt.Errorf("invalid default directory mode: %w", err)
		}
	}
	if fsCreateConfiguration.defaultDirectoryModeAlpha != "" {
		if err := defaultDirectoryModeAlpha.UnmarshalText([]byte(fsCreateConfiguration.defaultDirectoryModeAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse default directory mode for alpha: %w", err)
		} else if err = core.EnsureDefaultDirectoryModeValid(effectivePermissionsMode, defaultDirectoryModeAlpha); err != nil {
			return "", fmt.Errorf("invalid default directory mode for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.defaultDirectoryModeBeta != "" {
		if err := defaultDirectoryModeBeta.UnmarshalText([]byte(fsCreateConfiguration.defaultDirectoryModeBeta)); err != nil {
			return "", fmt.Errorf("unable to parse default directory mode for beta: %w", err)
		} else if err = core.EnsureDefaultDirectoryModeValid(effectivePermissionsMode, defaultDirectoryModeBeta); err != nil {
			return "", fmt.Errorf("invalid default directory mode for beta: %w", err)
		}
	}

	// Validate default file owner specifications.
	if fsCreateConfiguration.defaultOwner != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultOwner,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid ownership specification")
		}
	}
	if fsCreateConfiguration.defaultOwnerAlpha != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultOwnerAlpha,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid ownership specification for alpha")
		}
	}
	if fsCreateConfiguration.defaultOwnerBeta != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultOwnerBeta,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid ownership specification for beta")
		}
	}

	// Validate default file group specifications.
	if fsCreateConfiguration.defaultGroup != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultGroup,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid group specification")
		}
	}
	if fsCreateConfiguration.defaultGroupAlpha != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultGroupAlpha,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid group specification for alpha")
		}
	}
	if fsCreateConfiguration.defaultGroupBeta != "" {
		if kind, _ := filesystem.ParseOwnershipIdentifier(
			fsCreateConfiguration.defaultGroupBeta,
		); kind == filesystem.OwnershipIdentifierKindInvalid {
			return "", fmt.Errorf("invalid group specification for beta")
		}
	}

	// Validate and convert compression algorithm specifications.
	var compressionAlgorithm, compressionAlgorithmAlpha, compressionAlgorithmBeta compression.Algorithm
	if fsCreateConfiguration.compression != "" {
		if err := compressionAlgorithm.UnmarshalText([]byte(fsCreateConfiguration.compression)); err != nil {
			return "", fmt.Errorf("unable to parse compression algorithm: %w", err)
		}
	}
	if fsCreateConfiguration.compressionAlpha != "" {
		if err := compressionAlgorithmAlpha.UnmarshalText([]byte(fsCreateConfiguration.compressionAlpha)); err != nil {
			return "", fmt.Errorf("unable to parse compression algorithm for alpha: %w", err)
		}
	}
	if fsCreateConfiguration.compressionBeta != "" {
		if err := compressionAlgorithmBeta.UnmarshalText([]byte(fsCreateConfiguration.compressionBeta)); err != nil {
			return "", fmt.Errorf("unable to parse compression algorithm for beta: %w", err)
		}
	}

	configuration = synchronization.MergeConfigurations(configuration, &synchronization.Configuration{
		SynchronizationMode:    synchronizationMode,
		HashingAlgorithm:       hashingAlgorithm,
		MaximumEntryCount:      fsCreateConfiguration.maximumEntryCount,
		MaximumStagingFileSize: maximumStagingFileSize,
		ProbeMode:              probeMode,
		ScanMode:               scanMode,
		StageMode:              stageMode,
		SymbolicLinkMode:       symbolicLinkMode,
		WatchMode:              watchMode,
		WatchPollingInterval:   fsCreateConfiguration.watchPollingInterval,
		IgnoreSyntax:           ignoreSyntax,
		Ignores:                fsCreateConfiguration.ignores,
		IgnoreVCSMode:          ignoreVCSMode,
		PermissionsMode:        permissionsMode,
		DefaultFileMode:        uint32(defaultFileMode),
		DefaultDirectoryMode:   uint32(defaultDirectoryMode),
		DefaultOwner:           fsCreateConfiguration.defaultOwner,
		DefaultGroup:           fsCreateConfiguration.defaultGroup,
		CompressionAlgorithm:   compressionAlgorithm,
	})

	// Create the creation specification.
	specification := &synchronizationsvc.CreationSpecification{
		Alpha:         alpha,
		Beta:          beta,
		Configuration: configuration,
		ConfigurationAlpha: &synchronization.Configuration{
			ProbeMode:            probeModeAlpha,
			ScanMode:             scanModeAlpha,
			StageMode:            stageModeAlpha,
			WatchMode:            watchModeAlpha,
			WatchPollingInterval: fsCreateConfiguration.watchPollingIntervalAlpha,
			DefaultFileMode:      uint32(defaultFileModeAlpha),
			DefaultDirectoryMode: uint32(defaultDirectoryModeAlpha),
			DefaultOwner:         fsCreateConfiguration.defaultOwnerAlpha,
			DefaultGroup:         fsCreateConfiguration.defaultGroupAlpha,
			CompressionAlgorithm: compressionAlgorithmAlpha,
		},
		ConfigurationBeta: &synchronization.Configuration{
			ProbeMode:            probeModeBeta,
			ScanMode:             scanModeBeta,
			StageMode:            stageModeBeta,
			WatchMode:            watchModeBeta,
			WatchPollingInterval: fsCreateConfiguration.watchPollingIntervalBeta,
			DefaultFileMode:      uint32(defaultFileModeBeta),
			DefaultDirectoryMode: uint32(defaultDirectoryModeBeta),
			DefaultOwner:         fsCreateConfiguration.defaultOwnerBeta,
			DefaultGroup:         fsCreateConfiguration.defaultGroupBeta,
			CompressionAlgorithm: compressionAlgorithmBeta,
		},
		Name:   fsCreateConfiguration.name,
		Labels: labels,
		Paused: fsCreateConfiguration.paused,
	}

	session, err := m.mutagenSyncMgr.Create(
		context.Background(),
		specification.Alpha,
		specification.Beta,
		specification.Configuration,
		specification.ConfigurationAlpha,
		specification.ConfigurationBeta,
		specification.Name,
		specification.Labels,
		specification.Paused,
		"",
	)
	if err != nil {
		return "", fmt.Errorf("failed to create sync session: %w", err)
	}

	log.Printf("Created sync session %s: %s -> %s", session, mount.HostPath, remotePath)
	return session, nil
}

// TeardownSyncs tears down file synchronization sessions for a container
func (m *FileSyncManager) TeardownSyncs(containerID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exists := m.containerMounts[containerID]
	if !exists {
		return
	}

	log.Printf("Tearing down file syncs for container %s", containerID)

	selected := &selection.Selection{
		All:            false,
		Specifications: []string{},
		LabelSelector:  fmt.Sprintf("container-id=%s", compressContainerID(containerID)),
	}
	err := m.mutagenSyncMgr.Terminate(context.Background(), selected, "")
	if err != nil {
		log.Printf("Error terminating sync sessions: %s", err)
	}

	delete(m.containerMounts, containerID)
}

// TeardownAll tears down all file synchronization sessions
func (m *FileSyncManager) TeardownAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("Tearing down all file syncs")

	for containerID := range m.containerMounts {
		selected := &selection.Selection{
			All:            false,
			Specifications: []string{},
			LabelSelector:  fmt.Sprintf("container-id=%s", compressContainerID(containerID)),
		}
		err := m.mutagenSyncMgr.Terminate(context.Background(), selected, "")
		if err != nil {
			log.Printf("Error terminating sync sessions for container %s: %s", containerID, err)
		}
		delete(m.containerMounts, containerID)
	}
}
