package auth

import "os"

// 下面这些服务器位置使用 var 变量，以便于编译时替换（ldflags）
var (
	// DefaultLoginEndpoint is the default OAuth2 authorization server
	DefaultLoginEndpoint = "https://id.tinyscale.com"

	// DefaultOpenAPIEndpoint is the default Tinyscale OpenAPI endpoint
	DefaultOpenAPIEndpoint = "https://openapi.tinyscale.com"

	// DefaultConnectEndpoint is the default Tinyscale Connect endpoint
	DefaultConnectEndpoint = "https://connect.tinyscale.com"
)

const (
	// ClientID is the OAuth2 client ID for tsctl
	ClientID = "tsctl"

	// Scope is the OAuth2 scope for login
	Scope = "openapi hosts"

	// EnvLoginEndpoint is the environment variable for login endpoint
	EnvLoginEndpoint = "TINYSCALE_LOGIN_ENDPOINT"

	// EnvOpenAPIEndpoint is the environment variable for OpenAPI endpoint
	EnvOpenAPIEndpoint = "TINYSCALE_OPENAPI_ENDPOINT"

	// DeviceAuthorizationPath is the OAuth2 device authorization endpoint path
	DeviceAuthorizationPath = "/device_authorization"

	// TokenPath is the OAuth2 token endpoint path
	TokenPath = "/token"

	// OrganizationsPath is the API path for fetching user's organizations
	OrganizationsPath = "/v1/my-organizations"
)

// GetLoginEndpoint returns the login endpoint from env or default
func GetLoginEndpoint() string {
	if endpoint := os.Getenv(EnvLoginEndpoint); endpoint != "" {
		return endpoint
	}
	return DefaultLoginEndpoint
}

// GetOpenAPIEndpoint returns the OpenAPI endpoint from env or default
func GetOpenAPIEndpoint() string {
	if endpoint := os.Getenv(EnvOpenAPIEndpoint); endpoint != "" {
		return endpoint
	}
	return DefaultOpenAPIEndpoint
}
