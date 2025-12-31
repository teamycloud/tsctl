package auth

// AuthData represents the authentication data stored in ~/.tinyscale/auth.json
type AuthData struct {
	User         *UserInfo         `json:"user,omitempty"`
	Organization *OrganizationInfo `json:"organization,omitempty"`
	Token        *TokenInfo        `json:"tokens,omitempty"`
	Endpoints    *EndpointsInfo    `json:"endpoints,omitempty"`
}

// UserInfo represents the user information from the id_token
type UserInfo struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// OrganizationInfo represents the currently active organization
type OrganizationInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TokenInfo holds the OAuth tokens
type TokenInfo struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// EndpointsInfo holds the configured API endpoints
type EndpointsInfo struct {
	Auth    string `json:"auth"`
	OpenAPI string `json:"openapi"`
	Connect string `json:"connect"`
}

// Organization represents an organization returned from the API
type Organization struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Subscription string `json:"subscription"`
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IDTokenClaims represents the claims in the JWT id_token
type IDTokenClaims struct {
	Sub       string `json:"sub"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
}
