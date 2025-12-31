package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ParseIDToken parses a JWT id_token and extracts the claims.
// Note: This performs basic parsing without cryptographic verification.
// The token is received directly from the authorization server over HTTPS,
// so signature verification is not required for extracting user display information.
func ParseIDToken(idToken string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("unable to decode JWT payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unable to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// GetTokenExpiration returns the expiration time of the token
func GetTokenExpiration(idToken string) (time.Time, error) {
	claims, err := ParseIDToken(idToken)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.Exp, 0), nil
}

// GetTokenIssuedAt returns the issued time of the token
func GetTokenIssuedAt(idToken string) (time.Time, error) {
	claims, err := ParseIDToken(idToken)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(claims.Iat, 0), nil
}

// IsTokenExpired checks if the token is expired
func IsTokenExpired(idToken string) (bool, error) {
	exp, err := GetTokenExpiration(idToken)
	if err != nil {
		return true, err
	}
	return time.Now().After(exp), nil
}

// GetTokenRemainingPercentage returns the percentage of token lifetime remaining
// Returns a value between 0 and 1
func GetTokenRemainingPercentage(idToken string) (float64, error) {
	claims, err := ParseIDToken(idToken)
	if err != nil {
		return 0, err
	}

	now := time.Now().Unix()
	totalLifetime := claims.Exp - claims.Iat
	if totalLifetime <= 0 {
		return 0, nil
	}

	remaining := claims.Exp - now
	if remaining <= 0 {
		return 0, nil
	}

	return float64(remaining) / float64(totalLifetime), nil
}

// ShouldRefreshToken returns true if the token has less than 20% of its lifetime remaining
func ShouldRefreshToken(idToken string) (bool, error) {
	remaining, err := GetTokenRemainingPercentage(idToken)
	if err != nil {
		return false, err
	}
	return remaining < 0.2, nil
}

// ExtractUserInfo extracts user information from the id_token
func ExtractUserInfo(idToken string) (*UserInfo, error) {
	claims, err := ParseIDToken(idToken)
	if err != nil {
		return nil, err
	}

	return &UserInfo{
		ID:        claims.Sub,
		FirstName: claims.FirstName,
		LastName:  claims.LastName,
	}, nil
}
