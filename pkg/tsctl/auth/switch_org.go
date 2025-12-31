package auth

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// NewSwitchOrgCommand creates the switch-org command
func NewSwitchOrgCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch-org",
		Short: "Switch active organization",
		Long: `Switch the active organization for Tinyscale operations.

This command will:
1. Fetch the list of organizations you belong to
2. Prompt you to select one as the active organization
3. Save your selection locally`,
		RunE: runSwitchOrg,
	}

	return cmd
}

func runSwitchOrg(cmd *cobra.Command, args []string) error {
	authData, err := LoadAuthData()
	if err != nil {
		return fmt.Errorf("failed to load authentication data: %w", err)
	}

	if authData == nil || authData.Token == nil || authData.Token.IDToken == "" {
		return fmt.Errorf("please use 'tsctl auth login' to log in first")
	}

	return selectOrganization(authData)
}

// selectOrganization handles the organization selection flow
// This is shared between login and switch-org commands
func selectOrganization(authData *AuthData) error {
	idToken := authData.Token.IDToken
	refreshToken := authData.Token.RefreshToken

	// Check if token is expired
	expired, err := IsTokenExpired(idToken)
	if err != nil {
		return fmt.Errorf("failed to check token expiration: %w", err)
	}
	if expired {
		return fmt.Errorf("your session has expired, please use 'tsctl auth login' to log in again")
	}

	// Check if token should be refreshed (less than 20% remaining)
	shouldRefresh, err := ShouldRefreshToken(idToken)
	if err != nil {
		// Non-fatal error, continue with current token
		fmt.Fprintf(os.Stderr, "Warning: failed to check token refresh status: %v\n", err)
	} else if shouldRefresh && refreshToken != "" {
		// Start async token refresh - pass copies of the values, not the pointer
		authEndpoint := GetLoginEndpoint()
		if authData.Endpoints != nil && authData.Endpoints.Auth != "" {
			authEndpoint = authData.Endpoints.Auth
		}
		go refreshTokenAsync(authEndpoint, refreshToken)
	}

	// Fetch organizations
	openAPIEndpoint := GetOpenAPIEndpoint()
	if authData.Endpoints != nil && authData.Endpoints.OpenAPI != "" {
		openAPIEndpoint = authData.Endpoints.OpenAPI
	}

	apiClient := NewAPIClient(openAPIEndpoint, idToken)
	orgs, err := apiClient.GetMyOrganizations()
	if err != nil {
		return fmt.Errorf("failed to fetch organizations: %w", err)
	}

	if len(orgs) == 0 {
		fmt.Println("You are not a member of any organization.")
		return nil
	}

	// Display organizations and prompt for selection
	fmt.Println("Select an organization:")
	fmt.Println()
	for i, org := range orgs {
		current := ""
		if authData.Organization != nil && authData.Organization.ID == org.ID {
			current = " (current)"
		}
		fmt.Printf("  [%d] %s%s\n", i+1, org.Name, current)
		if org.Description != "" {
			fmt.Printf("      %s\n", org.Description)
		}
	}
	fmt.Println()

	// Read user selection
	selectedOrg, err := promptOrgSelection(orgs)
	if err != nil {
		return err
	}

	// Save the selected organization
	authData.Organization = &OrganizationInfo{
		ID:   selectedOrg.ID,
		Name: selectedOrg.Name,
	}

	if err := SaveAuthData(authData); err != nil {
		return fmt.Errorf("failed to save organization selection: %w", err)
	}

	fmt.Printf("\nActive organization set to: %s\n", selectedOrg.Name)
	return nil
}

// promptOrgSelection prompts the user to select an organization
func promptOrgSelection(orgs []Organization) (*Organization, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("Enter number (1-%d): ", len(orgs))
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read input: %w", err)
		}

		input = strings.TrimSpace(input)
		num, err := strconv.Atoi(input)
		if err != nil || num < 1 || num > len(orgs) {
			fmt.Printf("Please enter a number between 1 and %d\n", len(orgs))
			continue
		}

		return &orgs[num-1], nil
	}
}

// refreshTokenAsync refreshes the token in the background
// It operates independently by reloading auth data from disk to avoid race conditions
func refreshTokenAsync(authEndpoint, refreshToken string) {
	oauthClient := NewOAuthClient(authEndpoint)
	tokenResp, err := oauthClient.RefreshToken(refreshToken)
	if err != nil {
		// Silently fail - we'll continue with the existing token
		return
	}

	// Reload auth data from disk to get current state
	authData, err := LoadAuthData()
	if err != nil || authData == nil {
		return
	}

	// Only update if tokens still match (prevent overwriting newer auth)
	if authData.Token == nil || authData.Token.RefreshToken != refreshToken {
		return
	}

	// Update the auth data with the new tokens
	authData.Token.IDToken = tokenResp.IDToken
	if tokenResp.RefreshToken != "" {
		authData.Token.RefreshToken = tokenResp.RefreshToken
	}

	// Update user info if changed
	if userInfo, err := ExtractUserInfo(tokenResp.IDToken); err == nil {
		authData.User = userInfo
	}

	// Save the updated auth data
	_ = SaveAuthData(authData)
}
