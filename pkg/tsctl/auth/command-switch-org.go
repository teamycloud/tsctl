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
		Short: "切换活跃组织",
		Long: `切换 Tinyscale 操作的活跃组织。

当前命令将执行以下操作：
1. 获取你所关联的组织列表
2. 提示你选择一个作为活跃组织
3. 本地保存你的选择，以便后续命令使用。`,
		RunE: runSwitchOrg,
	}

	return cmd
}

func runSwitchOrg(cmd *cobra.Command, args []string) error {
	authData, err := LoadAuthData()
	if err != nil {
		return fmt.Errorf("无法加载身份验证数据: %w", err)
	}

	if authData == nil || authData.Token == nil || authData.Token.IDToken == "" {
		return fmt.Errorf("请先使用 'tsctl auth login' 登录")
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
		return fmt.Errorf("无法检查令牌是否过期: %w", err)
	}
	if expired {
		return fmt.Errorf("你的会话已过期，请使用 'tsctl auth login' 重新登录")
	}

	// Check if token should be refreshed (less than 20% remaining)
	shouldRefresh, err := ShouldRefreshToken(idToken)
	if err != nil {
		// Non-fatal error, continue with current token
		fmt.Fprintf(os.Stderr, "警告: 无法检查令牌状态: %v\n", err)
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
		return fmt.Errorf("无法获取组织列表: %w", err)
	}

	if len(orgs) == 0 {
		fmt.Println("你没有加入任何组织。")
		return nil
	}

	// Display organizations and prompt for selection
	fmt.Println("请选择一个组织：")
	fmt.Println()
	for i, org := range orgs {
		current := ""
		if authData.Organization != nil && authData.Organization.ID == org.ID {
			current = " (当前)"
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
		return fmt.Errorf("无法保存组织选择: %w", err)
	}

	fmt.Printf("\n活跃组织已设置为: %s\n", selectedOrg.Name)
	return nil
}

// promptOrgSelection prompts the user to select an organization
func promptOrgSelection(orgs []Organization) (*Organization, error) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("请输入数字 (1-%d): ", len(orgs))
		input, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("无法读取输入: %w", err)
		}

		input = strings.TrimSpace(input)
		num, err := strconv.Atoi(input)
		if err != nil || num < 1 || num > len(orgs) {
			fmt.Printf("请输入一个数字，范围在 1 到 %d 之间\n", len(orgs))
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
