package auth

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewLoginCommand creates the login command
func NewLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "登录到 Tinyscale",
		Long: `使用 OAuth2 设备代码流登录到 Tinyscale。

此命令将：
1. 显示一个验证 URL 和代码
2. 等待你在浏览器中完成身份验证
3. 将临时凭据保存到本地
4. 提示你选择一个活跃的组织`,
		RunE: runLogin,
	}

	return cmd
}

func runLogin(cmd *cobra.Command, args []string) error {
	authEndpoint := GetLoginEndpoint()
	openAPIEndpoint := GetOpenAPIEndpoint()

	fmt.Printf("Logging in to Tinyscale...\n")
	fmt.Printf("Auth server: %s\n\n", authEndpoint)

	// Step 1: Start device authorization
	oauthClient := NewOAuthClient(authEndpoint)
	deviceAuth, err := oauthClient.StartDeviceAuthorization()
	if err != nil {
		return fmt.Errorf("failed to start device authorization: %w", err)
	}

	// Step 2: Display verification info to user
	fmt.Printf("要登录，请使用网页浏览器打开以下页面：\n")
	fmt.Printf("  %s\n\n", deviceAuth.VerificationURI)
	fmt.Printf("并输入代码：\n")
	fmt.Printf("  %s\n\n", deviceAuth.UserCode)

	if deviceAuth.VerificationURIComplete != "" {
		fmt.Printf("或者直接打开此 URL：\n")
		fmt.Printf("  %s\n\n", deviceAuth.VerificationURIComplete)
	}

	fmt.Printf("等待身份验证完成...\n")
	// Step 3: Poll for token
	tokenResp, err := oauthClient.PollForToken(deviceAuth)
	if err != nil {
		return fmt.Errorf("无法完成登录: %w", err)
	}

	// Step 4: Parse user info from id_token
	userInfo, err := ExtractUserInfo(tokenResp.IDToken)
	if err != nil {
		return fmt.Errorf("无法解析用户信息: %w", err)
	}

	// Step 5: Save auth data (without organization for now)
	authData := &AuthData{
		User: userInfo,
		Token: &TokenInfo{
			IDToken:      tokenResp.IDToken,
			RefreshToken: tokenResp.RefreshToken,
		},
		Endpoints: &EndpointsInfo{
			Auth:    authEndpoint,
			OpenAPI: openAPIEndpoint,
			Connect: DefaultConnectEndpoint,
		},
	}

	if err := SaveAuthData(authData); err != nil {
		return fmt.Errorf("无法保存临时凭据数据: %w", err)
	}

	fmt.Printf("欢迎回来，%s %s!\n\n", userInfo.FirstName, userInfo.LastName)

	// Step 6: Trigger organization selection
	return selectOrganization(authData)
}
