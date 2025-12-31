package auth

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewLogoutCommand creates the logout command
func NewLogoutCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "注销登录 Tinyscale",
		Long: `注销登录 Tinyscale 并清除本地凭据。

此命令将删除本地存储的身份验证数据。`,
		RunE: runLogout,
	}

	return cmd
}

func runLogout(cmd *cobra.Command, args []string) error {
	authData, err := LoadAuthData()
	if err != nil {
		return fmt.Errorf("无法加载身份验证数据: %w", err)
	}

	if authData == nil {
		fmt.Println("你尚未登录。")
		return nil
	}

	if err := ClearAuthData(); err != nil {
		return fmt.Errorf("无法清除身份验证数据: %w", err)
	}

	userName := ""
	if authData.User != nil {
		userName = fmt.Sprintf("%s %s", authData.User.FirstName, authData.User.LastName)
	}

	if userName != "" {
		fmt.Printf("%s 已成功注销登录。\n", userName)
	} else {
		fmt.Println("成功注销登录。")
	}

	return nil
}
