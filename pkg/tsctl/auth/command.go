package auth

import (
	"github.com/spf13/cobra"
)

// NewAuthCommand creates the auth parent command
func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "身份验证",
		Long:  `管理 Tinyscale 身份验证和组织的命令。`,
	}

	cmd.AddCommand(NewLoginCommand())
	cmd.AddCommand(NewLogoutCommand())
	cmd.AddCommand(NewSwitchOrgCommand())

	return cmd
}
