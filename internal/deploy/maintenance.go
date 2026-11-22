package deploy

import (
	"context"
	"errors"

	"github.com/Link2theWorld/mintyx/internal/hostcheck"
)

// ErrNotDeployed means there is no Mintyx panel on the server to act on.
var ErrNotDeployed = errors.New("this server has no Mintyx panel installed")

// ResetAdminPassword gives the panel's admin account a new password, through the panel program
// on the server, and returns the account name and that password. The server must run a panel
// build that has the reset-password command, which every deploy from this program puts there.
func (c *Client) ResetAdminPassword(ctx context.Context) (user, password string, err error) {
	out, err := c.RunRoot(ctx, Script{Name: "reset-password", Body: resetPasswordBody, Vars: []Var{
		{"BIN", PanelBinaryPath}, {"DATA", DataDir},
	}})
	if err != nil {
		return "", "", err
	}
	v := out.Values()
	if v["problem"] == "not-installed" {
		return "", "", ErrNotDeployed
	}
	if v["user"] == "" || v["password"] == "" {
		return "", "", errors.New("reset-password: the panel program did not print the new password")
	}
	return v["user"], v["password"], nil
}

// PasswordLogin reports whether the server's sshd accepts passwords, from `sshd -T` run as
// root. Anything that keeps sshd from answering yields hostcheck.Unknown.
func (c *Client) PasswordLogin(ctx context.Context) hostcheck.PasswordLogin {
	out, err := c.RunRoot(ctx, Script{Name: "sshd-settings", Body: sshdSettingsBody})
	if err != nil {
		return hostcheck.Unknown
	}
	return hostcheck.ParseSSHD(out.Stdout)
}
