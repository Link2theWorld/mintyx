package panel

import (
	"context"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/store"
)

// ErrNoAdmin means the panel has not been set up yet, so there is no password to reset.
var ErrNoAdmin = errors.New("the panel has no admin account yet; open the panel to create one")

// ResetAdminPassword gives the admin account a new random password and returns the account
// name and that password. It backs `mintyx reset-password`, run on the server by someone who
// lost the old password: whoever can open the database there controls the panel anyway.
// Sessions opened with the old password stop working, also in a panel process that is
// already running against the same database (see credTag).
func ResetAdminPassword(ctx context.Context, st *store.Store) (user, password string, err error) {
	if _, found, err := st.GetSetting(ctx, settingAdminHash); err != nil {
		return "", "", err
	} else if !found {
		return "", "", ErrNoAdmin
	}
	if user, _, err = st.GetSetting(ctx, settingAdminUser); err != nil {
		return "", "", err
	}
	// 26 base32 characters: 130 random bits, well inside the 10-character and 72-byte limits.
	password = rand.Text()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	if err := st.SetSetting(ctx, settingAdminHash, string(hash)); err != nil {
		return "", "", err
	}
	// Best effort, as for every other action: failing here must not withhold a password that
	// is already in force.
	_ = st.AppendAudit(ctx, &model.AuditEntry{Action: "password.reset", Target: user})
	return user, password, nil
}
