package deploy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ErrKeyNeverWorked means the new key could not log in, so the server's SSH settings were left alone.
var ErrKeyNeverWorked = errors.New("the new key could not log in; nothing was changed on the server")

// KeyLoginRolledBackError means password login was (or was about to be) turned off, the
// safety check failed, and the change was undone. Passwords work as before.
type KeyLoginRolledBackError struct {
	Reason string
	// RollbackErr is set when undoing failed too; the open connection is then the only way in.
	RollbackErr error
}

func (e *KeyLoginRolledBackError) Error() string {
	if e.RollbackErr != nil {
		return "turning off password login failed (" + e.Reason + ") and undoing it failed too: " + e.RollbackErr.Error()
	}
	return "turning off password login was undone: " + e.Reason
}

// PasswordStillOnError means key login works, but another sshd config file keeps passwords
// enabled and the deployer will not edit files it did not write.
type PasswordStillOnError struct {
	// Files lists config files that say `PasswordAuthentication yes`; may be empty.
	Files []string
}

func (e *PasswordStillOnError) Error() string {
	msg := "key login works, but password login is still enabled by the server's own SSH configuration"
	if len(e.Files) > 0 {
		msg += " (" + strings.Join(e.Files, ", ") + ")"
	}
	return msg
}

type KeyLoginOptions struct {
	// KeyDir is where the private key is saved; normally ~/.ssh.
	KeyDir     string
	KnownHosts *KnownHosts
}

// KeyLoginResult is returned whenever a working key exists, including with *PasswordStillOnError.
type KeyLoginResult struct {
	KeyPath     string
	PublicKey   string
	PasswordOff bool
}

const (
	keyLoginProofTimeout  = 5 * time.Second
	keyLoginProofInterval = 100 * time.Millisecond
)

func proveAfterReload(ctx context.Context, prove func(context.Context) error) error {
	start := time.Now()
	for {
		err := prove(ctx)
		if err == nil {
			return nil
		}
		var unreachable *UnreachableError
		if !errors.As(err, &unreachable) || ctx.Err() != nil || time.Since(start) >= keyLoginProofTimeout {
			return err
		}
		timer := time.NewTimer(keyLoginProofInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

// EnableKeyLogin creates a key, proves it logs in, and only then turns password login off,
// proving the key again afterwards and undoing the change if that fails.
func (c *Client) EnableKeyLogin(ctx context.Context, opt KeyLoginOptions) (*KeyLoginResult, error) {
	if err := c.EnsureRoot(ctx); err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "mintyx-deploy")
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(block)
	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " mintyx-deploy"

	keyPath, err := saveNewKey(opt.KeyDir, c.target.Host, privPEM, authorized)
	if err != nil {
		return nil, err
	}
	keyVar := []Var{{"KEY", authorized}}
	discard := func() {
		_, _ = c.RunUser(ctx, Script{Name: "authorized-keys-remove", Body: authorizedKeysRemoveBody, Vars: keyVar})
		_ = os.Remove(keyPath)
		_ = os.Remove(keyPath + ".pub")
	}
	if _, err := c.RunUser(ctx, Script{Name: "authorized-keys-add", Body: authorizedKeysAddBody, Vars: keyVar}); err != nil {
		discard()
		return nil, err
	}

	prove := func(proofCtx context.Context) error {
		t := Target{Host: c.target.Host, Port: c.target.Port, User: c.target.User, PrivateKey: privPEM}
		probe, err := Dial(proofCtx, t, Options{KnownHosts: opt.KnownHosts})
		if err != nil {
			return err
		}
		return probe.Close()
	}
	if err := prove(ctx); err != nil {
		discard()
		return nil, fmt.Errorf("%w (%v)", ErrKeyNeverWorked, err)
	}
	res := &KeyLoginResult{KeyPath: keyPath, PublicKey: authorized}

	dropIn := []Var{{"DROPIN", SSHDDropIn}}
	out, err := c.RunRoot(ctx, Script{Name: "keylogin-apply", Body: keyLoginApplyBody, Vars: dropIn})
	if err != nil {
		return res, err
	}
	v := out.Values()
	switch v["result"] {
	case "applied":
	case "still-on":
		return res, &PasswordStillOnError{Files: strings.Fields(v["files"])}
	case "invalid":
		return res, &KeyLoginRolledBackError{Reason: "sshd rejected the new setting: " + lastLines(out.Stderr, 3)}
	case "reload-failed":
		return res, &KeyLoginRolledBackError{Reason: "sshd could not be reloaded"}
	default:
		return res, fmt.Errorf("keylogin-apply: unexpected answer %q", strings.TrimSpace(out.Stdout))
	}

	if proveErr := proveAfterReload(ctx, prove); proveErr != nil {
		rolled := &KeyLoginRolledBackError{Reason: "the key stopped working once passwords were off (" + proveErr.Error() + ")"}
		// This runs on the connection that was open all along, which no sshd reload cuts.
		if _, err := c.RunRoot(ctx, Script{Name: "keylogin-rollback", Body: keyLoginRollbackBody, Vars: dropIn}); err != nil {
			rolled.RollbackErr = err
		}
		return res, rolled
	}
	res.PasswordOff = true
	return res, nil
}

// saveNewKey writes the key pair under a name that includes the host and never replaces a file.
func saveNewKey(dir, host string, privPEM []byte, authorized string) (string, error) {
	if dir == "" {
		return "", errors.New("deploy: KeyLoginOptions.KeyDir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, host)
	for n := 1; n < 1000; n++ {
		name := "mintyx_" + safe + "_ed25519"
		if n > 1 {
			name = fmt.Sprintf("mintyx_%s_%d_ed25519", safe, n)
		}
		path := filepath.Join(dir, name)
		if _, err := os.Lstat(path + ".pub"); err == nil {
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		_, werr := f.Write(privPEM)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.WriteFile(path+".pub", []byte(authorized+"\n"), 0o644)
		}
		if werr != nil {
			_ = os.Remove(path)
			return "", werr
		}
		return path, nil
	}
	return "", errors.New("too many existing mintyx keys for this host in " + dir)
}
