package deploy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/deploy/deploytest"
)

type keyLoginCase struct {
	v      *deploytest.VPS
	kh     *KnownHosts
	c      *Client
	keyDir string
}

func newKeyLoginCase(t *testing.T, setup func(*deploytest.VPS)) *keyLoginCase {
	t.Helper()
	v := deploytest.New(t)
	if setup != nil {
		setup(v)
	}
	kh := testKnownHosts(t)
	return &keyLoginCase{v: v, kh: kh, c: dialVPS(t, v, kh), keyDir: filepath.Join(t.TempDir(), ".ssh")}
}

func (k *keyLoginCase) enable(t *testing.T) (*KeyLoginResult, error) {
	t.Helper()
	return k.c.EnableKeyLogin(testContext(t), KeyLoginOptions{KeyDir: k.keyDir, KnownHosts: k.kh})
}

// passwordLoginWorks tries a brand-new password login, which is what the user would be locked out of.
func (k *keyLoginCase) passwordLoginWorks(t *testing.T) bool {
	t.Helper()
	c, err := Dial(testContext(t), vpsTarget(k.v), Options{KnownHosts: k.kh})
	if err != nil {
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("password login: %v", err)
		}
		return false
	}
	c.Close()
	return true
}

func (k *keyLoginCase) keyLoginWorks(t *testing.T, keyPath string) bool {
	t.Helper()
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(testContext(t), Target{Host: "127.0.0.1", Port: k.v.SSH.Port(), User: deploytest.User, PrivateKey: pemBytes}, Options{KnownHosts: k.kh})
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func keyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestKeyLoginSucceeds(t *testing.T) {
	k := newKeyLoginCase(t, nil)
	res, err := k.enable(t)
	if err != nil {
		t.Fatalf("EnableKeyLogin: %v", err)
	}
	if !res.PasswordOff {
		t.Fatal("PasswordOff = false after a clean run")
	}
	if want := filepath.Join(k.keyDir, "mintyx_127.0.0.1_ed25519"); res.KeyPath != want {
		t.Fatalf("key saved at %q, want %q", res.KeyPath, want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(res.KeyPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %o, want 600", fi.Mode().Perm())
		}
	}
	if !k.keyLoginWorks(t, res.KeyPath) {
		t.Fatal("the saved key cannot log in")
	}
	if k.passwordLoginWorks(t) {
		t.Fatal("password login still works")
	}
	want := []string{"authorized-keys-add", "keylogin-apply"}
	if got := k.v.RanNames(); !slices.Equal(got, want) {
		t.Fatalf("scripts = %v, want %v", got, want)
	}
}

// Outcome: the key never worked, so sshd must not have been touched at all.
func TestKeyLoginStopsWhenTheKeyNeverWorks(t *testing.T) {
	k := newKeyLoginCase(t, func(v *deploytest.VPS) { v.IgnoreAuthorizedKeys = true })
	res, err := k.enable(t)
	if !errors.Is(err, ErrKeyNeverWorked) || res != nil {
		t.Fatalf("res = %+v, err = %v; want nil and ErrKeyNeverWorked", res, err)
	}
	if got := k.v.RanNames(); slices.Contains(got, "keylogin-apply") {
		t.Fatalf("scripts = %v: sshd was reconfigured although the key never worked", got)
	}
	if !k.passwordLoginWorks(t) {
		t.Fatal("password login was lost")
	}
	if keys, _ := k.v.File("~/.ssh/authorized_keys"); len(keys) != 0 {
		t.Fatalf("authorized_keys still holds the useless key: %q", keys)
	}
	if left := keyFiles(t, k.keyDir); len(left) != 0 {
		t.Fatalf("useless key files left on this computer: %v", left)
	}
}

// Outcome: passwords went off, the key then failed, and the change was undone.
func TestKeyLoginRollsBackWhenTheSecondProofFails(t *testing.T) {
	k := newKeyLoginCase(t, func(v *deploytest.VPS) { v.BreakKeysWithPasswords = true })
	res, err := k.enable(t)
	var rolled *KeyLoginRolledBackError
	if !errors.As(err, &rolled) || rolled.RollbackErr != nil {
		t.Fatalf("err = %v, want a clean *KeyLoginRolledBackError", err)
	}
	if res == nil || res.PasswordOff {
		t.Fatalf("res = %+v, want a result with PasswordOff false", res)
	}
	if _, present := k.v.File(SSHDDropIn); present {
		t.Fatal("the sshd drop-in is still there after the rollback")
	}
	if !k.passwordLoginWorks(t) {
		t.Fatal("password login was not restored: the user is locked out")
	}
	want := []string{"authorized-keys-add", "keylogin-apply", "keylogin-rollback"}
	if got := k.v.RanNames(); !slices.Equal(got, want) {
		t.Fatalf("scripts = %v, want %v", got, want)
	}
}

// Outcome: the key works but another config file keeps passwords on.
func TestKeyLoginReportsAnotherConfigKeepingPasswordsOn(t *testing.T) {
	k := newKeyLoginCase(t, func(v *deploytest.VPS) { v.OtherConfigKeepsPasswords = true })
	res, err := k.enable(t)
	var still *PasswordStillOnError
	if !errors.As(err, &still) {
		t.Fatalf("err = %v, want *PasswordStillOnError", err)
	}
	if want := []string{"/etc/ssh/sshd_config.d/50-cloud-init.conf"}; !slices.Equal(still.Files, want) {
		t.Fatalf("Files = %v, want %v", still.Files, want)
	}
	if res == nil || res.PasswordOff || !k.keyLoginWorks(t, res.KeyPath) {
		t.Fatalf("res = %+v, want a working key with PasswordOff false", res)
	}
	if !k.passwordLoginWorks(t) {
		t.Fatal("password login should still work in this outcome")
	}
}

func TestKeyLoginNeverOverwritesAnExistingKeyFile(t *testing.T) {
	k := newKeyLoginCase(t, nil)
	if err := os.MkdirAll(k.keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(k.keyDir, "mintyx_127.0.0.1_ed25519")
	if err := os.WriteFile(existing, []byte("someone's key"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := k.enable(t)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(existing); string(got) != "someone's key" {
		t.Fatalf("existing key file was overwritten: %q", got)
	}
	if want := filepath.Join(k.keyDir, "mintyx_127.0.0.1_2_ed25519"); res.KeyPath != want {
		t.Fatalf("new key at %q, want %q", res.KeyPath, want)
	}
	if pub, _ := os.ReadFile(res.KeyPath + ".pub"); !strings.HasPrefix(string(pub), "ssh-ed25519 ") {
		t.Fatalf("public key file = %q, want an ssh-ed25519 line", pub)
	}
}
