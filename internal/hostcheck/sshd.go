// Package hostcheck inspects the host the panel runs on for risky settings worth a reminder.
package hostcheck

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// PasswordLogin says whether sshd accepts a password instead of a key.
type PasswordLogin string

const (
	On      PasswordLogin = "on"
	Off     PasswordLogin = "off"
	Unknown PasswordLogin = "unknown"
)

// ParseSSHD reads an `sshd -T` dump. PermitRootLogin is deliberately not consulted:
// keys-only root still leaves every other account open to password guessing.
func ParseSSHD(out string) PasswordLogin {
	opts := map[string]string{}
	for line := range strings.Lines(out) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		opts[strings.ToLower(key)] = strings.ToLower(strings.TrimSpace(value))
	}
	password, ok := yesNo(opts["passwordauthentication"])
	if !ok {
		return Unknown
	}
	kbd, ok := yesNo(opts["kbdinteractiveauthentication"])
	if !ok {
		// OpenSSH before 8.7 only knows the old name.
		kbd, _ = yesNo(opts["challengeresponseauthentication"])
	}
	// Keyboard-interactive only prompts for the account password when PAM backs it.
	pam, _ := yesNo(opts["usepam"])
	if password || (kbd && pam) {
		return On
	}
	return Off
}

func yesNo(v string) (value, ok bool) {
	switch v {
	case "yes":
		return true, true
	case "no":
		return false, true
	}
	return false, false
}

// Runner returns the effective sshd configuration as printed by `sshd -T`.
type Runner func(ctx context.Context) (string, error)

const (
	cacheTTL   = time.Minute
	runTimeout = 3 * time.Second
)

// Checker caches the answer so page loads do not fork sshd each time.
type Checker struct {
	run Runner
	now func() time.Time

	mu      sync.Mutex
	cached  PasswordLogin
	checked time.Time
}

// New uses the real sshd when run is nil.
func New(run Runner) *Checker {
	if run == nil {
		run = runSSHD
	}
	return &Checker{run: run, now: time.Now}
}

// PasswordLogin never fails: anything that prevents a clear answer is Unknown.
func (c *Checker) PasswordLogin(ctx context.Context) PasswordLogin {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cached != "" && now.Sub(c.checked) < cacheTTL {
		return c.cached
	}
	// Detached from the request so one cancelled page load does not cache Unknown for everyone.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runTimeout)
	defer cancel()
	c.cached = Unknown
	if out, err := c.run(ctx); err == nil {
		c.cached = ParseSSHD(out)
	}
	c.checked = now
	return c.cached
}

// sshd usually lives in sbin, which a service's PATH often lacks.
var sshdPaths = []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"}

func runSSHD(ctx context.Context) (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("hostcheck: sshd is only inspected on Linux")
	}
	bin, err := exec.LookPath("sshd")
	for i := 0; err != nil && i < len(sshdPaths); i++ {
		bin, err = exec.LookPath(sshdPaths[i])
	}
	if err != nil {
		return "", errors.New("hostcheck: sshd not found")
	}
	out, err := exec.CommandContext(ctx, bin, "-T").Output()
	return string(out), err
}
