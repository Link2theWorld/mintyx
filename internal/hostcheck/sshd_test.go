package hostcheck

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Trimmed `sshd -T` dumps; real output is ~150 lowercase "keyword value" lines in this shape.
const (
	debianDefault = `port 22
addressfamily any
listenaddress [::]:22
listenaddress 0.0.0.0:22
usepam yes
logingracetime 120
permitrootlogin yes
pubkeyauthentication yes
passwordauthentication yes
kbdinteractiveauthentication no
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
subsystem sftp /usr/lib/openssh/sftp-server
`
	keyOnly = `port 22
usepam yes
permitrootlogin prohibit-password
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
`
	// PasswordAuthentication no alone still lets PAM ask for the password over keyboard-interactive.
	pamKbdLeftOn = `port 22
usepam yes
permitrootlogin yes
passwordauthentication no
kbdinteractiveauthentication yes
`
	kbdWithoutPAM = `port 22
usepam no
permitrootlogin yes
passwordauthentication no
kbdinteractiveauthentication yes
`
	// OpenSSH before 8.7 prints the old keyword name.
	legacyKeyword = `port 22
usepam yes
permitrootlogin without-password
passwordauthentication no
challengeresponseauthentication yes
`
	rootKeyOnlyOthersPassword = `port 22
usepam yes
permitrootlogin prohibit-password
passwordauthentication yes
kbdinteractiveauthentication no
`
)

func TestParseSSHD(t *testing.T) {
	for _, tc := range []struct {
		name, out string
		want      PasswordLogin
	}{
		{"distro default accepts passwords", debianDefault, On},
		{"key only", keyOnly, Off},
		{"keyboard-interactive through PAM is a password login", pamKbdLeftOn, On},
		{"keyboard-interactive without PAM has nothing to ask", kbdWithoutPAM, Off},
		{"pre-8.7 keyword name", legacyKeyword, On},
		{"root restricted to keys, other accounts still take passwords", rootKeyOnlyOthersPassword, On},
		{"CRLF and mixed case", "UsePAM yes\r\nPasswordAuthentication NO\r\nKbdInteractiveAuthentication no\r\n", Off},
		{"empty output", "", Unknown},
		{"error text instead of a dump", "sshd: no hostkeys available -- exiting.\n", Unknown},
		{"unrecognised value", "passwordauthentication maybe\n", Unknown},
		{"keyword only inside another value", "banner /etc/passwordauthentication yes\n", Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseSSHD(tc.out); got != tc.want {
				t.Errorf("ParseSSHD = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckerCachesAndRefreshes(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	out, runs := debianDefault, 0
	c := New(func(context.Context) (string, error) { runs++; return out, nil })
	c.now = func() time.Time { return now }

	if got := c.PasswordLogin(t.Context()); got != On {
		t.Fatalf("first check = %q, want %q", got, On)
	}
	out = keyOnly
	now = now.Add(cacheTTL - time.Second)
	if got := c.PasswordLogin(t.Context()); got != On || runs != 1 {
		t.Fatalf("within TTL: got %q after %d runs, want cached %q after 1 run", got, runs, On)
	}
	now = now.Add(2 * time.Second)
	if got := c.PasswordLogin(t.Context()); got != Off || runs != 2 {
		t.Fatalf("after TTL: got %q after %d runs, want %q after 2 runs", got, runs, Off)
	}
}

func TestCheckerRunnerFailureIsUnknown(t *testing.T) {
	// A failed run may still print a partial dump; it must not be trusted.
	c := New(func(context.Context) (string, error) { return keyOnly, errors.New("exit status 255") })
	if got := c.PasswordLogin(t.Context()); got != Unknown {
		t.Errorf("PasswordLogin = %q, want %q", got, Unknown)
	}
}
