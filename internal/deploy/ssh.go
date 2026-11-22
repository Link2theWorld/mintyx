// Package deploy installs the panel on a fresh server over SSH and drives it through a tunnel,
// so the panel itself never has to listen on a public address.
package deploy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultConnectTimeout = 15 * time.Second

// Target is where and how to log in. Password doubles as the sudo password for a non-root user.
type Target struct {
	Host       string
	Port       int
	User       string
	Password   string
	PrivateKey []byte
	Passphrase string
}

// Addr is the "host:port" form used on the wire and as the known-hosts key.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

type Options struct {
	// KnownHosts is required: there is no mode that skips host key checking.
	KnownHosts *KnownHosts
	// Timeout bounds the TCP connect and the SSH handshake; zero means 15 seconds.
	Timeout time.Duration
}

var (
	// ErrAuth means the server was reached and identified, but refused the credentials.
	ErrAuth = errors.New("the server refused this user name, password or key")
	// ErrPassphraseRequired and ErrPassphraseWrong are about the pasted private key, not the server.
	ErrPassphraseRequired = errors.New("the private key is protected by a passphrase")
	ErrPassphraseWrong    = errors.New("the passphrase does not unlock the private key")
	ErrBadPrivateKey      = errors.New("the private key could not be read")
	ErrNoCredentials      = errors.New("a password or a private key is required")
)

// UnreachableError means no SSH conversation happened: wrong address, closed port, or not an SSH server.
type UnreachableError struct {
	Addr string
	Err  error
}

func (e *UnreachableError) Error() string { return "cannot reach " + e.Addr + ": " + e.Err.Error() }
func (e *UnreachableError) Unwrap() error { return e.Err }

// HostKeyChangedError means the host presented a different key than the one remembered for it.
type HostKeyChangedError struct {
	Addr      string
	Known     string
	Presented string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("the host key of %s changed: remembered %s, presented %s", e.Addr, e.Known, e.Presented)
}

// NeedsRootError means the login works but the user can neither be root nor become it.
type NeedsRootError struct {
	User   string
	Reason string
}

func (e *NeedsRootError) Error() string {
	return fmt.Sprintf("user %s cannot run commands as root: %s", e.User, e.Reason)
}

// Client is one authenticated SSH connection.
type Client struct {
	target      Target
	conn        *ssh.Client
	fingerprint string
	firstSeen   bool

	rootMu   sync.Mutex
	rootMode rootMode
}

func (t Target) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(t.PrivateKey) > 0 {
		signer, err := parseSigner(t.PrivateKey, t.Passphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if t.Password != "" {
		methods = append(methods, ssh.Password(t.Password))
		// PAM-only servers ask for the same password through keyboard-interactive.
		methods = append(methods, ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = t.Password
			}
			return answers, nil
		}))
	}
	if len(methods) == 0 {
		return nil, ErrNoCredentials
	}
	return methods, nil
}

func parseSigner(pemBytes []byte, passphrase string) (ssh.Signer, error) {
	var signer ssh.Signer
	var err error
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	}
	var missing *ssh.PassphraseMissingError
	switch {
	case err == nil:
		return signer, nil
	case errors.As(err, &missing):
		return nil, ErrPassphraseRequired
	case errors.Is(err, x509.IncorrectPasswordError):
		return nil, ErrPassphraseWrong
	case passphrase != "":
		// An unencrypted key pasted together with a passphrase is still a usable key.
		if signer, plainErr := ssh.ParsePrivateKey(pemBytes); plainErr == nil {
			return signer, nil
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrBadPrivateKey, err)
}

// hostKeyAlgorithms pins negotiation to the remembered key's type, so a host that merely
// gained another key type is not mistaken for a changed host.
func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{keyType}
}

// Dial connects and authenticates. A host seen for the first time is remembered; one that
// presents a different key than remembered is refused with *HostKeyChangedError.
func Dial(ctx context.Context, t Target, opt Options) (*Client, error) {
	if opt.KnownHosts == nil {
		return nil, errors.New("deploy: Options.KnownHosts is required")
	}
	auth, err := t.authMethods()
	if err != nil {
		return nil, err
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = defaultConnectTimeout
	}
	addr := t.Addr()
	known, isKnown, err := opt.KnownHosts.Lookup(addr)
	if err != nil {
		return nil, err
	}

	var (
		fingerprint string
		firstSeen   bool
		hostKeyErr  error
		hostKeyOK   bool
	)
	cfg := &ssh.ClientConfig{
		User:    t.User,
		Auth:    auth,
		Timeout: timeout,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = ssh.FingerprintSHA256(key)
			switch {
			case !isKnown:
				firstSeen = true
				hostKeyErr = opt.KnownHosts.Remember(addr, KnownHost{KeyType: key.Type(), Fingerprint: fingerprint, AddedAt: time.Now().UTC()})
			case known.Fingerprint != fingerprint:
				hostKeyErr = &HostKeyChangedError{Addr: addr, Known: known.Fingerprint, Presented: fingerprint}
			}
			hostKeyOK = hostKeyErr == nil
			return hostKeyErr
		},
	}
	if isKnown {
		cfg.HostKeyAlgorithms = hostKeyAlgorithms(known.KeyType)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &UnreachableError{Addr: addr, Err: err}
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	sc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		switch {
		case hostKeyErr != nil:
			return nil, hostKeyErr
		case hostKeyOK && strings.Contains(err.Error(), "unable to authenticate"):
			return nil, ErrAuth
		case isKnown && !hostKeyOK && strings.Contains(err.Error(), "no common algorithm for host key"):
			// The host no longer has a key of the remembered type at all.
			return nil, &HostKeyChangedError{Addr: addr, Known: known.Fingerprint, Presented: "a different key type"}
		}
		return nil, &UnreachableError{Addr: addr, Err: err}
	}
	_ = raw.SetDeadline(time.Time{})
	return &Client{target: t, conn: ssh.NewClient(sc, chans, reqs), fingerprint: fingerprint, firstSeen: firstSeen}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) Target() Target { return c.target }

// Fingerprint is the SHA256 fingerprint of the host key this connection verified.
func (c *Client) Fingerprint() string { return c.fingerprint }

// FirstSeen reports whether this connection was the one that remembered the host key.
func (c *Client) FirstSeen() bool { return c.firstSeen }

// DialRemote opens a TCP connection from the server's side, e.g. to its own loopback.
func (c *Client) DialRemote(ctx context.Context, addr string) (net.Conn, error) {
	return c.conn.DialContext(ctx, "tcp", addr)
}
