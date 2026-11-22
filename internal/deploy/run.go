package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxOutputBytes = 1 << 20

// Script is a POSIX shell program fed to `sh -s` on stdin. Name becomes its first line so
// a log or a test can tell scripts apart; Vars are assigned, safely quoted, before Body runs.
type Script struct {
	Name string
	Vars []Var
	Body string
}

type Var struct{ Name, Value string }

func (s Script) render() string {
	var b strings.Builder
	b.WriteString("# mintyx:" + s.Name + "\nset -eu\n")
	for _, v := range s.Vars {
		b.WriteString(v.Name + "=" + shellQuote(v.Value) + "\n")
	}
	b.WriteString(strings.TrimLeft(s.Body, "\n"))
	if !strings.HasSuffix(s.Body, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

type Output struct {
	Stdout string
	Stderr string
}

// Values reads the `key=value` lines scripts print to report what they found or did.
func (o Output) Values() map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(o.Stdout, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// ExitError is a remote command that ran and reported failure.
type ExitError struct {
	What   string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	msg := fmt.Sprintf("%s failed on the server (exit %d)", e.What, e.Code)
	if tail := lastLines(e.Stderr, 6); tail != "" {
		msg += ": " + tail
	}
	return msg
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

type cappedBuffer struct{ bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxOutputBytes - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// run executes command as the login user. what names it in errors; command itself may be long.
func (c *Client) run(ctx context.Context, what, command string, stdin io.Reader) (Output, error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return Output{}, fmt.Errorf("%s: open SSH session: %w", what, err)
	}
	defer sess.Close()
	var stdout, stderr cappedBuffer
	sess.Stdin, sess.Stdout, sess.Stderr = stdin, &stdout, &stderr

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			sess.Close()
		case <-done:
		}
	}()

	err = sess.Run(command)
	out := Output{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *ssh.ExitError
	switch {
	case err == nil:
		return out, nil
	case ctx.Err() != nil:
		return out, ctx.Err()
	case errors.As(err, &exit):
		return out, &ExitError{What: what, Code: exit.ExitStatus(), Stderr: out.Stderr}
	}
	return out, fmt.Errorf("%s: %w", what, err)
}

type rootMode int

const (
	rootUnknown rootMode = iota
	rootDirect
	rootSudo
	rootSudoPassword
)

// The password travels on stdin only, followed by a blank guard line. sudo normally consumes the
// password line and the inner shell discards the guard. If a NOPASSWD rule means sudo does not ask
// after all, the inner shell discards the password line instead, so it never runs as script text.
const (
	cmdWhoami           = "id -u"
	cmdShell            = "sh -s"
	cmdSudoProbe        = "sudo -k -n true"
	cmdSudoShell        = "sudo -n sh -s"
	cmdSudoPasswordTest = "sudo -k -S -p '' true"
	cmdSudoPasswordSh   = "sudo -k -S -p '' sh -c 'IFS= read -r _; exec sh -s'"
)

// EnsureRoot works out how this login becomes root, or returns *NeedsRootError.
func (c *Client) EnsureRoot(ctx context.Context) error {
	_, err := c.resolveRootMode(ctx)
	return err
}

func (c *Client) resolveRootMode(ctx context.Context) (rootMode, error) {
	c.rootMu.Lock()
	defer c.rootMu.Unlock()
	if c.rootMode != rootUnknown {
		return c.rootMode, nil
	}
	out, err := c.run(ctx, "id -u", cmdWhoami, nil)
	if err != nil {
		return rootUnknown, err
	}
	if strings.TrimSpace(out.Stdout) == "0" {
		c.rootMode = rootDirect
		return c.rootMode, nil
	}
	var exit *ExitError
	if _, err := c.run(ctx, "sudo", cmdSudoProbe, nil); err == nil {
		c.rootMode = rootSudo
		return c.rootMode, nil
	} else if !errors.As(err, &exit) {
		return rootUnknown, err
	}
	pw := c.target.Password
	if pw == "" {
		return rootUnknown, &NeedsRootError{User: c.target.User, Reason: "sudo asks for a password and none was given"}
	}
	if strings.ContainsAny(pw, "\r\n") {
		return rootUnknown, &NeedsRootError{User: c.target.User, Reason: "the password contains a line break"}
	}
	if _, err := c.run(ctx, "sudo", cmdSudoPasswordTest, strings.NewReader(pw+"\n")); err != nil {
		if errors.As(err, &exit) {
			return rootUnknown, &NeedsRootError{User: c.target.User, Reason: "sudo refused the password, or this user is not allowed to use sudo"}
		}
		return rootUnknown, err
	}
	c.rootMode = rootSudoPassword
	return c.rootMode, nil
}

// IsRoot reports whether the login user is root itself; valid after EnsureRoot succeeded.
func (c *Client) IsRoot() bool {
	c.rootMu.Lock()
	defer c.rootMu.Unlock()
	return c.rootMode == rootDirect
}

// RunRoot runs the script as root: directly, through passwordless sudo, or through sudo
// with the login password.
func (c *Client) RunRoot(ctx context.Context, s Script) (Output, error) {
	mode, err := c.resolveRootMode(ctx)
	if err != nil {
		return Output{}, err
	}
	text := s.render()
	switch mode {
	case rootDirect:
		return c.run(ctx, s.Name, cmdShell, strings.NewReader(text))
	case rootSudo:
		return c.run(ctx, s.Name, cmdSudoShell, strings.NewReader(text))
	default:
		return c.run(ctx, s.Name, cmdSudoPasswordSh, strings.NewReader(c.target.Password+"\n\n"+text))
	}
}

// RunUser runs the script as the login user, for things that belong to that user's home.
func (c *Client) RunUser(ctx context.Context, s Script) (Output, error) {
	return c.run(ctx, s.Name, cmdShell, strings.NewReader(s.render()))
}
