// Package notify sends mail through an SMTP server the panel's owner chose.
// It contacts nothing else: no relay, no fallback, no project-run service.
package notify

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Security string

const (
	// StartTLS upgrades a plain connection and refuses to continue if the server cannot.
	StartTLS Security = "starttls"
	// TLS speaks TLS from the first byte (usually port 465).
	TLS Security = "tls"
	// None sends everything, including the password, unencrypted.
	None Security = "none"
)

func (s Security) Valid() bool { return s == StartTLS || s == TLS || s == None }

type Server struct {
	Host     string
	Port     int
	Security Security
	// Username empty means no authentication.
	Username string
	Password string
	// TLSConfig overrides certificate verification settings; nil verifies against Host.
	TLSConfig *tls.Config
}

type Message struct {
	From string
	// To is one address or a comma-separated list.
	To      string
	Subject string
	Body    string
}

const sendTimeout = 30 * time.Second

// Send delivers one plain-text message. Errors carry the server's own reply text.
func Send(ctx context.Context, srv Server, msg Message) error {
	from, err := mail.ParseAddress(msg.From)
	if err != nil {
		return fmt.Errorf("notify: sender address: %w", err)
	}
	to, err := mail.ParseAddressList(msg.To)
	if err != nil {
		return fmt.Errorf("notify: recipient address: %w", err)
	}
	if !srv.Security.Valid() {
		return fmt.Errorf("notify: unknown security mode %q", srv.Security)
	}

	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	host := strings.Trim(srv.Host, "[]")
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(srv.Port)))
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)

	tlsCfg := srv.TLSConfig.Clone()
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	if srv.Security == TLS {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	defer c.Close()
	if srv.Security == StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("notify: server does not offer STARTTLS; refusing to send the password unencrypted")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("notify: STARTTLS: %w", err)
		}
	}
	if srv.Username != "" {
		auth, err := chooseAuth(c, srv, host)
		if err != nil {
			return err
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("notify: sign-in: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("notify: sender: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt.Address); err != nil {
			return fmt.Errorf("notify: recipient %s: %w", rcpt.Address, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	if _, err := w.Write(render(from, to, msg, time.Now())); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	// The message is accepted once DATA closes; a failed QUIT must not report it as unsent.
	_ = c.Quit()
	return nil
}

// chooseAuth prefers PLAIN and falls back to LOGIN, which some large providers offer alone.
// Both refuse to run over an unencrypted connection to anything but localhost.
func chooseAuth(c *smtp.Client, srv Server, host string) (smtp.Auth, error) {
	_, offered := c.Extension("AUTH")
	mechs := strings.Fields(offered)
	switch {
	case slices.Contains(mechs, "PLAIN"):
		return smtp.PlainAuth("", srv.Username, srv.Password, host), nil
	case slices.Contains(mechs, "LOGIN"):
		return &loginAuth{srv.Username, srv.Password}, nil
	}
	return nil, fmt.Errorf("notify: server offers no supported sign-in method (it offers %q)", offered)
}

type loginAuth struct{ username, password string }

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && server.Name != "localhost" && server.Name != "127.0.0.1" && server.Name != "::1" {
		return "", nil, errors.New("unencrypted connection")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSuffix(string(fromServer), ":")) {
	case "username":
		return []byte(a.username), nil
	case "password":
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("unexpected server challenge %q", fromServer)
}

// render builds an RFC 5322 message; base64 keeps non-ASCII text and long lines safe everywhere.
func render(from *mail.Address, to []*mail.Address, msg Message, now time.Time) []byte {
	var rcpts []string
	for _, a := range to {
		rcpts = append(rcpts, a.String())
	}
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 {
		domain = from.Address[at+1:]
	}
	var id [12]byte
	_, _ = rand.Read(id[:])
	subject := strings.NewReplacer("\r", " ", "\n", " ").Replace(msg.Subject)

	var b strings.Builder
	b.WriteString("From: " + from.String() + "\r\n")
	b.WriteString("To: " + strings.Join(rcpts, ", ") + "\r\n")
	b.WriteString("Subject: " + mime.BEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + now.Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: <" + hex.EncodeToString(id[:]) + "@" + domain + ">\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(msg.Body))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}
