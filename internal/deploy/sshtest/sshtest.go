// Package sshtest is a loopback SSH server for tests: password and public-key auth, exec with
// stdin, and direct-tcpip forwarding, all scriptable while it runs.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Exec is one command a client asked the server to run.
type Exec struct {
	User    string
	Command string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// Handler plays the remote shell; its return value is the exit status.
type Handler func(*Exec) int

// Record is what one finished exec looked like from the server's side.
type Record struct {
	User    string
	Command string
	Stdin   []byte
}

type Server struct {
	// Addr is the 127.0.0.1:port the server listens on.
	Addr string

	ln net.Listener
	wg sync.WaitGroup

	mu          sync.Mutex
	signer      ssh.Signer
	passwords   map[string]string
	passwordOff bool
	keys        map[string]map[string]bool
	handler     Handler
	dial        func(addr string) (net.Conn, error)
	records     []Record
	conns       map[net.Conn]bool
	closed      bool
	dropNext    int
}

// New starts a server that accepts nobody until SetPassword or AuthorizeKey is called.
func New(t testing.TB) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Addr:      ln.Addr().String(),
		ln:        ln,
		passwords: map[string]string{},
		keys:      map[string]map[string]bool{},
		conns:     map[net.Conn]bool{},
		handler: func(e *Exec) int {
			fmt.Fprintf(e.Stderr, "sshtest: no handler for %q\n", e.Command)
			return 127
		},
		dial: func(addr string) (net.Conn, error) { return nil, errors.New("sshtest: forwarding not configured") },
	}
	s.RotateHostKey()
	s.wg.Go(s.serve)
	t.Cleanup(s.Close)
	return s
}

// Port is the listening port as a number.
func (s *Server) Port() int {
	_, p, _ := net.SplitHostPort(s.Addr)
	n, _ := strconv.Atoi(p)
	return n
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.ln.Close()
	s.wg.Wait()
}

// RotateHostKey gives the server a new identity, as a reinstalled machine would have.
func (s *Server) RotateHostKey() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	s.signer = signer
	s.mu.Unlock()
}

// HostKeyFingerprint is the SHA256 fingerprint new connections will see.
func (s *Server) HostKeyFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ssh.FingerprintSHA256(s.signer.PublicKey())
}

func (s *Server) SetPassword(user, password string) {
	s.mu.Lock()
	s.passwords[user] = password
	s.mu.Unlock()
}

// DisablePassword makes the server stop offering password auth, like `PasswordAuthentication no`.
func (s *Server) DisablePassword() { s.setPasswordOff(true) }

func (s *Server) EnablePassword() { s.setPasswordOff(false) }

func (s *Server) setPasswordOff(off bool) {
	s.mu.Lock()
	s.passwordOff = off
	s.mu.Unlock()
}

func (s *Server) PasswordDisabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.passwordOff
}

// DropNextConnections closes the next n TCP connections before SSH negotiation.
func (s *Server) DropNextConnections(n int) {
	s.mu.Lock()
	s.dropNext += n
	s.mu.Unlock()
}

func (s *Server) AuthorizeKey(user string, key ssh.PublicKey) {
	s.mu.Lock()
	if s.keys[user] == nil {
		s.keys[user] = map[string]bool{}
	}
	s.keys[user][string(key.Marshal())] = true
	s.mu.Unlock()
}

func (s *Server) RevokeKey(user string, key ssh.PublicKey) {
	s.mu.Lock()
	delete(s.keys[user], string(key.Marshal()))
	s.mu.Unlock()
}

// RevokeAllKeys forgets every authorized key of user.
func (s *Server) RevokeAllKeys(user string) {
	s.mu.Lock()
	delete(s.keys, user)
	s.mu.Unlock()
}

// Handle installs the function that answers exec requests.
func (s *Server) Handle(h Handler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

// Forward decides where a direct-tcpip request for addr ("host:port") really connects; nil refuses all.
func (s *Server) Forward(dial func(addr string) (net.Conn, error)) {
	if dial == nil {
		dial = func(string) (net.Conn, error) { return nil, errors.New("connection refused") }
	}
	s.mu.Lock()
	s.dial = dial
	s.mu.Unlock()
}

// Records returns every exec that has finished so far, oldest first.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.records...)
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conns[c] = true
		s.mu.Unlock()
		s.wg.Go(func() {
			s.handleConn(c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		})
	}
}

// config is rebuilt per connection so auth changes made mid-test apply to the next login.
func (s *Server) config() *ssh.ServerConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.keys[meta.User()][string(key.Marshal())] {
				return nil, nil
			}
			return nil, errors.New("key not authorized")
		},
	}
	if !s.passwordOff {
		cfg.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if want, ok := s.passwords[meta.User()]; ok && want == string(password) {
				return nil, nil
			}
			return nil, errors.New("wrong password")
		}
	}
	cfg.AddHostKey(s.signer)
	return cfg
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	s.mu.Lock()
	drop := s.dropNext > 0
	if drop {
		s.dropNext--
	}
	s.mu.Unlock()
	if drop {
		return
	}
	conn, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	var wg sync.WaitGroup
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			wg.Go(func() { s.session(conn.User(), nc) })
		case "direct-tcpip":
			wg.Go(func() { s.directTCPIP(nc) })
		default:
			_ = nc.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
	wg.Wait()
}

func (s *Server) session(user string, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
			_ = req.Reply(false, nil)
			return
		}
		_ = req.Reply(true, nil)
		go ssh.DiscardRequests(reqs)

		var stdin bytes.Buffer
		s.mu.Lock()
		h := s.handler
		s.mu.Unlock()
		code := h(&Exec{User: user, Command: payload.Command, Stdin: io.TeeReader(ch, &stdin), Stdout: ch, Stderr: ch.Stderr()})
		s.mu.Lock()
		s.records = append(s.records, Record{User: user, Command: payload.Command, Stdin: stdin.Bytes()})
		s.mu.Unlock()

		var status [4]byte
		binary.BigEndian.PutUint32(status[:], uint32(code))
		_, _ = ch.SendRequest("exit-status", false, status[:])
		return
	}
}

func (s *Server) directTCPIP(nc ssh.NewChannel) {
	var payload struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &payload); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "bad direct-tcpip request")
		return
	}
	s.mu.Lock()
	dial := s.dial
	s.mu.Unlock()
	target, err := dial(net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port))))
	if err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	defer target.Close()
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, ch); closeWrite(target); done <- struct{}{} }()
	go func() { _, _ = io.Copy(ch, target); _ = ch.CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
