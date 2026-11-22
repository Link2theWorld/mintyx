package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServer is a real SMTP listener on loopback that speaks just enough of the protocol.
type testServer struct {
	t    *testing.T
	ln   net.Listener
	cert tls.Certificate
	pool *x509.CertPool

	// implicitTLS wraps every connection in TLS from the start; startTLS advertises the upgrade.
	implicitTLS bool
	startTLS    bool
	// authMechs is what EHLO advertises; user/pass are the only accepted credentials.
	authMechs  string
	user, pass string
	rejectRcpt string

	mu       sync.Mutex
	received []receivedMail
}

type receivedMail struct {
	from string
	to   []string
	data string
	tls  bool
}

func newTestServer(t *testing.T, mod func(*testServer)) *testServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testServer{t: t, ln: ln, pool: pool, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
	if mod != nil {
		mod(s)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *testServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *testServer) tlsConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.cert}}
}

func (s *testServer) mails() []receivedMail {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]receivedMail(nil), s.received...)
}

func (s *testServer) serve(conn net.Conn) {
	defer conn.Close()
	secure := false
	if s.implicitTLS {
		conn, secure = tls.Server(conn, s.tlsConfig()), true
	}
	r := bufio.NewReader(conn)
	say := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	read := func() (string, bool) {
		line, err := r.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err == nil
	}
	b64 := func(v string) string {
		raw, _ := base64.StdEncoding.DecodeString(v)
		return string(raw)
	}
	var cur receivedMail
	authed := s.authMechs == ""
	say("220 test ESMTP")
	for {
		line, ok := read()
		if !ok {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		switch strings.ToUpper(verb) {
		case "EHLO":
			lines := []string{"test"}
			if s.startTLS && !secure {
				lines = append(lines, "STARTTLS")
			}
			if s.authMechs != "" {
				lines = append(lines, "AUTH "+s.authMechs)
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				say("250" + sep + l)
			}
		case "STARTTLS":
			say("220 go ahead")
			conn, secure = tls.Server(conn, s.tlsConfig()), true
			r = bufio.NewReader(conn)
		case "AUTH":
			mech, initial, _ := strings.Cut(arg, " ")
			var user, pass string
			switch mech {
			case "PLAIN":
				parts := strings.Split(b64(initial), "\x00")
				if len(parts) == 3 {
					user, pass = parts[1], parts[2]
				}
			case "LOGIN":
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := read()
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := read()
				user, pass = b64(u), b64(p)
			}
			if user != s.user || pass != s.pass {
				say("535 5.7.8 Authentication credentials invalid")
				continue
			}
			authed = true
			say("235 ok")
		case "MAIL":
			if !authed {
				say("530 5.7.0 Authentication required")
				continue
			}
			cur = receivedMail{from: strings.Trim(strings.TrimPrefix(arg, "FROM:"), "<>"), tls: secure}
			say("250 ok")
		case "RCPT":
			addr := strings.Trim(strings.TrimPrefix(arg, "TO:"), "<>")
			if addr == s.rejectRcpt {
				say("550 5.1.1 No such user here")
				continue
			}
			cur.to = append(cur.to, addr)
			say("250 ok")
		case "DATA":
			say("354 send it")
			var data strings.Builder
			for {
				l, ok := read()
				if !ok || l == "." {
					break
				}
				data.WriteString(l + "\n")
			}
			cur.data = data.String()
			s.mu.Lock()
			s.received = append(s.received, cur)
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("502 not implemented")
		}
	}
}
