package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"mime"
	"net"
	"net/mail"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testMessage = Message{
	From:    "Mintyx <panel@example.com>",
	To:      "me@example.org, friend@example.net",
	Subject: "Mintyx：线路已恢复",
	Body:    "东京直连 已恢复。\n" + strings.Repeat("long line ", 30) + "\n",
}

func (s *testServer) target(sec Security) Server {
	return Server{Host: "127.0.0.1", Port: s.port(), Security: sec, TLSConfig: &tls.Config{RootCAs: s.pool}}
}

func TestSendDeliversReadableMail(t *testing.T) {
	srv := newTestServer(t, nil)
	if err := Send(context.Background(), srv.target(None), testMessage); err != nil {
		t.Fatal(err)
	}
	got := srv.mails()
	if len(got) != 1 {
		t.Fatalf("server received %d mails, want 1", len(got))
	}
	if got[0].from != "panel@example.com" || !reflect.DeepEqual(got[0].to, []string{"me@example.org", "friend@example.net"}) {
		t.Errorf("envelope = %q -> %q", got[0].from, got[0].to)
	}
	m, err := mail.ReadMessage(strings.NewReader(got[0].data))
	if err != nil {
		t.Fatalf("unparseable message: %v\n%s", err, got[0].data)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || subject != testMessage.Subject {
		t.Errorf("Subject decodes to %q (%v), want %q", subject, err, testMessage.Subject)
	}
	if to := m.Header.Get("To"); to != "<me@example.org>, <friend@example.net>" {
		t.Errorf("To = %q", to)
	}
	if _, err := m.Header.Date(); err != nil {
		t.Errorf("Date header: %v", err)
	}
	raw := new(strings.Builder)
	for _, line := range strings.Split(strings.TrimSpace(got[0].data[strings.Index(got[0].data, "\n\n"):]), "\n") {
		if len(line) > 76 {
			t.Errorf("body line of %d chars exceeds the 76 the MIME standard allows", len(line))
		}
		raw.WriteString(line)
	}
	body, err := base64.StdEncoding.DecodeString(raw.String())
	if err != nil || string(body) != testMessage.Body {
		t.Errorf("body decodes to %q (%v), want %q", body, err, testMessage.Body)
	}
}

func TestSendSecurityModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		server  func(*testServer)
		sec     Security
		wantTLS bool
		wantErr string
	}{
		{"starttls upgrades before sending", func(s *testServer) { s.startTLS = true }, StartTLS, true, ""},
		{"implicit tls", func(s *testServer) { s.implicitTLS = true }, TLS, true, ""},
		{"none stays plain", nil, None, false, ""},
		{"starttls refuses a server that cannot upgrade", nil, StartTLS, false,
			"notify: server does not offer STARTTLS; refusing to send the password unencrypted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, tc.server)
			err := Send(context.Background(), srv.target(tc.sec), testMessage)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				if n := len(srv.mails()); n != 0 {
					t.Errorf("%d mails went out despite the refusal", n)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := srv.mails(); len(got) != 1 || got[0].tls != tc.wantTLS {
				t.Errorf("mails = %+v, want one with tls=%v", got, tc.wantTLS)
			}
		})
	}
}

func TestSendRejectsUntrustedCertificate(t *testing.T) {
	srv := newTestServer(t, func(s *testServer) { s.startTLS = true })
	target := srv.target(StartTLS)
	target.TLSConfig = nil
	err := Send(context.Background(), target, testMessage)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate verification failure", err)
	}
	if n := len(srv.mails()); n != 0 {
		t.Errorf("%d mails sent over an unverified connection", n)
	}
}

func TestSendAuthenticates(t *testing.T) {
	for _, tc := range []struct {
		name, mechs, pass, wantErr string
	}{
		{"plain", "LOGIN PLAIN", "s3cret", ""},
		{"login when plain is not offered", "LOGIN", "s3cret", ""},
		{"wrong password surfaces the server's reply", "PLAIN", "nope", `notify: sign-in: 535 "5.7.8 Authentication credentials invalid"`},
		{"no usable mechanism", "CRAM-MD5", "s3cret", `notify: server offers no supported sign-in method (it offers "CRAM-MD5")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, func(s *testServer) {
				s.startTLS, s.authMechs, s.user, s.pass = true, tc.mechs, "panel@example.com", "s3cret"
			})
			target := srv.target(StartTLS)
			target.Username, target.Password = "panel@example.com", tc.pass
			err := Send(context.Background(), target, testMessage)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if len(srv.mails()) != 1 {
					t.Error("authenticated mail did not arrive")
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestSendReportsServerRefusals(t *testing.T) {
	srv := newTestServer(t, func(s *testServer) { s.rejectRcpt = "friend@example.net" })
	err := Send(context.Background(), srv.target(None), testMessage)
	if want := `notify: recipient friend@example.net: 550 "5.1.1 No such user here"`; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}

	needAuth := newTestServer(t, func(s *testServer) { s.authMechs, s.user, s.pass = "PLAIN", "u", "p" })
	err = Send(context.Background(), needAuth.target(None), testMessage)
	if want := `notify: sender: 530 "5.7.0 Authentication required"`; err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}
}

func TestSendRejectsBadInput(t *testing.T) {
	srv := newTestServer(t, nil)
	for _, tc := range []struct {
		name string
		mod  func(*Server, *Message)
		want string
	}{
		{"header injection through the sender", func(_ *Server, m *Message) { m.From = "a@example.com\r\nBcc: x@example.com" }, "notify: sender address:"},
		{"empty recipient", func(_ *Server, m *Message) { m.To = "" }, "notify: recipient address:"},
		{"unknown security mode", func(s *Server, _ *Message) { s.Security = "ssl" }, `notify: unknown security mode "ssl"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, msg := srv.target(None), testMessage
			tc.mod(&target, &msg)
			err := Send(context.Background(), target, msg)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Errorf("err = %v, want prefix %q", err, tc.want)
			}
		})
	}
	if n := len(srv.mails()); n != 0 {
		t.Errorf("%d mails sent from invalid input", n)
	}
}

func TestSendSubjectCannotInjectHeaders(t *testing.T) {
	srv := newTestServer(t, nil)
	msg := testMessage
	msg.Subject = "hello\r\nBcc: evil@example.com"
	if err := Send(context.Background(), srv.target(None), msg); err != nil {
		t.Fatal(err)
	}
	m, err := mail.ReadMessage(strings.NewReader(srv.mails()[0].data))
	if err != nil {
		t.Fatal(err)
	}
	if bcc := m.Header.Get("Bcc"); bcc != "" {
		t.Errorf("subject smuggled a Bcc header: %q", bcc)
	}
}

func TestSendGivesUpOnASilentServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			defer conn.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = Send(ctx, Server{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Security: None}, testMessage)
	if err == nil {
		t.Fatal("Send returned nil against a server that never greets")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("Send took %s, want it to honour the 200ms context deadline", took)
	}
}
