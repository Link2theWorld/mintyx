package panel

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/reach"
)

// fakePinger answers every measurement from answer and records the requests.
type fakePinger struct {
	mu     sync.Mutex
	calls  []reach.PingRequest
	answer func(reach.PingRequest) ([]reach.ProbeResult, error)
	// hang, when set, makes Ping wait for its context instead of answering.
	hang chan struct{}
}

func (p *fakePinger) Ping(ctx context.Context, req reach.PingRequest) (reach.PingResult, error) {
	p.mu.Lock()
	p.calls = append(p.calls, req)
	answer, hang := p.answer, p.hang
	p.mu.Unlock()
	if hang != nil {
		select {
		case hang <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return reach.PingResult{}, ctx.Err()
	}
	probes, err := answer(req)
	return reach.PingResult{ID: "anchor", Probes: probes}, err
}

func (p *fakePinger) set(answer func(reach.PingRequest) ([]reach.ProbeResult, error)) {
	p.mu.Lock()
	p.answer = answer
	p.mu.Unlock()
}

func (p *fakePinger) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// seen builds one measurement's probes: cn of 5 China probes and ctl of 3 others got through.
func seen(cn, ctl int) []reach.ProbeResult {
	var out []reach.ProbeResult
	for i := range 8 {
		china := i < 5
		ok := (china && i < cn) || (!china && i-5 < ctl)
		o := reach.Unreached
		if ok {
			o = reach.Reached
		}
		out = append(out, reach.ProbeResult{China: china, Outcome: o})
	}
	return out
}

var (
	allFine     = func(reach.PingRequest) ([]reach.ProbeResult, error) { return seen(5, 3), nil }
	port443Shut = func(r reach.PingRequest) ([]reach.ProbeResult, error) {
		if r.Port == 443 {
			return seen(0, 3), nil
		}
		return seen(5, 3), nil
	}
)

// mailSink is a loopback SMTP server that accepts anything and keeps the messages.
type mailSink struct {
	ln   net.Listener
	mu   sync.Mutex
	got  []string
	rcpt [][]string
}

func newMailSink(t *testing.T) *mailSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &mailSink{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serve(conn)
		}
	}()
	return m
}

func (m *mailSink) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
	say("220 sink")
	var rcpt []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
		switch strings.ToUpper(verb) {
		case "RCPT":
			rcpt = append(rcpt, strings.Trim(strings.TrimPrefix(arg, "TO:"), "<>"))
			say("250 ok")
		case "DATA":
			say("354 go")
			var data strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				data.WriteString(l)
			}
			m.mu.Lock()
			m.got, m.rcpt = append(m.got, data.String()), append(m.rcpt, rcpt)
			m.mu.Unlock()
			say("250 ok")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func (m *mailSink) port() int { return m.ln.Addr().(*net.TCPAddr).Port }

func (m *mailSink) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.got)
}

func (m *mailSink) smtp() map[string]any {
	return map[string]any{
		"host": "127.0.0.1", "port": m.port(), "security": "none", "username": "",
		"from": "panel@example.com", "to": "me@example.org",
	}
}

type reachFixture struct {
	*fixture
	c      *http.Cookie
	pinger *fakePinger
}

// newReachFixture has one enabled REALITY line "tokyo" on vpn.example.com:443.
func newReachFixture(t *testing.T) *reachFixture {
	t.Helper()
	p := &fakePinger{answer: allFine}
	f := newFixture(t, func(c *Config) { c.Reach = p })
	rf := &reachFixture{fixture: f, c: f.setup(), pinger: p}
	expectStatus(t, f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(rf.c)), http.StatusCreated)
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(rf.c)), http.StatusOK)
	return rf
}

func (f *reachFixture) configure(enabled bool, smtp map[string]any) {
	f.t.Helper()
	if smtp == nil {
		smtp = map[string]any{"host": "", "port": 587, "security": "starttls"}
	}
	body := map[string]any{"enabled": enabled, "intervalMinutes": 30, "confirmRounds": 2, "smtp": smtp}
	expectStatus(f.t, f.do("PUT", "/api/reach/config", body, withCookie(f.c)), http.StatusOK)
}

func (f *reachFixture) status() reachStatusDTO {
	f.t.Helper()
	w := f.do("GET", "/api/reach/status", nil, withCookie(f.c))
	expectStatus(f.t, w, http.StatusOK)
	return decodeBody[reachStatusDTO](f.t, w)
}

func (f *reachFixture) advance(d time.Duration) { *f.clock = f.clock.Add(d) }

// tick runs the background loop's step and reports whether a round ran.
func (f *reachFixture) tick() bool {
	f.t.Helper()
	ran, err := f.srv.NewReachRunner(time.Minute).Tick(f.t.Context())
	if err != nil {
		f.t.Fatal(err)
	}
	return ran
}

func TestReachConfigDefaults(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	got := strings.TrimSpace(f.do("GET", "/api/reach/config", nil, withCookie(c)).Body.String())
	want := `{"enabled":false,"intervalMinutes":30,"confirmRounds":2,"smtp":{"host":"","port":587,"security":"starttls","username":"","passwordSet":false,"from":"","to":""}}`
	if got != want {
		t.Errorf("default config = %s\nwant             %s", got, want)
	}
}

func TestReachConfigValidation(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	valid := func() map[string]any {
		return map[string]any{"enabled": true, "intervalMinutes": 30, "confirmRounds": 2, "smtp": map[string]any{
			"host": "smtp.example.com", "port": 587, "security": "starttls", "username": "u", "password": "p",
			"from": "panel@example.com", "to": "a@example.org, b@example.org",
		}}
	}
	expectStatus(t, f.do("PUT", "/api/reach/config", valid(), withCookie(c)), http.StatusOK)
	for _, tc := range []struct {
		field string
		mod   func(cfg, smtp map[string]any)
	}{
		{"intervalMinutes", func(cfg, _ map[string]any) { cfg["intervalMinutes"] = 9 }},
		{"intervalMinutes", func(cfg, _ map[string]any) { cfg["intervalMinutes"] = 1441 }},
		{"confirmRounds", func(cfg, _ map[string]any) { cfg["confirmRounds"] = 0 }},
		{"confirmRounds", func(cfg, _ map[string]any) { cfg["confirmRounds"] = 11 }},
		{"smtp.host", func(_, smtp map[string]any) { smtp["host"] = "smtp.example.com:587" }},
		{"smtp.port", func(_, smtp map[string]any) { smtp["port"] = 0 }},
		{"smtp.security", func(_, smtp map[string]any) { smtp["security"] = "ssl" }},
		{"smtp.security", func(_, smtp map[string]any) { smtp["security"] = "none" }},
		{"smtp.from", func(_, smtp map[string]any) { smtp["from"] = "" }},
		{"smtp.from", func(_, smtp map[string]any) { smtp["from"] = "a@example.com, b@example.com" }},
		{"smtp.to", func(_, smtp map[string]any) { smtp["to"] = "not an address" }},
		{"smtp.username", func(_, smtp map[string]any) { smtp["username"] = "u\r\nRCPT TO:<x@example.com>" }},
		{"smtp.password", func(_, smtp map[string]any) { smtp["password"] = "p\nq" }},
	} {
		body := valid()
		tc.mod(body, body["smtp"].(map[string]any))
		expectError(t, f.do("PUT", "/api/reach/config", body, withCookie(c)), http.StatusBadRequest, codeInvalid, tc.field)
	}
	// Signing in without encryption is fine to a mail server on this machine.
	local := valid()
	local["smtp"].(map[string]any)["host"], local["smtp"].(map[string]any)["security"] = "127.0.0.1", "none"
	expectStatus(t, f.do("PUT", "/api/reach/config", local, withCookie(c)), http.StatusOK)
	// Clearing the host turns mail off even with an unencrypted sign-in left in the other fields.
	cleared := valid()
	cleared["smtp"].(map[string]any)["host"], cleared["smtp"].(map[string]any)["security"] = "", "none"
	cleared["smtp"].(map[string]any)["from"], cleared["smtp"].(map[string]any)["to"] = "", ""
	expectStatus(t, f.do("PUT", "/api/reach/config", cleared, withCookie(c)), http.StatusOK)
	// Mail is optional: without a host nothing about it is required.
	off := valid()
	off["smtp"] = map[string]any{"host": "", "port": 587, "security": "starttls"}
	expectStatus(t, f.do("PUT", "/api/reach/config", off, withCookie(c)), http.StatusOK)
}

func TestReachRoutesNeedLoginAndCSRFHeader(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	for _, rt := range [][2]string{
		{"GET", "/api/reach/config"}, {"PUT", "/api/reach/config"}, {"GET", "/api/reach/status"},
		{"POST", "/api/reach/check"}, {"POST", "/api/reach/test-email"},
	} {
		expectError(t, f.do(rt[0], rt[1], map[string]any{}), http.StatusUnauthorized, codeUnauthorized, "")
		if rt[0] != "GET" {
			expectError(t, f.do(rt[0], rt[1], map[string]any{}, withCookie(c), noMintyx()), http.StatusForbidden, codeForbidden, "")
		}
	}
}

func TestReachSMTPPasswordIsWriteOnly(t *testing.T) {
	const secret = "hunter2-smtp-secret"
	f := newFixture(t, nil)
	c := f.setup()
	smtp := map[string]any{
		"host": "smtp.example.com", "port": 465, "security": "tls", "username": "panel@example.com",
		"password": secret, "from": "panel@example.com", "to": "me@example.org",
	}
	body := map[string]any{"enabled": false, "intervalMinutes": 30, "confirmRounds": 2, "smtp": smtp}
	stored := func() string {
		t.Helper()
		v, _, err := f.st.GetSetting(t.Context(), settingReachPassword)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	w := f.do("PUT", "/api/reach/config", body, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	get := f.do("GET", "/api/reach/config", nil, withCookie(c))
	for name, text := range map[string]string{"PUT response": w.Body.String(), "GET response": get.Body.String()} {
		if strings.Contains(text, secret) || strings.Contains(text, `"password"`) {
			t.Errorf("%s leaks the password: %s", name, text)
		}
		if !strings.Contains(text, `"passwordSet":true`) {
			t.Errorf("%s does not say a password is stored: %s", name, text)
		}
	}
	if stored() != secret {
		t.Fatalf("stored password = %q", stored())
	}
	if raw, _, _ := f.st.GetSetting(t.Context(), settingReachConfig); strings.Contains(raw, secret) {
		t.Errorf("config JSON carries the password: %s", raw)
	}

	// Saving again with an empty password keeps it.
	smtp["password"] = ""
	smtp["port"] = 587
	expectStatus(t, f.do("PUT", "/api/reach/config", body, withCookie(c)), http.StatusOK)
	if stored() != secret {
		t.Errorf("empty password on save replaced the stored one with %q", stored())
	}

	// Pointing the stored password at another server or account needs it typed again.
	smtp["host"] = "evil.example.net"
	expectError(t, f.do("PUT", "/api/reach/config", body, withCookie(c)), http.StatusBadRequest, codeInvalid, "smtp.password")
	expectError(t, f.do("POST", "/api/reach/test-email", smtp, withCookie(c)), http.StatusBadRequest, codeInvalid, "smtp.password")
	smtp["host"], smtp["username"] = "smtp.example.com", "other@example.com"
	expectError(t, f.do("PUT", "/api/reach/config", body, withCookie(c)), http.StatusBadRequest, codeInvalid, "smtp.password")
	if stored() != secret {
		t.Errorf("a refused save changed the stored password to %q", stored())
	}

	// No username means no sign-in, so the password is dropped.
	smtp["username"] = ""
	w = f.do("PUT", "/api/reach/config", body, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if stored() != "" || !strings.Contains(w.Body.String(), `"passwordSet":false`) {
		t.Errorf("password survived clearing the username: stored %q, body %s", stored(), w.Body)
	}

	audit := decodeBody[struct{ Entries []auditDTO }](t, f.do("GET", "/api/audit?limit=50", nil, withCookie(c)))
	var details []string
	for _, e := range audit.Entries {
		if strings.Contains(e.Detail+e.Target, secret) {
			t.Errorf("audit entry leaks the password: %+v", e)
		}
		if e.Action == "reach.configure" {
			details = append(details, e.Detail)
		}
	}
	want := []string{"smtp, smtp.password", "smtp", "smtp, smtp.password"}
	if !reflect.DeepEqual(details, want) {
		t.Errorf("reach.configure details, newest first = %q, want %q", details, want)
	}
}

func TestReachNotConfiguredWithoutPublicHost(t *testing.T) {
	p := &fakePinger{answer: allFine}
	f := newFixture(t, func(c *Config) { c.Reach = p })
	rf := &reachFixture{fixture: f, c: f.setup(), pinger: p}
	expectStatus(t, f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(rf.c)), http.StatusCreated)
	rf.configure(true, nil)

	st := rf.status()
	if st.Configured || len(st.Targets) != 0 || st.NextCheckAt != nil {
		t.Errorf("status = %+v, want unconfigured with nothing scheduled", st)
	}
	expectError(t, f.do("POST", "/api/reach/check", nil, withCookie(rf.c)), http.StatusConflict, codeConflict, "")
	if rf.tick() || p.count() != 0 {
		t.Errorf("probed %d times without an address to probe", p.count())
	}
}

func TestReachDisabledByDefaultProbesNothing(t *testing.T) {
	f := newReachFixture(t)
	if f.tick() {
		t.Error("loop ran a round although the owner never opted in")
	}
	expectError(t, f.do("POST", "/api/reach/check", nil, withCookie(f.c)), http.StatusConflict, codeConflict, "")
	if n := f.pinger.count(); n != 0 {
		t.Errorf("%d measurements sent while disabled", n)
	}
	if st := f.status(); st.Enabled || st.NextCheckAt != nil || !st.Configured || len(st.Targets) != 1 {
		t.Errorf("status = %+v", st)
	}
}

func TestReachCheckNowReportsVerdictsAndThrottles(t *testing.T) {
	f := newReachFixture(t)
	hy := model.Line{Name: "hy", Protocol: model.Hysteria2, Port: 8443, Enabled: true, Hysteria2: &model.Hysteria2Params{Domain: "hy.example.com"}}
	off := model.Line{Name: "off", Protocol: model.VLESSReality, Port: 9443, Reality: &model.RealityParams{PublicKey: "k", ServerName: "s"}}
	for _, l := range []*model.Line{&hy, &off} {
		if err := f.st.CreateLine(t.Context(), l); err != nil {
			t.Fatal(err)
		}
	}
	f.configure(true, nil)

	w := f.do("POST", "/api/reach/check", nil, withCookie(f.c))
	expectStatus(t, w, http.StatusOK)
	st := decodeBody[reachStatusDTO](t, w)
	now := *f.clock
	next := now.Add(30 * time.Minute)
	want := reachStatusDTO{
		Enabled: true, Configured: true, LastCheckAt: &now, NextCheckAt: &next,
		Targets: []reachTargetDTO{
			{LineID: 1, LineName: "tokyo", Protocol: "vless-reality", Host: "vpn.example.com", Port: 443,
				Verdict: reach.OK, Since: &now, LastResult: reach.OK, ChinaReached: 5, ChinaAnswered: 5, ControlReached: 3, ControlAnswered: 3},
			{LineID: hy.ID, LineName: "hy", Protocol: "hysteria2", Host: "vpn.example.com", Port: 8443, IPOnly: true,
				Verdict: reach.OK, Since: &now, LastResult: reach.OK, ChinaReached: 5, ChinaAnswered: 5, ControlReached: 3, ControlAnswered: 3},
		},
	}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("status = %+v\nwant     %+v", st, want)
	}
	// One ping plus the REALITY port: the UDP line and the disabled line add no measurement.
	wantCalls := []reach.PingRequest{{Host: "vpn.example.com"}, {Host: "vpn.example.com", Port: 443, Reuse: "anchor"}}
	if !reflect.DeepEqual(f.pinger.calls, wantCalls) {
		t.Errorf("measurements = %+v, want %+v", f.pinger.calls, wantCalls)
	}

	expectError(t, f.do("POST", "/api/reach/check", nil, withCookie(f.c)), http.StatusTooManyRequests, codeRateLimited, "")
	if n := f.pinger.count(); n != 2 {
		t.Errorf("a second click within a minute spent %d more measurements", n-2)
	}
	f.advance(61 * time.Second)
	expectStatus(t, f.do("POST", "/api/reach/check", nil, withCookie(f.c)), http.StatusOK)

	audit := decodeBody[struct{ Entries []auditDTO }](t, f.do("GET", "/api/audit?limit=2", nil, withCookie(f.c)))
	if e := audit.Entries[0]; e.Action != "reach.check" || e.Target != "reach" || e.Detail != "2 lines" {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestManualReachCheckStopsOnClose(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	hang := make(chan struct{}, 1)
	f.pinger.mu.Lock()
	f.pinger.hang = hang
	f.pinger.mu.Unlock()

	done := make(chan int, 1)
	go func() { done <- f.do("POST", "/api/reach/check", nil, withCookie(f.c)).Code }()
	<-hang
	select {
	case code := <-done:
		t.Fatalf("check returned %d while its measurement was still running", code)
	case <-time.After(50 * time.Millisecond):
	}
	f.srv.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a manual check kept running after the server was closed")
	}
}

func TestReachLoopConfirmsThenMailsOncePerTransition(t *testing.T) {
	f := newReachFixture(t)
	sink := newMailSink(t)
	f.configure(true, sink.smtp())

	type want struct {
		verdict, last reach.Verdict
		mails         int
	}
	for i, step := range []struct {
		answer func(reach.PingRequest) ([]reach.ProbeResult, error)
		want   want
	}{
		{allFine, want{reach.OK, reach.OK, 0}},
		{port443Shut, want{reach.OK, reach.PortBlocked, 0}},
		{port443Shut, want{reach.PortBlocked, reach.PortBlocked, 1}},
		{port443Shut, want{reach.PortBlocked, reach.PortBlocked, 1}},
		{allFine, want{reach.PortBlocked, reach.OK, 1}},
		{allFine, want{reach.OK, reach.OK, 2}},
		{allFine, want{reach.OK, reach.OK, 2}},
	} {
		f.pinger.set(step.answer)
		if !f.tick() {
			t.Fatalf("round %d: loop did not run although a check was due", i)
		}
		if f.tick() {
			t.Fatalf("round %d: loop ran twice within one interval", i)
		}
		got := f.status().Targets[0]
		if got.Verdict != step.want.verdict || got.LastResult != step.want.last || sink.count() != step.want.mails {
			t.Fatalf("round %d: verdict %q last %q mails %d, want %q %q %d",
				i, got.Verdict, got.LastResult, sink.count(), step.want.verdict, step.want.last, step.want.mails)
		}
		f.advance(29 * time.Minute)
		if f.tick() {
			t.Fatalf("round %d: loop ran a minute before the interval was over", i)
		}
		f.advance(time.Minute)
	}

	if !reflect.DeepEqual(sink.rcpt[0], []string{"me@example.org"}) {
		t.Errorf("alert went to %q", sink.rcpt[0])
	}
	subjects := []string{
		"Mintyx：有线路从中国大陆连不上了 / lines unreachable from mainland China",
		"Mintyx：线路已恢复 / lines reachable again",
	}
	for i, raw := range sink.got {
		m, err := mail.ReadMessage(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("mail %d: %v", i, err)
		}
		subject, _ := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
		body, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, m.Body))
		if subject != subjects[i] || !strings.Contains(string(body), "tokyo (vpn.example.com:443)") {
			t.Errorf("mail %d: subject %q, body %q", i, subject, body)
		}
	}
}

func TestReachRateLimitIsUnknownNotBlocked(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	f.pinger.set(func(reach.PingRequest) ([]reach.ProbeResult, error) {
		return nil, &reach.RateLimitError{Reset: 50 * time.Minute}
	})
	if !f.tick() {
		t.Fatal("first round did not run")
	}
	st := f.status()
	retry := f.clock.Add(50 * time.Minute)
	if st.LastError != reachErrRateLimited || st.Targets[0].Verdict != reach.Unknown || st.Targets[0].LastResult != reach.Unknown {
		t.Errorf("status = %+v, want rate_limited with an unknown verdict", st)
	}
	if st.NextCheckAt == nil || !st.NextCheckAt.Equal(retry) {
		t.Errorf("nextCheckAt = %v, want the rate-limit reset %s rather than the 30 minute interval", st.NextCheckAt, retry)
	}
	f.advance(49 * time.Minute)
	if f.tick() {
		t.Error("loop retried before the rate limit reset")
	}
	f.advance(time.Minute)
	f.pinger.set(allFine)
	if !f.tick() {
		t.Fatal("loop did not resume after the reset")
	}
	if st := f.status(); st.LastError != "" || st.Targets[0].Verdict != reach.OK {
		t.Errorf("after recovery: %+v", st)
	}
}

func TestReachAlertSurvivesMailFailure(t *testing.T) {
	f := newReachFixture(t)
	sink := newMailSink(t)
	dead := sink.smtp()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead["port"] = closed.Addr().(*net.TCPAddr).Port
	_ = closed.Close()
	f.configure(true, dead)
	body := map[string]any{"enabled": true, "intervalMinutes": 30, "confirmRounds": 1, "smtp": dead}
	expectStatus(t, f.do("PUT", "/api/reach/config", body, withCookie(f.c)), http.StatusOK)

	f.pinger.set(port443Shut)
	f.tick()
	if st := f.status(); st.Targets[0].Verdict != reach.PortBlocked || !strings.Contains(st.AlertError, "connection refused") {
		t.Fatalf("status = %+v, want port_blocked and the mail error", st)
	}

	body["smtp"] = sink.smtp()
	expectStatus(t, f.do("PUT", "/api/reach/config", body, withCookie(f.c)), http.StatusOK)
	f.advance(30 * time.Minute)
	f.tick()
	if sink.count() != 1 {
		t.Fatalf("%d mails after the SMTP server came back, want the one held alert", sink.count())
	}
	if st := f.status(); st.AlertError != "" {
		t.Errorf("alertError = %q after the mail went out", st.AlertError)
	}
	f.advance(30 * time.Minute)
	f.tick()
	if sink.count() != 1 {
		t.Errorf("the same alert was mailed %d times", sink.count())
	}
}

func TestReachStateSurvivesRestart(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	f.pinger.set(port443Shut)
	f.tick()
	f.advance(30 * time.Minute)

	// A second server on the same database stands in for the panel after a restart.
	again, err := New(Config{Store: f.st, Engine: f.eng, Keys: &fakeKeys{}, Reach: f.pinger})
	if err != nil {
		t.Fatal(err)
	}
	again.now = func() time.Time { return *f.clock }
	if ran, err := again.NewReachRunner(time.Minute).Tick(t.Context()); err != nil || !ran {
		t.Fatalf("tick after restart: ran %v, err %v", ran, err)
	}
	st, err := again.reachStatus(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Targets[0].Verdict; got != reach.PortBlocked {
		t.Errorf("verdict = %q, want port_blocked: the first bad round was forgotten across the restart", got)
	}
}

func TestReachRoundDoesNotHoldTheStoreLock(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	saved := make(chan int, 1)
	f.pinger.set(func(reach.PingRequest) ([]reach.ProbeResult, error) {
		// An admin request arriving mid-measurement needs s.mu; it must not have to wait.
		w := f.do("PUT", "/api/settings", map[string]string{"publicHost": "vpn.example.com"}, withCookie(f.c))
		select {
		case saved <- w.Code:
		default:
		}
		return seen(5, 3), nil
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.do("POST", "/api/reach/check", nil, withCookie(f.c))
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock: the round held s.mu across its network call")
	}
	if code := <-saved; code != http.StatusOK {
		t.Errorf("settings save during a round = %d", code)
	}
}

func TestReachTestEmail(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	sink := newMailSink(t)

	w := f.do("POST", "/api/reach/test-email", sink.smtp(), withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if got := strings.TrimSpace(w.Body.String()); got != `{"error":"","sent":true}` {
		t.Errorf("response = %s", got)
	}
	if sink.count() != 1 || !reflect.DeepEqual(sink.rcpt[0], []string{"me@example.org"}) {
		t.Fatalf("sink got %d mails to %q", sink.count(), sink.rcpt)
	}

	bad := sink.smtp()
	bad["security"] = "starttls"
	w = f.do("POST", "/api/reach/test-email", bad, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	var res struct {
		Sent  bool
		Error string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Sent || res.Error != "notify: server does not offer STARTTLS; refusing to send the password unencrypted" {
		t.Errorf("failed test = %+v, want the SMTP error text", res)
	}

	missing := sink.smtp()
	missing["host"] = ""
	expectError(t, f.do("POST", "/api/reach/test-email", missing, withCookie(c)), http.StatusBadRequest, codeInvalid, "smtp.host")

	audit := decodeBody[struct{ Entries []auditDTO }](t, f.do("GET", "/api/audit?limit=2", nil, withCookie(c)))
	var got []string
	for _, e := range audit.Entries {
		got = append(got, fmt.Sprintf("%s %s %s", e.Action, e.Target, e.Detail))
	}
	if want := []string{"reach.test_email 127.0.0.1 failed", "reach.test_email 127.0.0.1 sent"}; !reflect.DeepEqual(got, want) {
		t.Errorf("audit = %q, want %q", got, want)
	}
}

func TestReachTestEmailFallsBackToStoredPassword(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	sink := newMailSink(t)
	smtp := sink.smtp()
	smtp["username"], smtp["password"] = "panel", "stored-pw-123"
	body := map[string]any{"enabled": false, "intervalMinutes": 30, "confirmRounds": 2, "smtp": smtp}
	expectStatus(t, f.do("PUT", "/api/reach/config", body, withCookie(c)), http.StatusOK)

	// The form sends no password for the saved server; the attempt must still try to sign in.
	smtp["password"] = ""
	w := f.do("POST", "/api/reach/test-email", smtp, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	// The sink offers no AUTH, which is how we see that a sign-in was attempted at all.
	if !strings.Contains(w.Body.String(), "no supported sign-in method") {
		t.Errorf("response = %s, want the sign-in attempt to reach the server", w.Body)
	}
	if strings.Contains(w.Body.String(), "stored-pw-123") {
		t.Errorf("response echoes the stored password: %s", w.Body)
	}
}

func TestReachRunnerStartStop(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	probed := make(chan struct{}, 1)
	f.pinger.set(func(reach.PingRequest) ([]reach.ProbeResult, error) {
		select {
		case probed <- struct{}{}:
		default:
		}
		return seen(5, 3), nil
	})
	r := f.srv.NewReachRunner(time.Millisecond)
	r.Start(t.Context())
	select {
	case <-probed:
	case <-time.After(5 * time.Second):
		t.Fatal("runner never started a due round")
	}
	r.Stop()
	r.Stop()
}

func TestReachStatusDropsVerdictWhenLineMoves(t *testing.T) {
	f := newReachFixture(t)
	f.configure(true, nil)
	expectStatus(t, f.do("POST", "/api/reach/check", nil, withCookie(f.c)), http.StatusOK)
	if got := f.status().Targets[0]; got.Verdict != reach.OK {
		t.Fatalf("setup: verdict %q", got.Verdict)
	}
	moved := realityLine("tokyo", 443)
	moved["host"] = "other.example.com"
	expectStatus(t, f.do("PUT", "/api/lines/1", moved, withCookie(f.c)), http.StatusOK)
	got := f.status().Targets[0]
	want := reachTargetDTO{LineID: 1, LineName: "tokyo", Protocol: "vless-reality", Host: "other.example.com", Port: 443, Verdict: reach.Unknown}
	if got != want {
		t.Errorf("after moving the line to another address: %+v\nwant an untested line: %+v", got, want)
	}
}
