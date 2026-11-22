package attack

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

var t0 = time.Date(2026, 11, 22, 6, 24, 39, 0, time.UTC)

func drainByKind(c *Collector) map[string]model.AttackHit {
	hits, _ := c.Drain()
	out := map[string]model.AttackHit{}
	for _, h := range hits {
		out[h.IP+" "+h.Kind] = h
	}
	return out
}

// The messages are the shapes sshd on Debian 13 (OpenSSH 10) writes, with documentation addresses.
func TestSSHMessagesAreClassified(t *testing.T) {
	cases := []struct {
		msg  string
		kind Kind // "" when the line must be ignored
	}{
		{"Invalid user admin from 203.0.113.5 port 40001", SSHInvalidUser},
		{"Failed password for invalid user oracle from 203.0.113.5 port 40002 ssh2", SSHInvalidUser},
		{"Failed password for root from 203.0.113.5 port 40003 ssh2", SSHLogin},
		{"Connection closed by authenticating user root 203.0.113.5 port 40004 [preauth]", SSHLogin},
		{"Connection reset by authenticating user root 203.0.113.5 port 40005 [preauth]", SSHLogin},
		{"Connection closed by invalid user test 203.0.113.5 port 40006 [preauth]", SSHInvalidUser},
		{"error: maximum authentication attempts exceeded for root from 203.0.113.5 port 40007 ssh2 [preauth]", SSHLogin},
		{"Connection closed by 203.0.113.5 port 40008 [preauth]", SSHScan},
		{"banner exchange: Connection from 203.0.113.5 port 40009: invalid format", SSHScan},
		{"Unable to negotiate with 203.0.113.5 port 40010: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1 [preauth]", SSHScan},
		{"Timeout before authentication for connection from 203.0.113.5 to 10.0.0.4, pid = 12341", SSHScan},
		{"Received disconnect from 2001:db8::1 port 40011:11: Bye Bye [preauth]", SSHScan},

		{"Connection closed by 203.0.113.5 port 40012", ""}, // an ordinary session ending
		{"Disconnected from user ops 203.0.113.5 port 40013", ""},
		{"pam_unix(sshd:session): session opened for user ops(uid=1000) by ops(uid=0)", ""},
		{"Invalid user admin from 10.0.0.7 port 40014", ""}, // a private address is nobody to report
		{"Invalid user admin from 127.0.0.1 port 40015", ""},
		{"Invalid user admin from not-an-ip port 40016", ""},
	}
	for _, tc := range cases {
		c := NewCollector()
		c.SSH(t0, tc.msg)
		hits, _ := c.Drain()
		switch {
		case tc.kind == "" && len(hits) != 0:
			t.Errorf("%q: recorded %+v, want nothing", tc.msg, hits)
		case tc.kind != "" && (len(hits) != 1 || hits[0].Kind != string(tc.kind)):
			t.Errorf("%q: recorded %+v, want one %s", tc.msg, hits, tc.kind)
		}
	}
}

// A user name is attacker-controlled text; it must not be able to blame another address.
func TestSSHUserNameCannotSpoofTheSource(t *testing.T) {
	c := NewCollector()
	c.SSH(t0, "Invalid user x from 198.51.100.99 port 1 from 203.0.113.5 port 40001")
	c.SSH(t0, "Failed password for invalid user root from 198.51.100.99 port 2 from 203.0.113.5 port 40002 ssh2")
	for key := range drainByKind(c) {
		if !strings.HasPrefix(key, "203.0.113.5 ") {
			t.Errorf("recorded %q; the real peer is 203.0.113.5", key)
		}
	}
}

func TestOneConnectionCountsOnce(t *testing.T) {
	c := NewCollector()
	// What sshd writes for a single connection that guesses twice.
	c.SSH(t0, "Invalid user admin from 203.0.113.5 port 40001")
	c.SSH(t0.Add(time.Second), "Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2")
	c.SSH(t0.Add(2*time.Second), "Failed password for invalid user admin from 203.0.113.5 port 40001 ssh2")
	c.SSH(t0.Add(3*time.Second), "Connection closed by invalid user admin 203.0.113.5 port 40001 [preauth]")
	// A second connection from the same address.
	c.SSH(t0.Add(4*time.Second), "Invalid user test from 203.0.113.5 port 40002")

	got := drainByKind(c)
	h, ok := got["203.0.113.5 ssh_invalid_user"]
	if len(got) != 1 || !ok || h.Count != 2 {
		t.Fatalf("got %+v, want ssh_invalid_user counted twice", got)
	}
	if !h.First.Equal(t0) || !h.Last.Equal(t0.Add(4*time.Second)) || h.Day != "2026-11-22" {
		t.Errorf("first %v last %v day %q", h.First, h.Last, h.Day)
	}
	if len(h.Samples) != 2 || h.Samples[1].Line != "Invalid user test from 203.0.113.5 port 40002" {
		t.Errorf("samples = %+v", h.Samples)
	}
	if hits, _ := c.Drain(); len(hits) != 0 {
		t.Errorf("second Drain returned %+v", hits)
	}
}

func TestKeyLoginMarksAddressTrustedButPasswordLoginDoesNot(t *testing.T) {
	c := NewCollector()
	c.SSH(t0, "Accepted publickey for ops from 198.51.100.7 port 50000 ssh2: ED25519 SHA256:abc")
	c.SSH(t0, "Accepted password for root from 203.0.113.5 port 50001 ssh2")
	hits, trusted := c.Drain()
	if len(hits) != 0 || len(trusted) != 1 || trusted[0] != "198.51.100.7" {
		t.Fatalf("hits %+v trusted %v", hits, trusted)
	}
}

// The lines are what Xray 26.11.9 prints, taken from a local run.
func TestXrayLines(t *testing.T) {
	c := NewCollector()
	c.Xray(t0, "2026/11/21 22:25:25.568501 [Info] transport/internet/tcp: REALITY: processed invalid connection from 203.0.113.5:64998: failed to read client hello")
	c.Xray(t0, "2026/11/21 22:25:26.238597 [Info] transport/internet/tcp: REALITY: processed invalid connection from [2001:db8::2]:64987: server name mismatch: ")
	c.Xray(t0, "2026/11/21 22:25:17.451132 from 203.0.113.6:64860 rejected  proxy/vless/encoding: invalid request user id: 22222222-2222-4222-8222-222222222222")
	c.Xray(t0, "2026/11/21 22:25:31.080746 [Info] [2253650119] app/proxyman/inbound: connection ends > proxy/vless/inbound: invalid request from 203.0.113.6:65003 > proxy/vless/encoding: invalid request user id: 22222222-2222-4222-8222-222222222222")
	c.Xray(t0, "2026/11/21 22:25:40.000000 from 203.0.113.7:1234 accepted tcp:example.com:443 [line-1 >> direct] email: c1")
	c.Xray(t0, "2026/11/21 22:25:41.000000 from 127.0.0.1:1234 rejected  proxy/vless/encoding: invalid request user id: 2222")

	got := drainByKind(c)
	if len(got) != 3 {
		t.Fatalf("got %+v, want three sources", got)
	}
	for _, key := range []string{"203.0.113.5 line_probe", "2001:db8::2 line_probe", "203.0.113.6 line_bad_auth"} {
		if got[key].Count != 1 {
			t.Errorf("%s: count %d, want 1", key, got[key].Count)
		}
	}
	if line := got["203.0.113.6 line_bad_auth"].Samples[0].Line; strings.Contains(line, "2222") {
		t.Errorf("sample keeps the credential that was tried: %q", line)
	}
	if line := got["203.0.113.5 line_probe"].Samples[0].Line; !strings.HasPrefix(line, "REALITY: processed invalid connection") {
		t.Errorf("sample = %q", line)
	}
}

func TestSamplesAreBounded(t *testing.T) {
	c := NewCollector()
	for i := range 10 {
		c.SSH(t0.Add(time.Duration(i)*time.Second), "Invalid user "+strings.Repeat("a", 1000)+" from 203.0.113.5 port "+string(rune('0'+i)))
	}
	h := drainByKind(c)["203.0.113.5 ssh_invalid_user"]
	if h.Count != 10 || len(h.Samples) != MaxSamples {
		t.Fatalf("count %d, %d samples", h.Count, len(h.Samples))
	}
	if n := len(h.Samples[0].Line); n > maxSampleLen+len("…") {
		t.Errorf("sample is %d bytes", n)
	}
}

func TestParseJournal(t *testing.T) {
	in := `{"__CURSOR":"s=a;i=1","__REALTIME_TIMESTAMP":"1795328679940165","MESSAGE":"Invalid user admin from 203.0.113.5 port 40001"}
not json
{"__CURSOR":"s=a;i=2","__REALTIME_TIMESTAMP":"1795328680000000","MESSAGE":[1,2,3]}
{"__CURSOR":"s=a;i=3","__REALTIME_TIMESTAMP":"1795328681000000","MESSAGE":"Connection closed by 203.0.113.5 port 40002 [preauth]"}
`
	var got []string
	cursor, err := parseJournal(bytes.NewBufferString(in), func(at time.Time, msg string) {
		got = append(got, at.Format(time.RFC3339)+" "+msg)
	})
	if err != nil || cursor != "s=a;i=3" {
		t.Fatalf("cursor %q err %v", cursor, err)
	}
	want := []string{
		"2026-11-22T06:24:39Z Invalid user admin from 203.0.113.5 port 40001",
		"2026-11-22T06:24:41Z Connection closed by 203.0.113.5 port 40002 [preauth]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q", got)
	}
}

func TestReport(t *testing.T) {
	a := model.Attacker{
		IP: "203.0.113.5", FirstAt: t0, LastAt: t0.Add(time.Hour), Hits: 12,
		Whois: model.Whois{Network: "Example Hosting Ltd", NetRange: "203.0.113.0/24", AbuseEmail: "abuse@example.net"},
		Kinds: []model.AttackerKind{
			{Kind: string(SSHLogin), Hits: 10, FirstAt: t0, LastAt: t0.Add(time.Hour),
				Samples: []model.AttackSample{{At: t0, Line: "Failed password for root from 203.0.113.5 port 40003 ssh2"}}},
			{Kind: string(SSHScan), Hits: 2, FirstAt: t0, LastAt: t0},
		},
	}
	subject, body := Report(a, "198.51.100.20")
	if subject != "Abuse report: SSH brute-force attempts from 203.0.113.5" {
		t.Errorf("subject = %q", subject)
	}
	for _, want := range []string{
		"registered to your network (Example Hosting Ltd)",
		"Source IP:   203.0.113.5", "Network:     203.0.113.0/24", "Destination: 198.51.100.20",
		"First seen:  2026-11-22 06:24:39 UTC", "Last seen:   2026-11-22 07:24:39 UTC",
		"- SSH login attempts (password guessing): 10, between 2026-11-22 06:24:39 and 2026-11-22 07:24:39",
		"- SSH port scanning: 2,",
		"2026-11-22 06:24:39 UTC  Failed password for root from 203.0.113.5 port 40003 ssh2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}

	subject, body = Report(model.Attacker{IP: "2001:db8::2", Kinds: []model.AttackerKind{{Kind: string(LineProbe), Hits: 1}}}, "")
	if subject != "Abuse report: unsolicited connections probing a TLS service from 2001:db8::2" {
		t.Errorf("subject = %q", subject)
	}
	if !strings.Contains(body, "Destination: [your server's IP address]") || !strings.Contains(body, "in your network. ") {
		t.Errorf("body without a known target or network:\n%s", body)
	}
}
