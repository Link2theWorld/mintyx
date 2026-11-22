// Package attack recognises hostile connection attempts in the server's sshd and Xray logs
// and tallies them per source address.
package attack

import (
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// Kind is what a source was seen doing. The values are stored and sent to the UI.
type Kind string

const (
	// SSHLogin is a login attempt on an account that exists, root included.
	SSHLogin Kind = "ssh_login"
	// SSHInvalidUser is a login attempt with a user name the server does not have.
	SSHInvalidUser Kind = "ssh_invalid_user"
	// SSHScan is a connection to sshd that never got as far as naming a user.
	SSHScan Kind = "ssh_scan"
	// LineProbe is a connection to a line's port that did not speak the line's protocol.
	LineProbe Kind = "line_probe"
	// LineBadAuth spoke the protocol with credentials no enabled visitor has.
	LineBadAuth Kind = "line_bad_auth"
)

var Kinds = []Kind{SSHLogin, SSHInvalidUser, SSHScan, LineProbe, LineBadAuth}

func (k Kind) Valid() bool {
	for _, known := range Kinds {
		if k == known {
			return true
		}
	}
	return false
}

// A user name is whatever the client sent, so it may itself contain " from 1.2.3.4 port 5".
// sshd writes the real peer last, hence the greedy name and the anchored tail.
var sshPatterns = []struct {
	re       *regexp.Regexp
	kind     Kind
	ip, port int
	// invalid is the group that is non-empty when the user does not exist; 0 when the pattern has none.
	invalid int
}{
	{regexp.MustCompile(`^Failed \S+ for (invalid user )?.* from (\S+) port (\d+)(?: ssh2)?$`), SSHLogin, 2, 3, 1},
	{regexp.MustCompile(`^Invalid user .* from (\S+) port (\d+)$`), SSHInvalidUser, 1, 2, 0},
	{regexp.MustCompile(`^(?:Connection (?:closed|reset) by|Disconnected from) (?:authenticating|(invalid)) user .* (\S+) port (\d+) \[preauth\]$`), SSHLogin, 2, 3, 1},
	{regexp.MustCompile(`^error: maximum authentication attempts exceeded for (invalid user )?.* from (\S+) port (\d+) ssh2 \[preauth\]$`), SSHLogin, 2, 3, 1},
	{regexp.MustCompile(`^(?:Connection (?:closed|reset) by|Disconnected from) (\S+) port (\d+) \[preauth\]$`), SSHScan, 1, 2, 0},
	{regexp.MustCompile(`^Received disconnect from (\S+) port (\d+):.*\[preauth\]$`), SSHScan, 1, 2, 0},
	{regexp.MustCompile(`^banner exchange: Connection from (\S+) port (\d+): `), SSHScan, 1, 2, 0},
	{regexp.MustCompile(`^Unable to negotiate with (\S+) port (\d+): `), SSHScan, 1, 2, 0},
	{regexp.MustCompile(`^Did not receive identification string from (\S+) port (\d+)`), SSHScan, 1, 2, 0},
	{regexp.MustCompile(`^Timeout before authentication for connection from (\S+) to `), SSHScan, 1, 0, 0},
	{regexp.MustCompile(`^Timeout before authentication for (\S+) port (\d+)`), SSHScan, 1, 2, 0},
}

// Only a key login vouches for an address: a password that was accepted may be one that was guessed.
var sshAccepted = regexp.MustCompile(`^Accepted publickey for .* from (\S+) port \d+ ssh2`)

var (
	xrayReality  = regexp.MustCompile(`REALITY: processed invalid connection from (\S+): `)
	xrayRejected = regexp.MustCompile(` from (?:tcp:|udp:)?(\S+) rejected +(.*)$`)
)

// sourceAddr accepts only addresses a report could be about: nothing private, loopback or link-local.
func sourceAddr(s string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	ip = ip.Unmap().WithZone("")
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return netip.Addr{}, false
	}
	return ip, true
}

type event struct {
	ip      netip.Addr
	port    string
	kind    Kind
	trusted bool
	line    string
}

func parseSSH(msg string) (event, bool) {
	if m := sshAccepted.FindStringSubmatch(msg); m != nil {
		ip, ok := sourceAddr(m[1])
		return event{ip: ip, trusted: true}, ok
	}
	for _, p := range sshPatterns {
		m := p.re.FindStringSubmatch(msg)
		if m == nil {
			continue
		}
		ip, ok := sourceAddr(m[p.ip])
		if !ok {
			return event{}, false
		}
		ev := event{ip: ip, kind: p.kind, line: msg}
		if p.port > 0 {
			ev.port = m[p.port]
		}
		if p.invalid > 0 && m[p.invalid] != "" {
			ev.kind = SSHInvalidUser
		}
		return ev, true
	}
	return event{}, false
}

func parseXray(line string) (event, bool) {
	var addr, text string
	kind := LineProbe
	if m := xrayReality.FindStringSubmatchIndex(line); m != nil {
		addr, text = line[m[2]:m[3]], line[m[0]:]
	} else if m := xrayRejected.FindStringSubmatch(line); m != nil {
		addr, text = m[1], "rejected: "+m[2]
		// The credential that was tried may be a former visitor's; it has no place in a report.
		if i := strings.Index(text, "user id"); i >= 0 {
			text = text[:i+len("user id")]
		}
		if strings.Contains(m[2], "user") {
			kind = LineBadAuth
		}
	} else {
		return event{}, false
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return event{}, false
	}
	ip, ok := sourceAddr(ap.Addr().String())
	if !ok {
		return event{}, false
	}
	return event{ip: ip, kind: kind, line: text}, true
}

const (
	maxPending    = 20000
	maxConns      = 4096
	maxSampleLen  = 300
	MaxSamples    = 3
	dayLayout     = "2006-01-02"
	sshConnPrefix = "ssh "
)

type hitKey struct {
	ip, day string
	kind    Kind
}

// Collector turns log lines into per-source tallies and holds them until Drain.
// sshd writes several lines about one connection; only the first that classifies it counts.
type Collector struct {
	mu      sync.Mutex
	hits    map[hitKey]*model.AttackHit
	trusted map[string]bool
	conns   map[string]bool
	connLog []string
	next    int
}

func NewCollector() *Collector {
	return &Collector{hits: map[hitKey]*model.AttackHit{}, trusted: map[string]bool{}, conns: map[string]bool{}}
}

// SSH takes one sshd log message, without the syslog prefix.
func (c *Collector) SSH(at time.Time, msg string) {
	if ev, ok := parseSSH(msg); ok {
		c.add(ev, sshConnPrefix, at)
	}
}

// Xray takes one line of Xray's output.
func (c *Collector) Xray(at time.Time, line string) {
	if ev, ok := parseXray(line); ok {
		c.add(ev, "", at)
	}
}

func (c *Collector) add(ev event, connPrefix string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ip := ev.ip.String()
	if ev.trusted {
		c.trusted[ip] = true
		return
	}
	if ev.port != "" {
		conn := connPrefix + ip + " " + ev.port
		if c.conns[conn] {
			return
		}
		c.rememberConn(conn)
	}
	at = at.UTC()
	key := hitKey{ip: ip, day: at.Format(dayLayout), kind: ev.kind}
	h := c.hits[key]
	if h == nil {
		if len(c.hits) >= maxPending {
			return
		}
		h = &model.AttackHit{IP: ip, Kind: string(ev.kind), Day: key.day, First: at, Last: at}
		c.hits[key] = h
	}
	h.Count++
	if at.Before(h.First) {
		h.First = at
	}
	if at.After(h.Last) {
		h.Last = at
	}
	line := strings.ToValidUTF8(ev.line, "?")
	if len(line) > maxSampleLen {
		line = strings.ToValidUTF8(line[:maxSampleLen], "") + "…"
	}
	h.Samples = append(h.Samples, model.AttackSample{At: at, Line: line})
	if len(h.Samples) > MaxSamples {
		h.Samples = h.Samples[len(h.Samples)-MaxSamples:]
	}
}

func (c *Collector) rememberConn(conn string) {
	if len(c.connLog) < maxConns {
		c.connLog = append(c.connLog, conn)
	} else {
		delete(c.conns, c.connLog[c.next])
		c.connLog[c.next] = conn
		c.next = (c.next + 1) % maxConns
	}
	c.conns[conn] = true
}

// Drain returns everything collected since the last call: the tallies, and the addresses that
// logged in with a key and so are the owner's own.
func (c *Collector) Drain() (hits []model.AttackHit, trusted []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range c.hits {
		hits = append(hits, *h)
	}
	for ip := range c.trusted {
		trusted = append(trusted, ip)
	}
	c.hits, c.trusted = map[hitKey]*model.AttackHit{}, map[string]bool{}
	return hits, trusted
}
