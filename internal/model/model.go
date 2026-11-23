// Package model holds the data types every other package agrees on.
package model

import (
	"fmt"
	"time"
)

type Protocol string

const (
	VLESSReality Protocol = "vless-reality"
	VLESSXHTTP   Protocol = "vless-xhttp"
	Hysteria2    Protocol = "hysteria2"
)

func (p Protocol) Valid() bool {
	switch p {
	case VLESSReality, VLESSXHTTP, Hysteria2:
		return true
	}
	return false
}

// Network is the transport a line of this protocol listens on. Two lines may share a port
// number when one is TCP and the other UDP.
type Network string

const (
	TCP Network = "tcp"
	UDP Network = "udp"
)

// Network says whether a line of protocol p listens on TCP or UDP: Hysteria2 runs over QUIC.
func (p Protocol) Network() Network {
	if p == Hysteria2 {
		return UDP
	}
	return TCP
}

// Line is one listening port on the server. Every enabled client may use every enabled line.
type Line struct {
	ID       int64
	Name     string
	Protocol Protocol
	Port     int
	Enabled  bool
	// Host is the address clients dial; empty means the panel-wide public host.
	Host string

	// Exactly one of these is set, matching Protocol.
	Reality   *RealityParams
	XHTTP     *XHTTPParams
	Hysteria2 *Hysteria2Params

	// ExitID is the first exit this line's traffic leaves through; 0 means straight out of this server.
	ExitID int64

	CreatedAt time.Time
}

type RealityParams struct {
	PrivateKey string
	PublicKey  string
	ShortID    string
	// ServerName is the SNI clients present; Target is the host:port Xray forwards probes to.
	ServerName string
	Target     string
}

type XHTTPSecurity string

const (
	// XHTTPTLS terminates TLS in Xray with CertFile/KeyFile.
	XHTTPTLS XHTTPSecurity = "tls"
	// XHTTPPlain listens without TLS behind a CDN or reverse proxy that terminates it.
	XHTTPPlain XHTTPSecurity = "none"
)

type XHTTPParams struct {
	Path     string
	Domain   string
	Security XHTTPSecurity
	CertFile string
	KeyFile  string
}

type Hysteria2Params struct {
	Domain   string
	CertFile string
	KeyFile  string
	// ObfsPassword enables Salamander obfuscation when non-empty.
	ObfsPassword string
}

type DisabledReason string

const (
	NotDisabled     DisabledReason = ""
	DisabledManual  DisabledReason = "manual"
	DisabledQuota   DisabledReason = "quota"
	DisabledExpired DisabledReason = "expired"
)

// Client is one device or person. Secret is its UUID on VLESS lines and its password on Hysteria2.
type Client struct {
	ID       int64
	Name     string
	Secret   string
	SubToken string

	Disabled DisabledReason
	// QuotaBytes of 0 means unlimited; a nil ExpiresAt means never.
	QuotaBytes int64
	ExpiresAt  *time.Time
	// QuotaResetDay makes the quota monthly: usage returns to zero at midnight on this day of
	// each month (1–31, the month's last day when it has fewer). 0 means usage never resets.
	QuotaResetDay int
	// CycleStart is when the current monthly cycle began; nil when QuotaResetDay is 0.
	CycleStart *time.Time
	UsedUp     int64
	UsedDown   int64

	CreatedAt time.Time
}

func (c Client) Enabled() bool { return c.Disabled == NotDisabled }

// StatsTag is the per-user label Xray counts this client's traffic under, on every line.
func (c Client) StatsTag() string { return fmt.Sprintf("c%d", c.ID) }

type Traffic struct {
	Up   int64
	Down int64
}

type AuditEntry struct {
	ID     int64
	At     time.Time
	Action string
	Target string
	Detail string
	// RemoteIP is the address the admin's request came from.
	RemoteIP string
}

// AttackSample is one log line kept as evidence of what a source did.
type AttackSample struct {
	At   time.Time `json:"at"`
	Line string    `json:"line"`
}

// AttackHit is what one source did, of one kind, on one UTC day, since the collector was last drained.
type AttackHit struct {
	IP      string
	Kind    string
	Day     string
	Count   int64
	First   time.Time
	Last    time.Time
	Samples []AttackSample
}

// Whois is what the address registries say about the network a source is in.
type Whois struct {
	// Country is where the network is registered, which is not always where the machine is:
	// an ISO 3166 code when the registry gave one, otherwise the registry's own wording, or "".
	Country    string
	Network    string
	NetRange   string
	AbuseEmail string
	Registry   string
}

type AttackerKind struct {
	Kind    string
	Hits    int64
	FirstAt time.Time
	LastAt  time.Time
	Samples []AttackSample
}

// Attacker is one source address and everything recorded about it.
type Attacker struct {
	IP      string
	FirstAt time.Time
	LastAt  time.Time
	Hits    int64
	Kinds   []AttackerKind
	// LookedUpAt is nil until the registries were asked; LookupError says why the last try failed.
	LookedUpAt  *time.Time
	LookupError string
	Whois
}

type AttackKindTotal struct {
	Kind    string
	Hits    int64
	Sources int64
}

type AttackOrigin struct {
	Country string
	Sources int64
	Hits    int64
}

type AttackNetwork struct {
	Network    string
	Country    string
	AbuseEmail string
	Sources    int64
	Hits       int64
}

type AttackDay struct {
	Day  string
	Kind string
	Hits int64
}

// AttackSummary aggregates every recorded source that is not the owner's own.
type AttackSummary struct {
	Sources   int64
	Hits      int64
	Kinds     []AttackKindTotal
	Countries []AttackOrigin
	Networks  []AttackNetwork
	Daily     []AttackDay
	// LookedUp and Pending count the sources whose network is known and still to be asked about.
	LookedUp int64
	Pending  int64
}
