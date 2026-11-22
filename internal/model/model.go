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
