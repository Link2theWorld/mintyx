// Package share builds per-client share links and subscription documents for every enabled line.
package share

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Link2theWorld/mintyx/internal/model"
)

const (
	visionFlow    = "xtls-rprx-vision"
	defaultFP     = "chrome"
	cdnTLSPort    = 443
	salamander    = "salamander"
	schemeVLESS   = "vless"
	schemeHy2     = "hysteria2"
	vlessEncNone  = "none"
	xhttpNetwork  = "xhttp"
	realityTCPNet = "tcp"
)

// endpoint is everything a client needs to reach one line, independent of output format.
type endpoint struct {
	line   model.Line
	host   string
	port   int
	secret string

	// tls is true when the client must speak TLS (REALITY has its own field).
	tls        bool
	serverName string
	reality    *model.RealityParams
	xhttpPath  string
	xhttpHost  string
	obfsPass   string
}

// resolve validates a line for one client and works out the address the client dials.
func resolve(line model.Line, c model.Client, defaultHost string) (endpoint, error) {
	if c.Secret == "" {
		return endpoint{}, errors.New("client has no secret")
	}
	if line.Port < 1 || line.Port > 65535 {
		return endpoint{}, fmt.Errorf("port %d out of range", line.Port)
	}
	ep := endpoint{line: line, host: line.Host, port: line.Port, secret: c.Secret}
	if ep.host == "" {
		ep.host = defaultHost
	}

	switch line.Protocol {
	case model.VLESSReality:
		r := line.Reality
		if r == nil {
			return endpoint{}, errors.New("missing reality parameters")
		}
		if r.PublicKey == "" {
			return endpoint{}, errors.New("reality public key is empty")
		}
		if r.ServerName == "" {
			return endpoint{}, errors.New("reality server name is empty")
		}
		ep.reality = r
		ep.serverName = r.ServerName
	case model.VLESSXHTTP:
		x := line.XHTTP
		if x == nil {
			return endpoint{}, errors.New("missing xhttp parameters")
		}
		if x.Domain == "" {
			return endpoint{}, errors.New("xhttp line has no domain")
		}
		ep.tls = true
		ep.serverName = x.Domain
		ep.xhttpHost = x.Domain
		ep.xhttpPath = x.Path
		if ep.xhttpPath == "" {
			ep.xhttpPath = "/"
		}
		switch x.Security {
		case model.XHTTPTLS:
		case model.XHTTPPlain:
			// Xray listens plain behind a CDN; the client still reaches the CDN edge over TLS on 443.
			ep.port = cdnTLSPort
			if line.Host == "" {
				ep.host = x.Domain
			}
		default:
			return endpoint{}, fmt.Errorf("unknown xhttp security %q", x.Security)
		}
	case model.Hysteria2:
		h := line.Hysteria2
		if h == nil {
			return endpoint{}, errors.New("missing hysteria2 parameters")
		}
		ep.tls = true
		ep.serverName = h.Domain
		ep.obfsPass = h.ObfsPassword
	default:
		return endpoint{}, fmt.Errorf("unknown protocol %q", line.Protocol)
	}

	host, err := cleanHost(ep.host)
	if err != nil {
		return endpoint{}, err
	}
	ep.host = host
	return ep, nil
}

func cleanHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(h), "["), "]")
	if h == "" {
		return "", errors.New("no dial host: set the line host or the panel public host")
	}
	if strings.ContainsAny(h, " /?#@[]%\\") {
		return "", fmt.Errorf("invalid host %q", h)
	}
	if strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return "", fmt.Errorf("invalid host %q", h)
	}
	return h, nil
}

// Link returns the share URI for client c on line. defaultHost is used when line.Host is empty.
func Link(line model.Line, c model.Client, defaultHost string) (string, error) {
	ep, err := resolve(line, c, defaultHost)
	if err != nil {
		return "", fmt.Errorf("line %q: %w", line.Name, err)
	}
	return ep.uri(), nil
}

func (ep endpoint) uri() string {
	var q query
	scheme, path := schemeVLESS, ""
	switch ep.line.Protocol {
	case model.VLESSReality:
		q.add("encryption", vlessEncNone)
		q.add("flow", visionFlow)
		q.add("security", "reality")
		q.add("sni", ep.serverName)
		q.add("fp", defaultFP)
		q.add("pbk", ep.reality.PublicKey)
		if ep.reality.ShortID != "" {
			q.add("sid", ep.reality.ShortID)
		}
		q.add("type", realityTCPNet)
	case model.VLESSXHTTP:
		q.add("encryption", vlessEncNone)
		q.add("security", "tls")
		q.add("sni", ep.serverName)
		q.add("fp", defaultFP)
		q.add("type", xhttpNetwork)
		q.add("host", ep.xhttpHost)
		q.add("path", ep.xhttpPath)
	case model.Hysteria2:
		// The Hysteria 2 URI scheme writes "host:port/?params"; keep the slash for strict parsers.
		scheme, path = schemeHy2, "/"
		if ep.obfsPass != "" {
			q.add("obfs", salamander)
			q.add("obfs-password", ep.obfsPass)
		}
		if ep.serverName != "" {
			q.add("sni", ep.serverName)
		}
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(escape(ep.secret))
	b.WriteByte('@')
	b.WriteString(net.JoinHostPort(ep.host, strconv.Itoa(ep.port)))
	b.WriteString(path)
	if s := q.String(); s != "" {
		b.WriteByte('?')
		b.WriteString(s)
	}
	b.WriteByte('#')
	b.WriteString(escape(ep.line.Name))
	return b.String()
}

// query keeps parameters in insertion order so emitted links are stable and diffable.
type query []string

func (q *query) add(k, v string) { *q = append(*q, k+"="+escape(v)) }

func (q query) String() string { return strings.Join(q, "&") }

// escape percent-encodes everything outside RFC 3986 unreserved characters, a strict
// subset of encodeURIComponent, so both Go and JavaScript decoders recover the original.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}
