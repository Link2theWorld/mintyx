package share

import (
	"fmt"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// RemoteError names the part of another server's share link that a subscription cannot carry,
// in the terms exitlink uses: "scheme", "host", or a query key such as "type" or "pcs".
type RemoteError struct{ Part, Problem string }

func (e *RemoteError) Error() string { return "link " + e.Part + ": " + e.Problem }

func refuse(part, format string, args ...any) (endpoint, error) {
	return endpoint{}, &RemoteError{Part: part, Problem: fmt.Sprintf(format, args...)}
}

// CheckRemote reports whether a parsed share link is a line every subscription format can list
// in full: VLESS over raw TCP with REALITY, VLESS over XHTTP with TLS, or Hysteria2, the three
// kinds of line a Mintyx panel makes. Anything a format would have to drop, such as a
// certificate pin, is refused rather than silently left out. Every error is a *RemoteError.
func CheckRemote(p model.ExitParams) error {
	_, err := remoteEndpoint(model.RemoteLine{Params: p})
	return err
}

func remoteEndpoint(r model.RemoteLine) (endpoint, error) {
	p := r.Params
	ep := endpoint{host: p.Host, port: p.Port, secret: p.Secret}
	line := model.Line{ID: r.ID, Name: r.Name}
	switch p.Protocol {
	case model.ExitVLESS:
		if p.Encryption != "" && p.Encryption != vlessEncNone {
			return refuse("encryption", "VLESS Encryption cannot go into a subscription; use encryption=none")
		}
		fp := ""
		switch p.Transport.Network {
		case model.ExitRaw, "":
			x := p.Reality
			if x == nil {
				return refuse("security", "a vless line over raw TCP must use reality here")
			}
			if x.MLDSA65Verify != "" {
				return refuse("pqv", "mihomo cannot verify an ML-DSA-65 key; leave pqv out")
			}
			switch p.Flow {
			case "", visionFlow:
			default:
				return refuse("flow", "%s cannot go into a mihomo subscription; use %s", p.Flow, visionFlow)
			}
			line.Protocol = model.VLESSReality
			ep.reality = &model.RealityParams{PublicKey: x.PublicKey, ShortID: x.ShortID, ServerName: x.ServerName}
			ep.serverName, ep.flow, fp = x.ServerName, p.Flow, x.Fingerprint
		case model.ExitXHTTP:
			t := p.TLS
			if t == nil {
				return refuse("security", "a vless line over xhttp must use tls here")
			}
			if t.PinSHA256 != "" {
				return refuse("pcs", "a certificate pin cannot go into every subscription format; leave pcs out")
			}
			if t.VerifyName != "" {
				return refuse("vcn", "cannot go into every subscription format; leave vcn out")
			}
			line.Protocol = model.VLESSXHTTP
			ep.tls, ep.serverName, fp = true, t.ServerName, t.Fingerprint
			if ep.serverName == "" {
				ep.serverName = p.Transport.Host
			}
			ep.xhttpHost, ep.xhttpPath, ep.xhttpMode = p.Transport.Host, p.Transport.Path, p.Transport.Mode
			if ep.xhttpPath == "" {
				ep.xhttpPath = "/"
			}
			if ep.xhttpMode == "auto" {
				// The default everywhere, so it is left out like the panel's own lines leave it out.
				ep.xhttpMode = ""
			}
		default:
			return refuse("type", "%s is not supported here; use raw with reality or xhttp with tls", p.Transport.Network)
		}
		switch fp {
		case "":
			ep.fp = defaultFP
		case "randomized":
			// mihomo's name for the same thing.
			ep.fp = "random"
		default:
			ep.fp = fp
		}
	case model.ExitHysteria2:
		ep.tls = true
		if t := p.TLS; t != nil {
			if t.PinSHA256 != "" {
				return refuse("pinSHA256", "a certificate pin cannot go into every subscription format; leave pinSHA256 out")
			}
			ep.serverName = t.ServerName
		}
		line.Protocol = model.Hysteria2
		ep.obfsPass = p.ObfsPassword
	default:
		return refuse("scheme", "%s lines cannot join a subscription; use a vless (reality or xhttp) or hysteria2 link", p.Protocol)
	}
	if p.Secret == "" {
		return refuse("userinfo", "the credential is missing")
	}
	if p.Protocol == model.ExitVLESS && !vlessUUID(p.Secret) {
		return refuse("userinfo", "subscription clients need a UUID for VLESS; Xray-only string ids cannot join one")
	}
	if p.Port < 1 || p.Port > 65535 {
		return refuse("port", "%d must be a number from 1 to 65535", p.Port)
	}
	host, err := cleanHost(p.Host)
	if err != nil {
		return refuse("host", "%v", err)
	}
	ep.host, ep.line = host, line
	return ep, nil
}

// vlessUUID reports whether secret is in the 8-4-4-4-12 UUID form subscription clients expect.
// exitlink.Parse canonicalises bare hex and mixed case before the secret reaches this package.
func vlessUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' {
				continue
			}
			return false
		}
	}
	return true
}

// RemoteLink is the share URI a subscription lists for a remote line, rebuilt from its parameters
// so it carries the name the admin gave it.
func RemoteLink(r model.RemoteLine) (string, error) {
	ep, err := remoteEndpoint(r)
	if err != nil {
		return "", err
	}
	return ep.uri(), nil
}
