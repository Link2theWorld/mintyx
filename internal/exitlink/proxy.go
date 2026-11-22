package exitlink

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// ssKeySize is the key size of each Shadowsocks 2022 cipher (SIP022); other ciphers are absent.
var ssKeySize = map[string]int{
	"2022-blake3-aes-128-gcm":       16,
	"2022-blake3-aes-256-gcm":       32,
	"2022-blake3-chacha20-poly1305": 32,
}

// ssMethods are the AEAD ciphers Xray 26 runs; it dropped stream ciphers and "none".
var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true,
	"chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

// parseShadowsocks reads SIP002 ss://userinfo@host:port[/]?plugin=…, where userinfo is plain
// method:password or base64 of it, and the legacy ss://BASE64(method:password@host:port).
func parseShadowsocks(_, rest string, q query) (model.ExitParams, error) {
	var p model.ExitParams
	if q["plugin"] != "" {
		return p, fail("plugin", "Xray does not run SIP003 plugins")
	}
	var (
		s                server
		method, password string
		err              error
	)
	if !strings.Contains(rest, "@") {
		if s, method, password, err = legacySS(rest); err != nil {
			return p, err
		}
	} else {
		if s, err = splitServer(rest); err != nil {
			return p, err
		}
		if m, pw, plain := strings.Cut(s.userinfo, ":"); plain {
			if method, err = decode(partUserinfo, m); err != nil {
				return p, err
			}
			if password, err = decode(partUserinfo, pw); err != nil {
				return p, err
			}
		} else if method, password, err = ssBase64Userinfo(s.userinfo); err != nil {
			return p, err
		}
	}

	method = strings.ToLower(method)
	if !ssMethods[method] {
		if len(method) <= 40 && method != "" && strings.Trim(method, "abcdefghijklmnopqrstuvwxyz0123456789-") == "" {
			return p, fail(partUserinfo, "cipher %s is not supported; use an AEAD or 2022-blake3 cipher such as aes-256-gcm",
				quote(method))
		}
		return p, fail(partUserinfo, "does not start with a supported cipher name")
	}
	if size, is2022 := ssKeySize[method]; is2022 {
		keys := strings.Split(password, ":")
		if method == "2022-blake3-chacha20-poly1305" && len(keys) > 1 {
			return p, fail(partUserinfo, "%s takes a single key", method)
		}
		for _, k := range keys {
			if b, err := base64.StdEncoding.DecodeString(k); err != nil || len(b) != size {
				return p, fail(partUserinfo, "each %s key must be standard base64 of %d bytes", method, size)
			}
		}
	} else if password == "" {
		return p, fail(partUserinfo, "the password is missing")
	}
	if p.Port, err = s.portOr(0); err != nil {
		return p, err
	}
	p.Protocol, p.Host, p.Method, p.Secret = model.ExitShadowsocks, s.host, method, password
	return p, nil
}

// legacySS reads the whole-body form ss://BASE64(method:password@host:port), whose decoded
// userinfo is not percent-encoded.
func legacySS(body string) (s server, method, password string, err error) {
	bad := fail(partUserinfo, "is neither method:password@host:port nor base64 of it")
	raw, uerr := url.PathUnescape(body)
	if uerr != nil {
		return s, "", "", bad
	}
	b, ok := decodeBase64(raw)
	if !ok {
		// A standard-base64 body can end in '/', so drop a trailing slash only as a second try.
		if b, ok = decodeBase64(strings.TrimSuffix(raw, "/")); !ok {
			return s, "", "", bad
		}
	}
	decoded := string(b)
	if err := checkText(partUserinfo, decoded); err != nil {
		return s, "", "", err
	}
	at := strings.LastIndexByte(decoded, '@')
	if at < 0 {
		return s, "", "", bad
	}
	method, password, ok = strings.Cut(decoded[:at], ":")
	if !ok {
		return s, "", "", bad
	}
	s, err = splitServer(decoded[at+1:])
	return s, method, password, err
}

func ssBase64Userinfo(userinfo string) (method, password string, err error) {
	bad := fail(partUserinfo, "is neither method:password nor base64 of it")
	raw, uerr := url.PathUnescape(userinfo)
	if uerr != nil {
		return "", "", bad
	}
	b, ok := decodeBase64(raw)
	if !ok {
		return "", "", bad
	}
	decoded := string(b)
	if err := checkText(partUserinfo, decoded); err != nil {
		return "", "", err
	}
	if method, password, ok = strings.Cut(decoded, ":"); !ok {
		return "", "", bad
	}
	return method, password, nil
}

// parseSOCKS reads socks5://[user:pass@]host:port, its socks5h:// alias, and socks://, which
// v2rayN writes as socks://BASE64(user:pass)@host:port.
func parseSOCKS(scheme, rest string, _ query) (model.ExitParams, error) {
	var p model.ExitParams
	s, err := splitServer(rest)
	if err != nil {
		return p, err
	}
	if s.hasUser {
		var user, pass string
		if u, pw, ok := strings.Cut(s.userinfo, ":"); ok {
			if user, err = decode(partUserinfo, u); err != nil {
				return p, err
			}
			if pass, err = decode(partUserinfo, pw); err != nil {
				return p, err
			}
		} else if s.userinfo == "" {
			return p, fail(partUserinfo, "is empty; leave out \"@\" for no authentication")
		} else if user, pass, ok = socksBase64Userinfo(scheme, s.userinfo); !ok {
			return p, fail(partUserinfo, "has a user but no password")
		}
		// RFC 1929 gives each one byte of length, and neither may be empty.
		switch {
		case user == "" || len(user) > 255:
			return p, fail(partUserinfo, "the user must be 1 to 255 bytes")
		case pass == "" || len(pass) > 255:
			return p, fail(partUserinfo, "the password must be 1 to 255 bytes")
		}
		if err := checkText(partUserinfo, user+pass); err != nil {
			return p, err
		}
		p.Username, p.Secret = user, pass
	}
	if p.Port, err = s.portOr(0); err != nil {
		return p, err
	}
	p.Protocol, p.Host = model.ExitSOCKS, s.host
	return p, nil
}

func socksBase64Userinfo(scheme, userinfo string) (user, pass string, ok bool) {
	if scheme != "socks" {
		return "", "", false
	}
	raw, err := url.PathUnescape(userinfo)
	if err != nil {
		return "", "", false
	}
	b, ok := decodeBase64(raw)
	if !ok {
		return "", "", false
	}
	return strings.Cut(string(b), ":")
}

// parseHysteria2 reads hysteria2://auth@host[:port][/]?… and its hy2:// alias (Hysteria 2 URI
// scheme). TLS is always on, with ALPN h3.
func parseHysteria2(_, rest string, q query) (model.ExitParams, error) {
	var p model.ExitParams
	s, err := splitServer(rest)
	if err != nil {
		return p, err
	}
	if strings.ContainsAny(s.port, ",-") {
		return p, fail(partPort, "port hopping is not supported; give a single port")
	}
	// A user:pass userinfo is the auth "user:pass".
	if p.Secret, err = decode(partUserinfo, s.userinfo); err != nil {
		return p, err
	}
	if p.Secret == "" {
		return p, fail(partUserinfo, "the auth is missing")
	}
	if p.Port, err = s.portOr(443); err != nil {
		return p, err
	}
	p.Protocol, p.Host = model.ExitHysteria2, s.host

	if q["ech"] != "" {
		return p, fail("ech", "not supported yet")
	}
	switch obfs := strings.ToLower(q["obfs"]); obfs {
	case "":
		if q["obfs-password"] != "" {
			return p, fail("obfs-password", "needs obfs=salamander")
		}
	case "salamander":
		if p.ObfsPassword = q["obfs-password"]; p.ObfsPassword == "" {
			return p, fail("obfs-password", "is required with obfs=salamander")
		}
	case "gecko":
		return p, fail("obfs", "gecko is not supported; use salamander")
	default:
		return p, fail("obfs", "%s is not supported; use salamander", quote(obfs))
	}

	t := &model.ExitTLS{ALPN: []string{"h3"}}
	if sni := q["sni"]; sni != "" {
		if t.ServerName, err = hostOrIP("sni", sni); err != nil {
			return p, err
		}
	}
	if v := q["pinSHA256"]; v != "" {
		if t.PinSHA256, err = pins("pinSHA256", v); err != nil {
			return p, err
		}
	}
	insecure, err := flag("insecure", q["insecure"])
	if err != nil {
		return p, err
	}
	if insecure && t.PinSHA256 == "" {
		return p, fail("insecure", "Xray 26 removed allowInsecure; pin the certificate with pinSHA256 instead")
	}
	p.TLS = t
	return p, nil
}
