package exitlink

import (
	"encoding/base64"
	"strings"

	"github.com/ysuhao/mintyx-next/internal/model"
)

const (
	visionFlow       = "xtls-rprx-vision"
	visionUDP443Flow = "xtls-rprx-vision-udp443"
	encryptionNone   = "none"
	// vlessEncPrefix starts every VLESS Encryption client string Xray 26 accepts.
	vlessEncPrefix = "mlkem768x25519plus."
	// mldsa65KeyLen is the size of an ML-DSA-65 public key (FIPS 204), what REALITY's pqv carries.
	mldsa65KeyLen = 1952
)

var (
	tlsFingerprints = map[string]bool{
		"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true,
		"edge": true, "360": true, "qq": true, "random": true, "randomized": true,
	}
	realityFingerprints = map[string]bool{"chrome": true, "firefox": true, "safari": true}
)

// parseVLESS reads vless://<id>@host:port?… (XTLS share-link proposal).
func parseVLESS(_, rest string, q query) (model.ExitParams, error) {
	var p model.ExitParams
	s, err := splitServer(rest)
	if err != nil {
		return p, err
	}
	if p.Secret, err = vlessID(s); err != nil {
		return p, err
	}
	if p.Port, err = s.portOr(0); err != nil {
		return p, err
	}
	p.Protocol, p.Host = model.ExitVLESS, s.host
	if p.Encryption, err = vlessEncryption(q["encryption"]); err != nil {
		return p, err
	}
	if err := parseStream(&p, q, "none"); err != nil {
		return p, err
	}

	switch flow := q["flow"]; flow {
	case "":
	case visionFlow, visionUDP443Flow:
		// Xray runs Vision on raw TCP only ("XTLS only supports TLS and REALITY directly"),
		// with TLS, REALITY or VLESS Encryption underneath.
		if p.Transport.Network != model.ExitRaw {
			return p, fail("flow", "%s only works with type=raw", flow)
		}
		if p.Encryption == encryptionNone && p.TLS == nil && p.Reality == nil {
			return p, fail("flow", "%s needs security tls or reality, or VLESS Encryption", flow)
		}
		p.Flow = flow
	default:
		return p, fail("flow", "%s is not supported; use %s or leave it out", quote(flow), visionFlow)
	}

	if p.Encryption == encryptionNone && p.TLS == nil && p.Reality == nil && !s.private() {
		return p, fail("security", "Xray 26 prohibits vless without TLS or other encryption "+
			"except to a private or loopback IP; use tls, reality or VLESS Encryption")
	}
	return p, nil
}

// vlessID reads the userinfo as a UUID (stored lower-case) or a 1–30 byte string, which Xray
// maps to a UUID itself.
func vlessID(s server) (string, error) {
	if !s.hasUser || s.userinfo == "" {
		return "", fail(partUserinfo, "the VLESS id is missing")
	}
	id, err := decode(partUserinfo, s.userinfo)
	if err != nil {
		return "", err
	}
	if u, ok := canonicalUUID(id); ok {
		return u, nil
	}
	if id == "" || len(id) > 30 {
		return "", fail(partUserinfo, "the VLESS id must be a UUID or a string of 1 to 30 bytes")
	}
	return id, nil
}

// canonicalUUID accepts the 8-4-4-4-12 form or 32 bare hex digits (Xray reads both) and returns
// the lower-case 8-4-4-4-12 form.
func canonicalUUID(s string) (string, bool) {
	var hex string
	switch len(s) {
	case 36:
		for _, i := range []int{8, 13, 18, 23} {
			if s[i] != '-' {
				return "", false
			}
		}
		hex = strings.ReplaceAll(s, "-", "")
	case 32:
		hex = s
	default:
		return "", false
	}
	if len(hex) != 32 || !isHex(hex) {
		return "", false
	}
	hex = strings.ToLower(hex)
	return hex[:8] + "-" + hex[8:12] + "-" + hex[12:16] + "-" + hex[16:20] + "-" + hex[20:], true
}

func vlessEncryption(v string) (string, error) {
	if v == "" || strings.EqualFold(v, encryptionNone) {
		return encryptionNone, nil
	}
	if rest, ok := strings.CutPrefix(v, vlessEncPrefix); ok && rest != "" &&
		strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-") == "" {
		return v, nil
	}
	return "", fail("encryption", "must be none or a VLESS Encryption string starting with %s", vlessEncPrefix)
}

// parseTrojan reads trojan://<password>@host[:port]?… (trojan-gfw/trojan-url). It takes the
// same transport and security keys as VLESS, with TLS by default.
func parseTrojan(_, rest string, q query) (model.ExitParams, error) {
	var p model.ExitParams
	s, err := splitServer(rest)
	if err != nil {
		return p, err
	}
	if !s.hasUser {
		return p, fail(partUserinfo, "the Trojan password is missing")
	}
	// An unescaped ':' stays in the password, so user:pass reads back as "user:pass".
	if p.Secret, err = decode(partUserinfo, s.userinfo); err != nil {
		return p, err
	}
	if p.Secret == "" {
		return p, fail(partUserinfo, "the Trojan password is missing")
	}
	if p.Port, err = s.portOr(443); err != nil {
		return p, err
	}
	p.Protocol, p.Host = model.ExitTrojan, s.host
	if q["flow"] != "" {
		return p, fail("flow", "Trojan has no flow; remove it")
	}
	if peer := q["peer"]; peer != "" {
		if sni := q["sni"]; sni != "" && sni != peer {
			return p, fail("peer", "differs from sni; give the server name once")
		}
		q["sni"] = peer
	}
	if err := parseStream(&p, q, "tls"); err != nil {
		return p, err
	}
	if p.TLS == nil && p.Reality == nil && !s.private() {
		return p, fail("security", "Xray 26 prohibits trojan without TLS except to a private or loopback IP; "+
			"use tls or reality")
	}
	return p, nil
}

// parseStream reads the transport (type) and security keys into p. Keys for a transport or
// security the link does not use are ignored, as are sni and fp without security.
func parseStream(p *model.ExitParams, q query, defSecurity string) error {
	for _, k := range []string{"ech", "fm", "extra"} {
		if q[k] != "" {
			return fail(k, "not supported yet")
		}
	}
	switch h := strings.ToLower(q["headerType"]); h {
	case "", "none":
	default:
		return fail("headerType", "%s is not supported; only none is", quote(h))
	}

	t := &p.Transport
	switch typ := strings.ToLower(q["type"]); typ {
	case "", "tcp", "raw":
		t.Network = model.ExitRaw
	case "xhttp":
		t.Network = model.ExitXHTTP
	case "ws":
		t.Network = model.ExitWS
	case "grpc":
		t.Network = model.ExitGRPC
	default:
		return fail("type", "%s is not supported; use raw, xhttp, ws or grpc", quote(typ))
	}
	switch t.Network {
	case model.ExitXHTTP, model.ExitWS:
		t.Path, t.Host = q["path"], q["host"]
		if t.Path == "" {
			t.Path = "/"
		} else if !strings.HasPrefix(t.Path, "/") {
			return fail("path", "must start with \"/\"")
		}
		if t.Network == model.ExitXHTTP {
			switch t.Mode = strings.ToLower(q["mode"]); t.Mode {
			case "":
				t.Mode = "auto"
			case "auto", "packet-up", "stream-up", "stream-one":
			default:
				return fail("mode", "%s is not an xhttp mode; use auto, packet-up, stream-up or stream-one",
					quote(t.Mode))
			}
		}
	case model.ExitGRPC:
		if t.ServiceName = q["serviceName"]; t.ServiceName == "" {
			return fail("serviceName", "is required for grpc")
		}
		t.Authority = q["authority"]
		switch mode := strings.ToLower(q["mode"]); mode {
		case "", "gun":
		case "multi":
			t.MultiMode = true
		default:
			return fail("mode", "%s is not a grpc mode; use gun or multi", quote(mode))
		}
	}

	security := strings.ToLower(q["security"])
	if security == "" {
		security = defSecurity
	}
	var err error
	switch security {
	case "none":
	case "tls":
		p.TLS, err = parseTLS(q)
	case "reality":
		if t.Network == model.ExitWS {
			return fail("security", "REALITY only supports RAW, XHTTP and gRPC")
		}
		p.Reality, err = parseReality(q)
	default:
		return fail("security", "%s is not supported; use none, tls or reality", quote(security))
	}
	return err
}

func parseTLS(q query) (*model.ExitTLS, error) {
	t := &model.ExitTLS{}
	var err error
	if sni := q["sni"]; sni != "" {
		if t.ServerName, err = hostOrIP("sni", sni); err != nil {
			return nil, err
		}
	}
	if t.Fingerprint = strings.ToLower(q["fp"]); t.Fingerprint == "" {
		t.Fingerprint = "chrome"
	} else if !tlsFingerprints[t.Fingerprint] {
		return nil, fail("fp", "%s is not supported; use chrome, firefox, safari, ios, android, edge, "+
			"360, qq, random or randomized", quote(t.Fingerprint))
	}
	if v := q["alpn"]; v != "" {
		for _, a := range strings.Split(v, ",") {
			switch a = strings.TrimSpace(a); a {
			case "h2", "http/1.1", "h3":
				t.ALPN = append(t.ALPN, a)
			default:
				return nil, fail("alpn", "%s is not supported; use h2, http/1.1 or h3", quote(a))
			}
		}
	}
	if v := q["pcs"]; v != "" {
		if t.PinSHA256, err = pins("pcs", v); err != nil {
			return nil, err
		}
	}
	if v := q["vcn"]; v != "" {
		var names []string
		for _, n := range strings.Split(v, ",") {
			n, err := hostname("vcn", strings.TrimSpace(n))
			if err != nil {
				return nil, err
			}
			names = append(names, n)
		}
		t.VerifyName = strings.Join(names, ",")
	}
	for _, k := range []string{"allowInsecure", "insecure"} {
		on, err := flag(k, q[k])
		if err != nil {
			return nil, err
		}
		if on && t.PinSHA256 == "" {
			return nil, fail(k, "Xray 26 removed allowInsecure; pin the certificate with pcs instead")
		}
	}
	return t, nil
}

func parseReality(q query) (*model.ExitReality, error) {
	r := &model.ExitReality{}
	var err error
	sni := q["sni"]
	if sni == "" {
		return nil, fail("sni", "is required for REALITY")
	}
	if r.ServerName, err = hostname("sni", sni); err != nil {
		return nil, err
	}
	if r.Fingerprint = strings.ToLower(q["fp"]); r.Fingerprint == "" {
		r.Fingerprint = "chrome"
	} else if !realityFingerprints[r.Fingerprint] {
		return nil, fail("fp", "%s is not supported with REALITY; use chrome, firefox or safari", quote(r.Fingerprint))
	}

	pbk := q["pbk"]
	if pbk == "" {
		return nil, fail("pbk", "is required for REALITY")
	}
	key, ok := decodeBase64(pbk)
	if !ok || len(key) != 32 {
		return nil, fail("pbk", "must be a base64 X25519 public key of 32 bytes")
	}
	r.PublicKey = base64.RawURLEncoding.EncodeToString(key)

	sid := q["sid"]
	if len(sid) > 16 || len(sid)%2 != 0 || sid != "" && !isHex(sid) {
		return nil, fail("sid", "must be up to 16 hex digits, an even number of them")
	}
	r.ShortID = strings.ToLower(sid)

	if r.SpiderX = q["spx"]; r.SpiderX != "" && !strings.HasPrefix(r.SpiderX, "/") {
		return nil, fail("spx", "must start with \"/\"")
	}
	if pqv := q["pqv"]; pqv != "" {
		key, ok := decodeBase64(pqv)
		if !ok || len(key) != mldsa65KeyLen {
			return nil, fail("pqv", "must be a base64url ML-DSA-65 public key of %d bytes", mldsa65KeyLen)
		}
		r.MLDSA65Verify = base64.RawURLEncoding.EncodeToString(key)
	}
	return r, nil
}

// decodeBase64 accepts the standard or URL alphabet, with or without padding.
func decodeBase64(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	b, err := base64.RawURLEncoding.DecodeString(s)
	return b, err == nil
}
