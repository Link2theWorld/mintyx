// Package exitlink reads the share link of another proxy server, an exit, into the parameters
// the panel dials it with. It accepts only what Xray 26 can run and, when it cannot, names the
// part of the link that is wrong.
//
// Sources: the XTLS share-link proposal (github.com/XTLS/Xray-core/discussions/716) for vless://
// and the transport keys trojan:// borrows; github.com/trojan-gfw/trojan-url for trojan://;
// SIP002 (shadowsocks.org/doc/sip002.html) for ss://; the Hysteria 2 URI scheme
// (v2.hysteria.network/docs/developers/URI-Scheme/) for hysteria2://; Xray-core's documentation
// for what each outbound accepts.
package exitlink

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// maxLinkLen is the longest link Parse reads. The largest legitimate value, an ML-DSA-65 key in
// pqv, is about 2.6 KiB.
const maxLinkLen = 8 << 10

// Parts an Error names besides query keys.
const (
	partText     = "text" // the link as a whole
	partScheme   = "scheme"
	partUserinfo = "userinfo"
	partHost     = "host"
	partPort     = "port"
	partName     = "name" // the #fragment
)

// Error names the bad part of a link: "scheme", "userinfo", "host", "port", "name" (the
// #fragment), "text" (the link as a whole), or a query key such as "pbk". Problem never repeats
// a password or key.
type Error struct{ Part, Problem string }

func (e *Error) Error() string { return "link " + e.Part + ": " + e.Problem }

func fail(part, format string, args ...any) error {
	return &Error{Part: part, Problem: fmt.Sprintf(format, args...)}
}

// Parse turns a share link into exit parameters and the name its #fragment carries ("" if none).
// Every error it returns is an *Error.
func Parse(link string) (model.ExitParams, string, error) {
	p, name, err := parse(strings.TrimSpace(link))
	if err != nil {
		return model.ExitParams{}, "", err
	}
	return p, name, nil
}

// parser reads the part of a link between "://" and "?" (rest) with its decoded query.
type parser func(scheme, rest string, q query) (model.ExitParams, error)

func parse(link string) (model.ExitParams, string, error) {
	var none model.ExitParams
	switch {
	case link == "":
		return none, "", fail(partText, "is empty")
	case len(link) > maxLinkLen:
		return none, "", fail(partText, "is longer than 8 KiB")
	}
	if err := checkText(partText, link); err != nil {
		return none, "", err
	}
	scheme, rest, ok := strings.Cut(link, "://")
	if !ok || scheme == "" {
		return none, "", fail(partScheme, "is missing; a share link starts with something like vless://")
	}
	scheme = strings.ToLower(scheme)
	var read parser
	switch scheme {
	case "vless":
		read = parseVLESS
	case "trojan":
		read = parseTrojan
	case "ss":
		read = parseShadowsocks
	case "socks", "socks5", "socks5h":
		read = parseSOCKS
	case "hysteria2", "hy2":
		read = parseHysteria2
	case "hysteria":
		return none, "", fail(partScheme, "Hysteria 1 is not supported; use a hysteria2 link")
	case "socks4", "socks4a":
		return none, "", fail(partScheme, "SOCKS4 is not supported; use socks5")
	default:
		return none, "", fail(partScheme, "%s is not supported; use vless, trojan, ss, socks5 or hysteria2",
			quote(scheme))
	}

	rest, frag, _ := strings.Cut(rest, "#")
	rest, rawQuery, _ := strings.Cut(rest, "?")
	q, err := parseQuery(rawQuery)
	if err != nil {
		return none, "", err
	}
	name, err := decode(partName, frag)
	if err != nil {
		return none, "", err
	}
	p, err := read(scheme, rest, q)
	if err != nil {
		return none, "", err
	}
	return p, name, nil
}

// knownKeys are the query keys some scheme reads. Other keys are ignored, values and all; only a
// repeat of one is an error.
var knownKeys = map[string]bool{
	"encryption": true, "flow": true, "type": true, "headerType": true, "security": true,
	"sni": true, "peer": true, "fp": true, "alpn": true, "pcs": true, "vcn": true,
	"allowInsecure": true, "insecure": true, "pbk": true, "sid": true, "spx": true, "pqv": true,
	"path": true, "host": true, "mode": true, "serviceName": true, "authority": true,
	"ech": true, "fm": true, "extra": true,
	"plugin": true, "obfs": true, "obfs-password": true, "pinSHA256": true,
}

// query holds the decoded values of the known keys a link carries. An empty value counts as
// absent, since generators often write "sid=&spx=" for parameters they do not use.
type query map[string]string

func parseQuery(raw string) (query, error) {
	q := query{}
	seen := map[string]bool{}
	for _, kv := range strings.Split(raw, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		key, err := url.PathUnescape(k)
		if err != nil || checkText(partText, key) != nil {
			return nil, fail(partText, "has a query key with a broken %%-escape or a control character")
		}
		if key == "" {
			continue
		}
		if seen[key] {
			return nil, fail(key, "appears more than once")
		}
		seen[key] = true
		if !knownKeys[key] {
			continue
		}
		if q[key], err = decode(key, v); err != nil {
			return nil, err
		}
	}
	return q, nil
}

// decode percent-decodes one part of a link. '+' stays '+': share links are written with
// encodeURIComponent, which never turns a space into '+', and base64 values carry a literal '+'.
func decode(part, s string) (string, error) {
	v, err := url.PathUnescape(s)
	if err != nil {
		return "", fail(part, "has a broken %%-escape")
	}
	if err := checkText(part, v); err != nil {
		return "", err
	}
	return v, nil
}

// checkText rejects bytes that are not UTF-8 (Xray's JSON config would silently replace them,
// changing a password) and control characters.
func checkText(part, s string) error {
	if !utf8.ValidString(s) {
		return fail(part, "is not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fail(part, "contains a control character")
		}
	}
	return nil
}

// server is the userinfo, host and port of a link.
type server struct {
	userinfo string // still percent-encoded
	hasUser  bool
	host     string     // brackets stripped; an IP in canonical form or a lower-cased hostname
	ip       netip.Addr // set when host is an IP literal
	port     string     // as written
	hasPort  bool
}

// splitServer reads "[userinfo@]host[:port][/]". The last '@' ends the userinfo, so a password
// with a raw '@' or a standard-base64 userinfo with '/' still splits correctly.
func splitServer(rest string) (server, error) {
	var s server
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		s.userinfo, s.hasUser, rest = rest[:at], true, rest[at+1:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		if path := rest[i:]; path != "/" {
			return s, fail(partText, "has %s after the port; only \"/\" may come before \"?\"", quote(path))
		}
		rest = rest[:i]
	}
	return s, s.setAuthority(rest)
}

func (s *server) setAuthority(a string) error {
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return fail(partHost, "has \"[\" without a closing \"]\"")
		}
		host, after := a[1:end], a[end+1:]
		switch {
		case after == "":
		case after[0] == ':':
			s.port, s.hasPort = after[1:], true
		default:
			return fail(partHost, "has text after \"]\" that is not a port")
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return fail(partHost, "%s is not an IPv6 address", quote(host))
		}
		return s.setIP(ip)
	}
	if strings.Count(a, ":") > 1 {
		return fail(partHost, "an IPv6 address must be written in [brackets]")
	}
	host, port, hasPort := strings.Cut(a, ":")
	s.port, s.hasPort = port, hasPort
	if host == "" {
		return fail(partHost, "is missing")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return s.setIP(ip)
	}
	h, err := hostname(partHost, host)
	s.host = h
	return err
}

func (s *server) setIP(ip netip.Addr) error {
	switch u := ip.Unmap(); {
	case u.IsUnspecified():
		return fail(partHost, "%s is not an address that can be dialled", quote(ip.String()))
	case u.IsMulticast():
		return fail(partHost, "%s is a multicast address", quote(ip.String()))
	}
	s.ip, s.host = ip, ip.String()
	return nil
}

// portOr returns the port, or def when the link has none; def 0 means the port is required.
func (s server) portOr(def int) (int, error) {
	if !s.hasPort {
		if def == 0 {
			return 0, fail(partPort, "is required")
		}
		return def, nil
	}
	if s.port == "" {
		return 0, fail(partPort, "is empty after \":\"")
	}
	if len(s.port) > 5 || strings.Trim(s.port, "0123456789") != "" {
		return 0, fail(partPort, "%s must be a number from 1 to 65535", quote(s.port))
	}
	n, _ := strconv.Atoi(s.port)
	if n < 1 || n > 65535 {
		return 0, fail(partPort, "%d must be a number from 1 to 65535", n)
	}
	return n, nil
}

// private reports whether s is an IP literal Xray 26 lets VLESS or Trojan reach in plain text.
func (s server) private() bool {
	u := s.ip.Unmap()
	return s.ip.IsValid() && (u.IsPrivate() || u.IsLoopback())
}

// hostname checks an ASCII letters-digits-hyphen hostname and returns it lower-cased.
func hostname(part, h string) (string, error) {
	for i := 0; i < len(h); i++ {
		if h[i] >= utf8.RuneSelf {
			return "", fail(part, "%s is not ASCII; use the punycode form (xn--…) of the domain", quote(h))
		}
	}
	if len(h) > 253 {
		return "", fail(part, "is longer than 253 characters")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		switch {
		case l == "":
			return "", fail(part, "%s has an empty label", quote(h))
		case len(l) > 63:
			return "", fail(part, "%s has a label longer than 63 characters", quote(h))
		case l[0] == '-' || l[len(l)-1] == '-':
			return "", fail(part, "%s has a label that starts or ends with \"-\"", quote(h))
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", fail(part, "%s contains %q, which a hostname cannot", quote(h), c)
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", fail(part, "%s is neither an IP address nor a hostname", quote(h))
	}
	return strings.ToLower(h), nil
}

// hostOrIP checks a name a TLS client may verify against: a hostname or an IP literal.
func hostOrIP(part, h string) (string, error) {
	if ip, err := netip.ParseAddr(h); err == nil && ip.Zone() == "" {
		return ip.String(), nil
	}
	return hostname(part, h)
}

// quote echoes a value the user wrote, cut short so a problem stays one line.
func quote(s string) string {
	const max = 40
	if len(s) > max {
		i := max
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = s[:i] + "…"
	}
	return strconv.Quote(s)
}

// isHex reports whether s is non-empty and only hex digits.
func isHex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789abcdefABCDEF") == ""
}

// flag reads a boolean query value: 1/true or 0/false.
func flag(key, v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fail(key, "must be 1, 0, true or false")
}

// pins reads a comma-separated list of certificate SHA-256 fingerprints, each 64 hex digits
// with optional colons, into lower-case hex without colons.
func pins(key, v string) (string, error) {
	var out []string
	for _, item := range strings.Split(v, ",") {
		h := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(item), ":", ""))
		if len(h) != 64 || !isHex(h) {
			return "", fail(key, "must be SHA-256 fingerprints of 64 hex digits, separated by commas")
		}
		out = append(out, h)
	}
	return strings.Join(out, ","), nil
}
