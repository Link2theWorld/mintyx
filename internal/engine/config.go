// Package engine turns lines and clients into an Xray config and supervises the Xray process.
package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/Link2theWorld/mintyx/internal/model"
)

const (
	apiTag    = "api"
	directTag = "direct"
	blockTag  = "block"

	vlessVisionFlow = "xtls-rprx-vision"
	defaultLogLevel = "warning"
	// defaultConnIdle is policy.levels.0.connIdle in seconds. Xray's own default keeps an idle
	// connection open for 300s; closing it sooner frees the server's sockets and keeps clients from
	// holding long-lived quiet tunnels that stand out.
	defaultConnIdle = 180
)

// Options carries the panel-wide settings that are not part of any line.
type Options struct {
	// APIPort is the 127.0.0.1 port the gRPC API (StatsService, HandlerService) listens on.
	APIPort int
	// LogLevel is Xray's log.loglevel: debug, info, warning, error or none. Empty means warning.
	LogLevel string
	// ConnIdle is how many seconds a connection may stay idle before Xray closes it
	// (policy connIdle). Zero means defaultConnIdle.
	ConnIdle int
}

// APIAddr is the host:port the stats query and other API clients dial.
func (o Options) APIAddr() string { return "127.0.0.1:" + strconv.Itoa(o.APIPort) }

// LineError reports a line whose fields cannot form a valid inbound.
type LineError struct {
	LineID  int64
	Field   string
	Problem string
}

func (e *LineError) Error() string {
	return fmt.Sprintf("line %d: %s: %s", e.LineID, e.Field, e.Problem)
}

// ClientError reports a client that cannot be expressed as an Xray user.
type ClientError struct {
	ClientID int64
	Field    string
	Problem  string
}

func (e *ClientError) Error() string {
	return fmt.Sprintf("client %d: %s: %s", e.ClientID, e.Field, e.Problem)
}

// OptionsError reports an invalid Options value.
type OptionsError struct {
	Field   string
	Problem string
}

func (e *OptionsError) Error() string {
	return fmt.Sprintf("engine options: %s: %s", e.Field, e.Problem)
}

// InboundTag is the Xray inbound tag of a line; it is stable across rebuilds.
func InboundTag(lineID int64) string { return "line-" + strconv.FormatInt(lineID, 10) }

// privateDestinations are blocked so clients cannot reach the server's LAN or loopback.
// Listed as CIDRs rather than geoip:private so the config does not depend on geoip.dat.
var privateDestinations = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/3",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

var (
	shortIDPattern  = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)
	validLogLevels  = map[string]bool{"debug": true, "info": true, "warning": true, "error": true, "none": true}
	realityKeyBytes = 32
)

type obj = map[string]any

// BuildConfig returns the complete Xray JSON config for the enabled lines and clients, with
// lines that have an exit leaving through it. Output is deterministic: inputs are ordered by
// ID and all objects are maps, which encoding/json sorts.
func BuildConfig(lines []model.Line, clients []model.Client, exits []model.Exit, opt Options) ([]byte, error) {
	if opt.APIPort < 1 || opt.APIPort > 65535 {
		return nil, &OptionsError{Field: "APIPort", Problem: fmt.Sprintf("%d is not a port number", opt.APIPort)}
	}
	logLevel := opt.LogLevel
	if logLevel == "" {
		logLevel = defaultLogLevel
	}
	if !validLogLevels[logLevel] {
		return nil, &OptionsError{Field: "LogLevel", Problem: fmt.Sprintf("unknown level %q", logLevel)}
	}
	connIdle := opt.ConnIdle
	if connIdle == 0 {
		connIdle = defaultConnIdle
	}
	if connIdle < 0 {
		return nil, &OptionsError{Field: "ConnIdle", Problem: fmt.Sprintf("%d is not a number of seconds", opt.ConnIdle)}
	}

	active := enabledClients(clients)
	for _, c := range active {
		if c.Secret == "" {
			return nil, &ClientError{ClientID: c.ID, Field: "Secret", Problem: "empty"}
		}
	}

	enabled := enabledLines(lines)
	if err := checkPorts(enabled, opt.APIPort); err != nil {
		return nil, err
	}

	inbounds := []any{obj{
		"tag":      apiTag,
		"listen":   "127.0.0.1",
		"port":     opt.APIPort,
		"protocol": "tunnel",
		"settings": obj{"rewriteAddress": "127.0.0.1"},
	}}
	for _, l := range enabled {
		in, err := buildInbound(l, active)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, in)
	}
	exitOutbounds, exitRules, err := exitRouting(enabled, exits)
	if err != nil {
		return nil, err
	}
	// IPIfNonMatch resolves a domain only when no rule matched it by name. Without exits nothing
	// does, so a name pointing at a LAN address meets the block rule resolved. A line routed to
	// an exit matches by inbound tag, though, so with exits the block rule must resolve on its
	// own (IPOnDemand) or such a name would slip past it to the exit.
	domainStrategy := "IPIfNonMatch"
	if len(exitRules) > 0 {
		domainStrategy = "IPOnDemand"
	}

	cfg := obj{
		"log": obj{"loglevel": logLevel},
		"api": obj{
			"tag":      apiTag,
			"services": []string{"HandlerService", "StatsService"},
		},
		"stats": obj{},
		"policy": obj{
			"levels": obj{"0": obj{
				"connIdle":          connIdle,
				"statsUserUplink":   true,
				"statsUserDownlink": true,
			}},
		},
		"inbounds": inbounds,
		// direct stays first: Xray sends anything no rule matches to the first outbound.
		"outbounds": append([]any{
			obj{"tag": directTag, "protocol": "freedom"},
			obj{"tag": blockTag, "protocol": "blackhole"},
		}, exitOutbounds...),
		"routing": obj{
			// Lines with exits come after the block rule; see domainStrategy above.
			"domainStrategy": domainStrategy,
			"rules": append([]any{
				obj{"inboundTag": []string{apiTag}, "outboundTag": apiTag},
				obj{"ip": privateDestinations, "outboundTag": blockTag},
			}, exitRules...),
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func enabledLines(lines []model.Line) []model.Line {
	var out []model.Line
	for _, l := range lines {
		if l.Enabled {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func enabledClients(clients []model.Client) []model.Client {
	var out []model.Client
	for _, c := range clients {
		if c.Enabled() {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// checkPorts rejects two listeners on the same port and transport; Xray's -test does not bind, so it would not catch this.
func checkPorts(lines []model.Line, apiPort int) error {
	type key struct {
		port int
		udp  bool
	}
	owner := map[key]string{{apiPort, false}: "the API inbound"}
	for _, l := range lines {
		if l.Port < 1 || l.Port > 65535 {
			return &LineError{LineID: l.ID, Field: "Port", Problem: fmt.Sprintf("%d is not a port number", l.Port)}
		}
		k := key{l.Port, l.Protocol == model.Hysteria2}
		if other, taken := owner[k]; taken {
			return &LineError{LineID: l.ID, Field: "Port", Problem: fmt.Sprintf("%d is already used by %s", l.Port, other)}
		}
		owner[k] = fmt.Sprintf("line %d", l.ID)
	}
	return nil
}

func buildInbound(l model.Line, clients []model.Client) (obj, error) {
	if err := checkParamsMatch(l); err != nil {
		return nil, err
	}
	in := obj{"tag": InboundTag(l.ID), "port": l.Port}
	switch l.Protocol {
	case model.VLESSReality:
		stream, err := realityStream(l)
		if err != nil {
			return nil, err
		}
		in["protocol"] = "vless"
		in["settings"] = vlessSettings(clients, vlessVisionFlow)
		in["streamSettings"] = stream
	case model.VLESSXHTTP:
		stream, err := xhttpStream(l)
		if err != nil {
			return nil, err
		}
		in["protocol"] = "vless"
		in["settings"] = vlessSettings(clients, "")
		in["streamSettings"] = stream
	case model.Hysteria2:
		stream, err := hysteria2Stream(l)
		if err != nil {
			return nil, err
		}
		users := make([]any, 0, len(clients))
		for _, c := range clients {
			users = append(users, obj{"auth": c.Secret, "email": c.StatsTag()})
		}
		in["protocol"] = "hysteria"
		in["settings"] = obj{"version": 2, "users": users}
		in["streamSettings"] = stream
	}
	return in, nil
}

func checkParamsMatch(l model.Line) error {
	if !l.Protocol.Valid() {
		return &LineError{LineID: l.ID, Field: "Protocol", Problem: fmt.Sprintf("unknown protocol %q", l.Protocol)}
	}
	set := map[model.Protocol]bool{
		model.VLESSReality: l.Reality != nil,
		model.VLESSXHTTP:   l.XHTTP != nil,
		model.Hysteria2:    l.Hysteria2 != nil,
	}
	fields := map[model.Protocol]string{
		model.VLESSReality: "Reality",
		model.VLESSXHTTP:   "XHTTP",
		model.Hysteria2:    "Hysteria2",
	}
	if !set[l.Protocol] {
		return &LineError{LineID: l.ID, Field: fields[l.Protocol], Problem: "missing for protocol " + string(l.Protocol)}
	}
	for _, p := range []model.Protocol{model.VLESSReality, model.VLESSXHTTP, model.Hysteria2} {
		if p != l.Protocol && set[p] {
			return &LineError{LineID: l.ID, Field: fields[p], Problem: "set on a " + string(l.Protocol) + " line"}
		}
	}
	return nil
}

func vlessSettings(clients []model.Client, flow string) obj {
	list := make([]any, 0, len(clients))
	for _, c := range clients {
		u := obj{"id": c.Secret, "email": c.StatsTag()}
		if flow != "" {
			u["flow"] = flow
		}
		list = append(list, u)
	}
	return obj{"clients": list, "decryption": "none"}
}

func realityStream(l model.Line) (obj, error) {
	p := l.Reality
	bad := func(field, problem string) error {
		return &LineError{LineID: l.ID, Field: "Reality." + field, Problem: problem}
	}
	if p.ServerName == "" {
		return nil, bad("ServerName", "empty")
	}
	if p.Target == "" {
		return nil, bad("Target", "empty")
	}
	if !hasHostPort(p.Target) {
		return nil, bad("Target", fmt.Sprintf("%q is not host:port", p.Target))
	}
	if raw, err := decodeKey(p.PrivateKey); err != nil || len(raw) != realityKeyBytes {
		return nil, bad("PrivateKey", "not a base64url X25519 key")
	}
	if !shortIDPattern.MatchString(p.ShortID) {
		return nil, bad("ShortID", fmt.Sprintf("%q is not 0-16 lowercase hex digits of even length", p.ShortID))
	}
	return obj{
		"network":  "raw",
		"security": "reality",
		"realitySettings": obj{
			"target":      p.Target,
			"serverNames": []string{p.ServerName},
			"privateKey":  p.PrivateKey,
			"shortIds":    []string{p.ShortID},
		},
	}, nil
}

func hasHostPort(s string) bool {
	host, port, ok := cutLast(s, ':')
	if !ok || host == "" {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func cutLast(s string, sep byte) (before, after string, found bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func xhttpStream(l model.Line) (obj, error) {
	p := l.XHTTP
	bad := func(field, problem string) error {
		return &LineError{LineID: l.ID, Field: "XHTTP." + field, Problem: problem}
	}
	if p.Path == "" || p.Path[0] != '/' {
		return nil, bad("Path", fmt.Sprintf("%q must start with /", p.Path))
	}
	stream := obj{
		"network":       "xhttp",
		"xhttpSettings": obj{"path": p.Path, "mode": "auto"},
	}
	switch p.Security {
	case model.XHTTPPlain:
		stream["security"] = "none"
	case model.XHTTPTLS:
		if p.CertFile == "" {
			return nil, bad("CertFile", "empty with tls security")
		}
		if p.KeyFile == "" {
			return nil, bad("KeyFile", "empty with tls security")
		}
		tls := obj{"certificates": []any{obj{"certificateFile": p.CertFile, "keyFile": p.KeyFile}}}
		if p.Domain != "" {
			tls["serverName"] = p.Domain
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	default:
		return nil, bad("Security", fmt.Sprintf("unknown value %q", p.Security))
	}
	return stream, nil
}

func hysteria2Stream(l model.Line) (obj, error) {
	p := l.Hysteria2
	bad := func(field, problem string) error {
		return &LineError{LineID: l.ID, Field: "Hysteria2." + field, Problem: problem}
	}
	if p.CertFile == "" {
		return nil, bad("CertFile", "empty; Hysteria2 runs over QUIC and needs a certificate")
	}
	if p.KeyFile == "" {
		return nil, bad("KeyFile", "empty")
	}
	tls := obj{
		"alpn":         []string{"h3"},
		"certificates": []any{obj{"certificateFile": p.CertFile, "keyFile": p.KeyFile}},
	}
	if p.Domain != "" {
		tls["serverName"] = p.Domain
	}
	stream := obj{
		"network":          "hysteria",
		"security":         "tls",
		"tlsSettings":      tls,
		"hysteriaSettings": obj{"version": 2},
	}
	if p.ObfsPassword != "" {
		stream["finalmask"] = obj{"udp": []any{obj{
			"type":     "salamander",
			"settings": obj{"password": p.ObfsPassword},
		}}}
	}
	return stream, nil
}
