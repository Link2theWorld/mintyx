package engine

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ysuhao/mintyx-next/internal/model"
)

// visionUDP443Flow is Vision that also carries UDP/443, which a Hysteria2 hop behind it needs:
// plain Vision refuses UDP/443 traffic.
const visionUDP443Flow = "xtls-rprx-vision-udp443"

// ExitError reports an exit that cannot be expressed as an Xray outbound, or a broken chain.
type ExitError struct {
	ExitID  int64
	Field   string
	Problem string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit %d: %s: %s", e.ExitID, e.Field, e.Problem)
}

// ExitTag is the outbound tag for a path of exits, first exit first: "via-3", "via-3-7".
// IDs rather than names, so renaming an exit never changes the config.
func ExitTag(path []int64) string {
	var b strings.Builder
	b.WriteString("via")
	for _, id := range path {
		b.WriteByte('-')
		b.WriteString(strconv.FormatInt(id, 10))
	}
	return b.String()
}

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true, "chacha20-ietf-poly1305": true,
	"xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true, "2022-blake3-chacha20-poly1305": true,
}

// ExitOutbound is the Xray outbound that dials exit p. dialer is the tag of the outbound it
// connects through ("" to dial directly); beforeHysteria2 means the next hop is a Hysteria2
// exit dialled through this one, so Vision must let UDP/443 pass.
func ExitOutbound(id int64, tag string, p model.ExitParams, dialer string, beforeHysteria2 bool) (map[string]any, error) {
	bad := func(field, problem string) error { return &ExitError{ExitID: id, Field: field, Problem: problem} }
	if p.Host == "" {
		return nil, bad("Host", "empty")
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, bad("Port", fmt.Sprintf("%d is not a port number", p.Port))
	}
	out := obj{"tag": tag}
	var stream obj
	var err error
	switch p.Protocol {
	case model.ExitVLESS:
		if p.Secret == "" {
			return nil, bad("Secret", "empty")
		}
		enc := p.Encryption
		if enc == "" {
			enc = "none"
		}
		settings := obj{"address": p.Host, "port": p.Port, "id": p.Secret, "encryption": enc}
		if flow := p.Flow; flow != "" {
			if beforeHysteria2 && flow == vlessVisionFlow {
				flow = visionUDP443Flow
			}
			settings["flow"] = flow
		}
		out["protocol"], out["settings"] = "vless", settings
		if stream, err = exitStream(p, bad); err != nil {
			return nil, err
		}
	case model.ExitTrojan:
		if p.Secret == "" {
			return nil, bad("Secret", "empty")
		}
		out["protocol"] = "trojan"
		out["settings"] = obj{"address": p.Host, "port": p.Port, "password": p.Secret}
		if stream, err = exitStream(p, bad); err != nil {
			return nil, err
		}
	case model.ExitShadowsocks:
		if !ssMethods[p.Method] {
			return nil, bad("Method", fmt.Sprintf("%q is not a cipher Xray supports", p.Method))
		}
		if p.Secret == "" {
			return nil, bad("Secret", "empty")
		}
		out["protocol"] = "shadowsocks"
		out["settings"] = obj{"address": p.Host, "port": p.Port, "method": p.Method, "password": p.Secret}
	case model.ExitSOCKS:
		settings := obj{"address": p.Host, "port": p.Port}
		if p.Username != "" {
			settings["user"], settings["pass"] = p.Username, p.Secret
		}
		out["protocol"], out["settings"] = "socks", settings
	case model.ExitHysteria2:
		if p.Secret == "" {
			return nil, bad("Secret", "empty")
		}
		tls := obj{"alpn": []string{"h3"}}
		if p.TLS != nil {
			if p.TLS.ServerName != "" {
				tls["serverName"] = p.TLS.ServerName
			}
			if p.TLS.PinSHA256 != "" {
				tls["pinnedPeerCertSha256"] = p.TLS.PinSHA256
			}
		}
		out["protocol"] = "hysteria"
		out["settings"] = obj{"version": 2, "address": p.Host, "port": p.Port}
		stream = obj{
			"network":          "hysteria",
			"hysteriaSettings": obj{"version": 2, "auth": p.Secret},
			"security":         "tls",
			"tlsSettings":      tls,
		}
		if p.ObfsPassword != "" {
			stream["finalmask"] = obj{"udp": []any{obj{"type": "salamander", "settings": obj{"password": p.ObfsPassword}}}}
		}
	default:
		return nil, bad("Protocol", fmt.Sprintf("unknown value %q", p.Protocol))
	}
	if dialer != "" {
		if stream == nil {
			stream = obj{}
		}
		stream["sockopt"] = obj{"dialerProxy": dialer}
	}
	if stream != nil {
		out["streamSettings"] = stream
	}
	return out, nil
}

// exitStream is the streamSettings of a VLESS or Trojan exit.
func exitStream(p model.ExitParams, bad func(field, problem string) error) (obj, error) {
	network := p.Transport.Network
	if network == "" {
		network = model.ExitRaw
	}
	stream := obj{"network": string(network)}
	t := p.Transport
	switch network {
	case model.ExitRaw:
	case model.ExitXHTTP:
		s := obj{"path": nonEmpty(t.Path, "/")}
		if t.Host != "" {
			s["host"] = t.Host
		}
		s["mode"] = nonEmpty(t.Mode, "auto")
		stream["xhttpSettings"] = s
	case model.ExitWS:
		s := obj{"path": nonEmpty(t.Path, "/")}
		if t.Host != "" {
			s["host"] = t.Host
		}
		stream["wsSettings"] = s
	case model.ExitGRPC:
		if t.ServiceName == "" {
			return nil, bad("Transport.ServiceName", "empty")
		}
		s := obj{"serviceName": t.ServiceName}
		if t.Authority != "" {
			s["authority"] = t.Authority
		}
		if t.MultiMode {
			s["multiMode"] = true
		}
		stream["grpcSettings"] = s
	default:
		return nil, bad("Transport.Network", fmt.Sprintf("unknown value %q", network))
	}
	if p.Flow != "" && network != model.ExitRaw {
		return nil, bad("Flow", "Vision only works on raw TCP")
	}
	switch {
	case p.TLS != nil && p.Reality != nil:
		return nil, bad("TLS", "both TLS and REALITY are set")
	case p.Reality != nil:
		r := p.Reality
		if network == model.ExitWS {
			return nil, bad("Reality", "REALITY only works with raw, xhttp or grpc")
		}
		if r.ServerName == "" {
			return nil, bad("Reality.ServerName", "empty")
		}
		if raw, err := decodeKey(r.PublicKey); err != nil || len(raw) != realityKeyBytes {
			return nil, bad("Reality.PublicKey", "not a base64url X25519 key")
		}
		if !shortIDPattern.MatchString(r.ShortID) {
			return nil, bad("Reality.ShortID", "not 0-16 lowercase hex digits of even length")
		}
		rs := obj{"serverName": r.ServerName, "fingerprint": nonEmpty(r.Fingerprint, "chrome"), "password": r.PublicKey}
		if r.ShortID != "" {
			rs["shortId"] = r.ShortID
		}
		if r.SpiderX != "" {
			rs["spiderX"] = r.SpiderX
		}
		if r.MLDSA65Verify != "" {
			rs["mldsa65Verify"] = r.MLDSA65Verify
		}
		stream["security"], stream["realitySettings"] = "reality", rs
	case p.TLS != nil:
		ts := obj{"fingerprint": nonEmpty(p.TLS.Fingerprint, "chrome")}
		if p.TLS.ServerName != "" {
			ts["serverName"] = p.TLS.ServerName
		}
		if len(p.TLS.ALPN) > 0 {
			ts["alpn"] = slices.Clone(p.TLS.ALPN)
		}
		if p.TLS.PinSHA256 != "" {
			ts["pinnedPeerCertSha256"] = p.TLS.PinSHA256
		}
		if p.TLS.VerifyName != "" {
			ts["verifyPeerCertByName"] = p.TLS.VerifyName
		}
		stream["security"], stream["tlsSettings"] = "tls", ts
	default:
		if p.Flow != "" && (p.Encryption == "" || p.Encryption == "none") {
			return nil, bad("Flow", "Vision needs TLS, REALITY or VLESS Encryption")
		}
		stream["security"] = "none"
	}
	return stream, nil
}

func nonEmpty(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// exitRouting builds the outbounds and routing rules that send each enabled line through its
// chain of exits. Only exits reachable from an enabled line appear, so a panel without wired
// exits gets exactly the config it had before exits existed, and editing an unwired exit
// never restarts Xray. lines must be the enabled lines, ordered by ID.
func exitRouting(lines []model.Line, exits []model.Exit) (outbounds, rules []any, err error) {
	byID := make(map[int64]model.Exit, len(exits))
	for _, e := range exits {
		byID[e.ID] = e
	}
	type hop struct {
		path []int64
		out  obj
	}
	var hops []hop
	seen := map[string]bool{}
	for _, l := range lines {
		if l.ExitID == 0 {
			continue
		}
		chain, err := model.ExitChain(byID, l.ExitID)
		if err != nil {
			return nil, nil, chainError(l, err)
		}
		ids := make([]int64, len(chain))
		for i, e := range chain {
			ids[i] = e.ID
		}
		for i, e := range chain {
			tag := ExitTag(ids[:i+1])
			if seen[tag] {
				continue
			}
			seen[tag] = true
			dialer := ""
			if i > 0 {
				dialer = ExitTag(ids[:i])
			}
			beforeHy2 := i+1 < len(chain) && chain[i+1].Params.Protocol == model.ExitHysteria2
			out, err := ExitOutbound(e.ID, tag, e.Params, dialer, beforeHy2)
			if err != nil {
				return nil, nil, err
			}
			hops = append(hops, hop{path: slices.Clone(ids[:i+1]), out: out})
		}
		rules = append(rules, obj{"inboundTag": []string{InboundTag(l.ID)}, "outboundTag": ExitTag(ids)})
	}
	slices.SortFunc(hops, func(a, b hop) int { return slices.Compare(a.path, b.path) })
	for _, h := range hops {
		outbounds = append(outbounds, h.out)
	}
	return outbounds, rules, nil
}

func chainError(l model.Line, err error) error {
	var ce *model.ChainError
	if !errors.As(err, &ce) {
		return err
	}
	if ce.Problem == model.ChainMissing && ce.ExitID == l.ExitID {
		return &LineError{LineID: l.ID, Field: "ExitID", Problem: fmt.Sprintf("exit %d does not exist", l.ExitID)}
	}
	at := ce.ExitID
	if ce.Problem == model.ChainMissing && len(ce.Path) > 1 {
		at = ce.Path[len(ce.Path)-2]
	}
	return &ExitError{ExitID: at, Field: "NextID", Problem: ce.Error()}
}
