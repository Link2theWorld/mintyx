package share

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Link2theWorld/mintyx/internal/model"
)

type Format string

const (
	// FormatLinks is a base64-encoded, newline-separated list of share URIs.
	FormatLinks  Format = "links"
	FormatMihomo Format = "mihomo"
)

const (
	selectGroupName = "Proxy"
	mihomoDirect    = "DIRECT"
)

// Omission is an enabled line a subscription format left out, with a reason the UI can show.
type Omission struct {
	LineID   int64
	LineName string
	Reason   string
}

// Omitted lists the enabled lines that Render leaves out of every format for any enabled client.
func Omitted(lines []model.Line, defaultHost string) []Omission {
	// Any non-empty secret works here: the per-client part never decides whether a line is usable.
	_, om := plan(lines, model.Client{Secret: "x"}, defaultHost)
	return om
}

func plan(lines []model.Line, c model.Client, defaultHost string) ([]endpoint, []Omission) {
	var eps []endpoint
	var om []Omission
	for _, l := range lines {
		if !l.Enabled {
			continue
		}
		ep, err := resolve(l, c, defaultHost)
		if err != nil {
			om = append(om, Omission{LineID: l.ID, LineName: l.Name, Reason: err.Error()})
			continue
		}
		eps = append(eps, ep)
	}
	return eps, om
}

// Render builds client c's subscription body. A disabled client or no usable lines yields
// a valid empty subscription; unusable lines are skipped (see Omitted).
func Render(format Format, lines []model.Line, c model.Client, defaultHost string) ([]byte, string, error) {
	var eps []endpoint
	if c.Enabled() {
		eps, _ = plan(lines, c, defaultHost)
	}
	switch format {
	case FormatLinks:
		uris := make([]string, len(eps))
		for i, ep := range eps {
			uris[i] = ep.uri()
		}
		body := base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n")))
		return []byte(body), "text/plain; charset=utf-8", nil
	case FormatMihomo:
		body, err := renderMihomo(eps)
		return body, "text/yaml; charset=utf-8", err
	}
	return nil, "", fmt.Errorf("unknown format %q", format)
}

// uniqueNames gives each endpoint a display name distinct from the others and from reserved names,
// because mihomo rejects duplicate proxy names.
func uniqueNames(eps []endpoint, reserved ...string) []string {
	seen := map[string]bool{}
	for _, r := range reserved {
		seen[r] = true
	}
	out := make([]string, len(eps))
	for i, ep := range eps {
		base := ep.line.Name
		if base == "" {
			base = "line " + strconv.FormatInt(ep.line.ID, 10)
		}
		name := base
		for n := 2; seen[name]; n++ {
			name = fmt.Sprintf("%s (%d)", base, n)
		}
		seen[name] = true
		out[i] = name
	}
	return out
}

type mihomoRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id,omitempty"`
	// Xray 26.7.11+ rejects a REALITY ClientHello without this key share (XTLS/Xray-core#6477).
	SupportX25519MLKEM768 bool `yaml:"support-x25519mlkem768"`
}

type mihomoXHTTPOpts struct {
	Path string `yaml:"path"`
	Host string `yaml:"host"`
}

type mihomoProxy struct {
	Name              string             `yaml:"name"`
	Type              string             `yaml:"type"`
	Server            string             `yaml:"server"`
	Port              int                `yaml:"port"`
	UUID              string             `yaml:"uuid,omitempty"`
	Password          string             `yaml:"password,omitempty"`
	UDP               bool               `yaml:"udp"`
	Network           string             `yaml:"network,omitempty"`
	TLS               bool               `yaml:"tls,omitempty"`
	Flow              string             `yaml:"flow,omitempty"`
	ServerName        string             `yaml:"servername,omitempty"`
	SNI               string             `yaml:"sni,omitempty"`
	ClientFingerprint string             `yaml:"client-fingerprint,omitempty"`
	RealityOpts       *mihomoRealityOpts `yaml:"reality-opts,omitempty"`
	XHTTPOpts         *mihomoXHTTPOpts   `yaml:"xhttp-opts,omitempty"`
	Obfs              string             `yaml:"obfs,omitempty"`
	ObfsPassword      string             `yaml:"obfs-password,omitempty"`
}

type mihomoGroup struct {
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Proxies []string `yaml:"proxies"`
}

type mihomoDoc struct {
	Proxies []mihomoProxy `yaml:"proxies"`
	Groups  []mihomoGroup `yaml:"proxy-groups"`
	Rules   []string      `yaml:"rules"`
}

func renderMihomo(eps []endpoint) ([]byte, error) {
	names := uniqueNames(eps, selectGroupName, mihomoDirect, "REJECT")
	doc := mihomoDoc{Proxies: []mihomoProxy{}, Rules: []string{"MATCH," + selectGroupName}}
	for i, ep := range eps {
		p := mihomoProxy{Name: names[i], Server: ep.host, Port: ep.port, UDP: true}
		switch ep.line.Protocol {
		case model.VLESSReality:
			p.Type, p.UUID, p.Network, p.TLS, p.Flow = "vless", ep.secret, realityTCPNet, true, visionFlow
			p.ServerName, p.ClientFingerprint = ep.serverName, defaultFP
			p.RealityOpts = &mihomoRealityOpts{PublicKey: ep.reality.PublicKey, ShortID: ep.reality.ShortID, SupportX25519MLKEM768: true}
		case model.VLESSXHTTP:
			p.Type, p.UUID, p.Network, p.TLS = "vless", ep.secret, xhttpNetwork, true
			p.ServerName, p.ClientFingerprint = ep.serverName, defaultFP
			p.XHTTPOpts = &mihomoXHTTPOpts{Path: ep.xhttpPath, Host: ep.xhttpHost}
		case model.Hysteria2:
			p.Type, p.Password, p.SNI = "hysteria2", ep.secret, ep.serverName
			if ep.obfsPass != "" {
				p.Obfs, p.ObfsPassword = salamander, ep.obfsPass
			}
		}
		doc.Proxies = append(doc.Proxies, p)
	}
	members := append(names, mihomoDirect)
	doc.Groups = []mihomoGroup{{Name: selectGroupName, Type: "select", Proxies: members}}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode mihomo yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode mihomo yaml: %w", err)
	}
	return buf.Bytes(), nil
}

// UserInfoHeader is the Subscription-Userinfo header value; total and expire are left out
// when the client has no quota or never expires.
func UserInfoHeader(c model.Client) string {
	s := fmt.Sprintf("upload=%d; download=%d", c.UsedUp, c.UsedDown)
	if c.QuotaBytes > 0 {
		s += fmt.Sprintf("; total=%d", c.QuotaBytes)
	}
	if c.ExpiresAt != nil {
		s += fmt.Sprintf("; expire=%d", c.ExpiresAt.Unix())
	}
	return s
}
