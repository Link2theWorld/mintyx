package panel

import (
	"context"
	"encoding/hex"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/probe"
)

type realityDTO struct {
	PublicKey  string `json:"publicKey"`
	ShortID    string `json:"shortId"`
	ServerName string `json:"serverName"`
	Target     string `json:"target"`
}

type xhttpDTO struct {
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Security string `json:"security"`
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

type hysteria2DTO struct {
	Domain       string `json:"domain"`
	CertFile     string `json:"certFile"`
	KeyFile      string `json:"keyFile"`
	ObfsPassword string `json:"obfsPassword"`
}

// lineDTO is the API shape of a line; it has no field for the REALITY private key by design.
type lineDTO struct {
	ID        int64          `json:"id,omitempty"`
	Name      string         `json:"name"`
	Protocol  model.Protocol `json:"protocol"`
	Port      int            `json:"port"`
	Enabled   *bool          `json:"enabled"`
	Host      string         `json:"host"`
	CreatedAt *time.Time     `json:"createdAt,omitempty"`
	Reality   *realityDTO    `json:"reality,omitempty"`
	XHTTP     *xhttpDTO      `json:"xhttp,omitempty"`
	Hysteria2 *hysteria2DTO  `json:"hysteria2,omitempty"`
}

func lineToDTO(l model.Line) lineDTO {
	enabled := l.Enabled
	d := lineDTO{ID: l.ID, Name: l.Name, Protocol: l.Protocol, Port: l.Port, Enabled: &enabled, Host: l.Host}
	if !l.CreatedAt.IsZero() {
		t := l.CreatedAt
		d.CreatedAt = &t
	}
	switch {
	case l.Protocol == model.VLESSReality && l.Reality != nil:
		r := l.Reality
		d.Reality = &realityDTO{PublicKey: r.PublicKey, ShortID: r.ShortID, ServerName: r.ServerName, Target: r.Target}
	case l.Protocol == model.VLESSXHTTP && l.XHTTP != nil:
		x := l.XHTTP
		d.XHTTP = &xhttpDTO{Path: x.Path, Domain: x.Domain, Security: string(x.Security), CertFile: x.CertFile, KeyFile: x.KeyFile}
	case l.Protocol == model.Hysteria2 && l.Hysteria2 != nil:
		h := l.Hysteria2
		d.Hysteria2 = &hysteria2DTO{Domain: h.Domain, CertFile: h.CertFile, KeyFile: h.KeyFile, ObfsPassword: h.ObfsPassword}
	}
	return d
}

func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validDialHost accepts a hostname or an IP literal, with or without IPv6 brackets.
func validDialHost(h string) bool {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return net.ParseIP(h[1:len(h)-1]) != nil
	}
	return net.ParseIP(h) != nil || validHostname(h)
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validShortID(s string) bool {
	if len(s) > 16 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// buildLine validates a request against prev (nil on create) and returns the line to store.
func (s *Server) buildLine(d lineDTO, prev *model.Line) (model.Line, error) {
	l := model.Line{Name: strings.TrimSpace(d.Name), Protocol: d.Protocol, Port: d.Port, Host: strings.TrimSpace(d.Host), Enabled: true}
	if prev != nil {
		l.ID, l.Enabled, l.CreatedAt = prev.ID, prev.Enabled, prev.CreatedAt
	}
	if d.Enabled != nil {
		l.Enabled = *d.Enabled
	}
	if err := validateName("name", l.Name); err != nil {
		return l, err
	}
	if !l.Protocol.Valid() {
		return l, invalid("protocol", "unknown protocol")
	}
	if prev != nil && prev.Protocol != l.Protocol {
		return l, invalid("protocol", "protocol cannot be changed")
	}
	if !validPort(l.Port) {
		return l, invalid("port", "port must be between 1 and 65535")
	}
	if s.reserved[l.Port] {
		return l, invalid("port", "port is reserved by the panel")
	}
	if l.Host != "" && !validDialHost(l.Host) {
		return l, invalid("host", "host must be a domain name or IP address")
	}

	switch l.Protocol {
	case model.VLESSReality:
		return l, s.buildReality(&l, d.Reality, prev)
	case model.VLESSXHTTP:
		x := d.XHTTP
		if x == nil {
			return l, invalid("xhttp", "xhttp parameters are required")
		}
		p := model.XHTTPParams{Path: strings.TrimSpace(x.Path), Domain: strings.TrimSpace(x.Domain),
			Security: model.XHTTPSecurity(x.Security), CertFile: strings.TrimSpace(x.CertFile), KeyFile: strings.TrimSpace(x.KeyFile)}
		if p.Path == "" {
			p.Path = "/"
		}
		if !validHostname(p.Domain) {
			return l, invalid("xhttp.domain", "domain is required")
		}
		if !strings.HasPrefix(p.Path, "/") || strings.ContainsAny(p.Path, " ?#\t\r\n") {
			return l, invalid("xhttp.path", "path must start with / and contain no spaces, ? or #")
		}
		switch p.Security {
		case model.XHTTPTLS:
			if p.CertFile == "" {
				return l, invalid("xhttp.certFile", "certificate file is required for TLS")
			}
			if p.KeyFile == "" {
				return l, invalid("xhttp.keyFile", "key file is required for TLS")
			}
		case model.XHTTPPlain:
		default:
			return l, invalid("xhttp.security", `security must be "tls" or "none"`)
		}
		l.XHTTP = &p
	case model.Hysteria2:
		h := d.Hysteria2
		if h == nil {
			return l, invalid("hysteria2", "hysteria2 parameters are required")
		}
		p := model.Hysteria2Params{Domain: strings.TrimSpace(h.Domain), CertFile: strings.TrimSpace(h.CertFile),
			KeyFile: strings.TrimSpace(h.KeyFile), ObfsPassword: h.ObfsPassword}
		if p.Domain != "" && !validHostname(p.Domain) {
			return l, invalid("hysteria2.domain", "domain must be a domain name")
		}
		if p.CertFile == "" {
			return l, invalid("hysteria2.certFile", "certificate file is required")
		}
		if p.KeyFile == "" {
			return l, invalid("hysteria2.keyFile", "key file is required")
		}
		l.Hysteria2 = &p
	}
	return l, nil
}

// buildReality keeps the stored private key while the public key is echoed back unchanged;
// an empty public key asks for a fresh pair. Any other value has no private key to go with it.
func (s *Server) buildReality(l *model.Line, r *realityDTO, prev *model.Line) error {
	if r == nil {
		return invalid("reality", "reality parameters are required")
	}
	// Hex is case-insensitive, but the config builder only takes the lowercase form.
	p := model.RealityParams{PublicKey: strings.TrimSpace(r.PublicKey), ShortID: strings.ToLower(strings.TrimSpace(r.ShortID)),
		ServerName: strings.TrimSpace(r.ServerName), Target: strings.TrimSpace(r.Target)}
	if !validHostname(p.ServerName) {
		return invalid("reality.serverName", "server name is required")
	}
	host, port, err := net.SplitHostPort(p.Target)
	n, perr := strconv.Atoi(port)
	if err != nil || host == "" || perr != nil || !validPort(n) {
		return invalid("reality.target", "target must be host:port")
	}
	if !validShortID(p.ShortID) {
		return invalid("reality.shortId", "short ID must be up to 16 hex digits, even length")
	}
	switch {
	case prev != nil && prev.Reality != nil && prev.Reality.PrivateKey != "" && p.PublicKey == prev.Reality.PublicKey:
		p.PrivateKey = prev.Reality.PrivateKey
	case p.PublicKey == "":
		if p.PrivateKey, p.PublicKey, err = s.keys.NewRealityKeyPair(); err != nil {
			return err
		}
	default:
		return invalid("reality.publicKey", "public key can only be kept or left empty to generate a new pair")
	}
	l.Reality = &p
	return nil
}

func (s *Server) listLines(w http.ResponseWriter, r *http.Request) {
	lines, err := s.st.ListLines(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]lineDTO, 0, len(lines))
	for _, l := range lines {
		out = append(out, lineToDTO(l))
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": out})
}

var preferredPorts = []int{443, 8443, 2053, 2083, 2087, 2096}

func (s *Server) suggestPort(ctx context.Context) (int, error) {
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		return 0, err
	}
	used := map[int]bool{}
	for _, l := range lines {
		used[l.Port] = true
	}
	free := func(p int) bool { return !used[p] && !s.reserved[p] }
	for _, p := range preferredPorts {
		if free(p) {
			return p, nil
		}
	}
	for range 1000 {
		if p := 10000 + rand.IntN(50000); free(p) {
			return p, nil
		}
	}
	for p := 1024; p <= 65535; p++ {
		if free(p) {
			return p, nil
		}
	}
	return 0, invalid("port", "no free port left")
}

var protocolLabels = map[model.Protocol]string{
	model.VLESSReality: "REALITY",
	model.VLESSXHTTP:   "XHTTP",
	model.Hysteria2:    "Hysteria2",
}

func (s *Server) draftLine(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Protocol model.Protocol `json:"protocol"`
		Region   string         `json:"region"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if !in.Protocol.Valid() {
		s.writeFail(w, invalid("protocol", "unknown protocol"))
		return
	}
	if in.Region != "" && !probe.KnownRegion(in.Region) {
		s.writeFail(w, invalid("region", "unknown region"))
		return
	}
	port, err := s.suggestPort(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	l := model.Line{Name: protocolLabels[in.Protocol] + " " + strconv.Itoa(port), Protocol: in.Protocol, Port: port, Enabled: true}
	switch in.Protocol {
	case model.VLESSReality:
		l.Reality = &model.RealityParams{ShortID: s.keys.NewShortID()}
		if s.coverSite != nil {
			if site := s.coverSite(r.Context(), in.Region); site != "" {
				l.Reality.ServerName, l.Reality.Target = site, site+":443"
			}
		}
	case model.VLESSXHTTP:
		l.XHTTP = &model.XHTTPParams{Path: "/" + s.keys.NewShortID(), Security: model.XHTTPTLS}
	case model.Hysteria2:
		l.Hysteria2 = &model.Hysteria2Params{}
	}
	writeJSON(w, http.StatusOK, lineToDTO(l))
}

func (s *Server) createLine(w http.ResponseWriter, r *http.Request) {
	var d lineDTO
	if !decodeJSON(w, r, &d) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.buildLine(d, nil)
	if err == nil {
		err = s.st.CreateLine(r.Context(), &l)
	}
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "line.create", l.Name, string(l.Protocol)+" port "+strconv.Itoa(l.Port))
	s.applyAndRespond(w, r, http.StatusCreated, lineToDTO(l))
}

func (s *Server) updateLine(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var d lineDTO
	if !decodeJSON(w, r, &d) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.st.GetLine(r.Context(), id)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	l, err := s.buildLine(d, &prev)
	if err == nil {
		err = s.st.UpdateLine(r.Context(), &l)
	}
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "line.update", l.Name, "")
	s.applyAndRespond(w, r, http.StatusOK, lineToDTO(l))
}

func (s *Server) deleteLine(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.st.GetLine(r.Context(), id)
	if err == nil {
		err = s.st.DeleteLine(r.Context(), id)
	}
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "line.delete", prev.Name, "")
	s.applyAndRespond(w, r, http.StatusNoContent, nil)
}
