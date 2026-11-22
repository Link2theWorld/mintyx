// Package rdap asks the regional internet registries which network an IP address belongs to,
// using the Registration Data Access Protocol (RFC 9082, 9083) and IANA's bootstrap registry
// (RFC 9224) to find the registry in charge.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

const (
	BootstrapV4 = "https://data.iana.org/rdap/ipv4.json"
	BootstrapV6 = "https://data.iana.org/rdap/ipv6.json"

	requestTimeout = 20 * time.Second
	maxBody        = 2 << 20
	bootstrapTTL   = 24 * time.Hour
	maxField       = 200
	maxRedirects   = 5
	userAgent      = "mintyx-panel"
)

var (
	// ErrNotFound means no registry has a record for the address.
	ErrNotFound = errors.New("rdap: no registration found")
	// ErrNoRegistry means the bootstrap registry lists no RDAP server for the address.
	ErrNoRegistry = errors.New("rdap: no registry serves this address")
)

// RateLimitError means a registry asked us to slow down; RetryAfter is 0 when it did not say for how long.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return "rdap: rate limited by the registry" }

type service struct {
	prefix netip.Prefix
	base   string
}

// Client is safe for concurrent use. The zero value is not usable; call New.
type Client struct {
	http       *http.Client
	bootstraps [2]string
	now        func() time.Time

	mu       sync.Mutex
	services []service
	loadedAt time.Time
}

func New() *Client {
	return NewWith(nil, BootstrapV4, BootstrapV6)
}

// NewWith points the client at other bootstrap files, for tests. A nil httpClient gets the defaults.
func NewWith(httpClient *http.Client, bootstrapV4, bootstrapV6 string) *Client {
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	c := *httpClient
	c.Timeout = requestTimeout
	// Registries redirect to one another, and only ever need to do so over TLS.
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("rdap: too many redirects")
		}
		if req.URL.Scheme != via[0].URL.Scheme {
			return errors.New("rdap: redirect changes scheme")
		}
		return nil
	}
	return &Client{http: &c, bootstraps: [2]string{bootstrapV4, bootstrapV6}, now: time.Now}
}

func (c *Client) get(ctx context.Context, rawURL string, v any) (*url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case res.StatusCode == http.StatusTooManyRequests:
		secs, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		return nil, &RateLimitError{RetryAfter: time.Duration(max(secs, 0)) * time.Second}
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("rdap: %s answered %s", req.URL.Host, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("rdap: answer from %s is too large", req.URL.Host)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return nil, fmt.Errorf("rdap: answer from %s: %w", req.URL.Host, err)
	}
	return res.Request.URL, nil
}

type bootstrapFile struct {
	// Each service is [[prefixes...], [base URLs...]].
	Services [][][]string `json:"services"`
}

func parseBootstrap(f bootstrapFile) []service {
	var out []service
	for _, svc := range f.Services {
		if len(svc) != 2 {
			continue
		}
		base := ""
		for _, u := range svc[1] {
			if strings.HasPrefix(u, "https://") {
				base = strings.TrimSuffix(u, "/") + "/"
				break
			}
		}
		if base == "" {
			continue
		}
		for _, p := range svc[0] {
			if prefix, err := netip.ParsePrefix(p); err == nil {
				out = append(out, service{prefix: prefix.Masked(), base: base})
			}
		}
	}
	return out
}

// registryFor returns the base URL of the registry serving ip, refreshing the bootstrap data once a day.
// A failed refresh keeps the previous data.
func (c *Client) registryFor(ctx context.Context, ip netip.Addr) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.services == nil || c.now().Sub(c.loadedAt) > bootstrapTTL {
		var loaded []service
		var loadErr error
		for _, u := range c.bootstraps {
			var f bootstrapFile
			if _, err := c.get(ctx, u, &f); err != nil {
				loadErr = fmt.Errorf("rdap: bootstrap: %w", err)
				break
			}
			loaded = append(loaded, parseBootstrap(f)...)
		}
		switch {
		case loadErr == nil && len(loaded) > 0:
			c.services, c.loadedAt = loaded, c.now()
		case c.services == nil && loadErr != nil:
			return "", loadErr
		case c.services == nil:
			return "", errors.New("rdap: bootstrap registry is empty")
		}
	}
	best, bits := "", -1
	for _, s := range c.services {
		if s.prefix.Contains(ip) && s.prefix.Bits() > bits {
			best, bits = s.base, s.prefix.Bits()
		}
	}
	if best == "" {
		return "", ErrNoRegistry
	}
	return best, nil
}

// Lookup returns what the registry in charge of ip records about its network.
func (c *Client) Lookup(ctx context.Context, ip netip.Addr) (model.Whois, error) {
	ip = ip.Unmap()
	base, err := c.registryFor(ctx, ip)
	if err != nil {
		return model.Whois{}, err
	}
	var n network
	final, err := c.get(ctx, base+"ip/"+ip.String(), &n)
	if err != nil {
		return model.Whois{}, err
	}
	w := n.whois()
	w.Registry = registryName(final.Host)
	return w, nil
}

var registries = map[string]string{
	"arin.net": "ARIN", "ripe.net": "RIPE NCC", "apnic.net": "APNIC", "lacnic.net": "LACNIC", "afrinic.net": "AFRINIC",
}

// registryName gives the well-known name for a registry's host, or the host itself for any other
// (national registries such as JPNIC and KRNIC answer for their own ranges).
func registryName(host string) string {
	for suffix, name := range registries {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return name
		}
	}
	return clean(host)
}

type network struct {
	Name         string   `json:"name"`
	Country      string   `json:"country"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	Entities     []entity `json:"entities"`
	CIDRs        []struct {
		V4     string `json:"v4prefix"`
		V6     string `json:"v6prefix"`
		Length int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

type entity struct {
	Roles    []string `json:"roles"`
	Entities []entity `json:"entities"`
	// VCard is jCard (RFC 7095): ["vcard", [[name, params, type, value], ...]].
	VCard []json.RawMessage `json:"vcardArray"`
}

type property struct {
	name   string
	params map[string]json.RawMessage
	value  json.RawMessage
}

func (e entity) properties() []property {
	if len(e.VCard) != 2 {
		return nil
	}
	var raw [][]json.RawMessage
	if json.Unmarshal(e.VCard[1], &raw) != nil {
		return nil
	}
	var out []property
	for _, r := range raw {
		if len(r) < 4 {
			continue
		}
		var p property
		if json.Unmarshal(r[0], &p.name) != nil {
			continue
		}
		_ = json.Unmarshal(r[1], &p.params)
		p.value = r[3]
		out = append(out, p)
	}
	return out
}

func (e entity) text(name string) string {
	for _, p := range e.properties() {
		var s string
		if p.name == name && json.Unmarshal(p.value, &s) == nil && s != "" {
			return s
		}
	}
	return ""
}

func (e entity) hasRole(role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// emails lists the entity's addresses; abuseOnly keeps those the registry marked as the abuse mailbox.
func (e entity) emails(abuseOnly bool) []string {
	var out []string
	for _, p := range e.properties() {
		var s string
		if p.name != "email" || json.Unmarshal(p.value, &s) != nil {
			continue
		}
		if abuseOnly && !strings.Contains(string(p.params["type"]), "abuse") {
			continue
		}
		// It ends up in a mailto: link, so it must be exactly one plain address.
		if a, err := mail.ParseAddress(s); err == nil && a.Address == s && len(s) <= maxField {
			out = append(out, s)
		}
	}
	return out
}

// country reads the country from the entity's postal address: the structured field when it is
// filled in, otherwise the last line of the printed label.
func (e entity) country() string {
	for _, p := range e.properties() {
		if p.name != "adr" {
			continue
		}
		var parts []json.RawMessage
		if json.Unmarshal(p.value, &parts) == nil && len(parts) == 7 {
			var s string
			if json.Unmarshal(parts[6], &s) == nil && strings.TrimSpace(s) != "" {
				return s
			}
		}
		var label string
		if json.Unmarshal(p.params["label"], &label) == nil {
			lines := strings.Split(strings.TrimSpace(label), "\n")
			// A one-line label is a street address, not a country.
			if len(lines) > 1 {
				return lines[len(lines)-1]
			}
		}
	}
	return ""
}

// walk visits entities depth-first, outermost first, bounded against hostile nesting.
func walk(es []entity, depth int, visit func(entity) bool) bool {
	if depth > 4 {
		return false
	}
	for _, e := range es {
		if visit(e) || walk(e.Entities, depth+1, visit) {
			return true
		}
	}
	return false
}

func (n network) whois() model.Whois {
	w := model.Whois{Network: clean(n.Name), Country: normalizeCountry(n.Country)}

	// The holder is the registrant that is an organisation. RIPE also lists the maintainer object
	// as a registrant, and its name ("EXAMPLE-MNT") says less than the network's own.
	var holder entity
	found := walk(n.Entities, 0, func(e entity) bool {
		if e.hasRole("registrant") && e.text("kind") == "org" && e.text("fn") != "" {
			holder = e
			return true
		}
		return false
	})
	if !found {
		found = walk(n.Entities, 0, func(e entity) bool {
			if e.hasRole("registrant") && e.country() != "" {
				holder = e
				return true
			}
			return false
		})
	}
	if found {
		if fn := clean(holder.text("fn")); fn != "" && holder.text("kind") == "org" {
			w.Network = fn
		}
		if w.Country == "" {
			w.Country = normalizeCountry(holder.country())
		}
	}

	// The abuse contact, else any mailbox flagged for abuse (RIPE hangs it on the technical contact).
	if !walk(n.Entities, 0, func(e entity) bool {
		if !e.hasRole("abuse") {
			return false
		}
		if list := e.emails(false); len(list) > 0 {
			w.AbuseEmail = list[0]
			return true
		}
		return false
	}) {
		walk(n.Entities, 0, func(e entity) bool {
			if list := e.emails(true); len(list) > 0 {
				w.AbuseEmail = list[0]
				return true
			}
			return false
		})
	}

	switch {
	case len(n.CIDRs) == 1 && n.CIDRs[0].V4 != "":
		w.NetRange = clean(n.CIDRs[0].V4 + "/" + strconv.Itoa(n.CIDRs[0].Length))
	case len(n.CIDRs) == 1 && n.CIDRs[0].V6 != "":
		w.NetRange = clean(n.CIDRs[0].V6 + "/" + strconv.Itoa(n.CIDRs[0].Length))
	case n.StartAddress != "" && n.EndAddress != "":
		w.NetRange = clean(n.StartAddress + " - " + n.EndAddress)
	}
	return w
}

// countryNames covers the registries that spell the country out instead of giving its code.
var countryNames = map[string]string{
	"UNITED STATES": "US", "UNITED STATES OF AMERICA": "US", "USA": "US", "CANADA": "CA",
	"NETHERLANDS": "NL", "THE NETHERLANDS": "NL", "GERMANY": "DE", "FRANCE": "FR",
	"UNITED KINGDOM": "GB", "RUSSIAN FEDERATION": "RU", "RUSSIA": "RU", "CHINA": "CN",
	"BRAZIL": "BR", "MEXICO": "MX", "ARGENTINA": "AR", "SINGAPORE": "SG", "JAPAN": "JP",
	"AUSTRALIA": "AU", "INDIA": "IN", "SOUTH AFRICA": "ZA",
}

func normalizeCountry(s string) string {
	s = clean(s)
	up := strings.ToUpper(s)
	if code, ok := countryNames[up]; ok {
		return code
	}
	if len(up) == 2 && up[0] >= 'A' && up[0] <= 'Z' && up[1] >= 'A' && up[1] <= 'Z' {
		return up
	}
	return s
}

// clean makes registry text safe to store and show: one line, no control characters, bounded.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxField {
		s = string(r[:maxField])
	}
	return s
}
