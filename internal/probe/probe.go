// Package probe checks whether a website can serve as a REALITY cover site, and how close it is.
package probe

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Host    string
	OK      bool
	Latency time.Duration
	// Problem says why the site is unusable; empty when OK.
	Problem string
}

type Prober struct {
	// RootCAs of nil uses the system roots. Address of nil dials host:443.
	RootCAs *x509.CertPool
	Address func(host string) string
	// Timeout bounds one Check, handshake and homepage request together; 0 means 6s.
	Timeout time.Duration
	// Rand returns a number in [0, n); nil uses math/rand. Tests pin the random choice with it.
	Rand func(n int) int
}

// browserUA is sent with the homepage request: some sites answer a client that does not look
// like a browser differently, and a browser is what a cover site must satisfy.
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

// Check does one TLS handshake with host and asks it for its homepage over that connection.
// REALITY relays a prober's handshake to the cover site, so the site must look like what REALITY
// clients present: TLS 1.3 with an X25519 key exchange, HTTP/2, and a valid certificate for the
// name. Its homepage must answer in place rather than redirect, since a redirect to another
// name gives away that this name is not where the content lives. A site that is one of the
// covers so many REALITY servers already imitate is refused too (see PopularDest).
func (p *Prober) Check(ctx context.Context, host string) Result {
	res := Result{Host: host}
	if brand := PopularDest(host); brand != "" {
		res.Problem = "is a popular REALITY cover site (" + brand + ")"
		return res
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, "443")
	if p.Address != nil {
		addr = p.Address(host)
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		// Only X25519 gets a key share up front, as with a REALITY client; a server that would
		// rather have P-256 asks for it again and so fails the X25519 check below.
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		// The certificate is verified below, to say precisely what is wrong with it.
		InsecureSkipVerify: true,
	}}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Problem = err.Error()
		return res
	}
	defer conn.Close()
	res.Latency = time.Since(start)
	tc := conn.(*tls.Conn)

	state := tc.ConnectionState()
	brand := ""
	if len(state.PeerCertificates) > 0 {
		brand = popularCert(state.PeerCertificates[0])
	}
	switch {
	case brand != "":
		res.Problem = "is served like a popular REALITY cover site (" + brand + ")"
		return res
	case state.Version != tls.VersionTLS13:
		res.Problem = "does not support TLS 1.3"
		return res
	case state.CurveID != tls.X25519:
		res.Problem = "does not negotiate X25519 (got " + state.CurveID.String() + ")"
		return res
	case state.NegotiatedProtocol != "h2":
		res.Problem = "does not support HTTP/2"
		return res
	}
	if problem := verifyCert(state.PeerCertificates, host, p.RootCAs); problem != "" {
		res.Problem = problem
		return res
	}
	if problem := checkHomepage(ctx, tc, host); problem != "" {
		res.Problem = problem
		return res
	}
	res.OK = true
	return res
}

// verifyCert says what is wrong with the chain a site presented for host, or "" when nothing is.
func verifyCert(certs []*x509.Certificate, host string, roots *x509.CertPool) string {
	if len(certs) == 0 {
		return "presented no certificate"
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates})
	var (
		nameErr      x509.HostnameError
		invalidErr   x509.CertificateInvalidError
		authorityErr x509.UnknownAuthorityError
	)
	switch {
	case err == nil:
		return ""
	case errors.As(err, &nameErr):
		return "certificate does not cover " + host
	case errors.As(err, &invalidErr) && invalidErr.Reason == x509.Expired:
		return "certificate has expired or is not yet valid"
	case errors.As(err, &authorityErr):
		return "certificate is not from a trusted authority"
	}
	return "certificate is not valid: " + err.Error()
}

// checkHomepage asks for / over the connection just probed, so the answer comes from the very
// server the handshake reached. It says what is wrong, or "" when nothing is.
func checkHomepage(ctx context.Context, conn *tls.Conn, host string) string {
	var once sync.Once
	tr := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var c net.Conn
			once.Do(func() { c = conn })
			if c == nil {
				return nil, errors.New("probe: the probed connection is already in use")
			}
			return c, nil
		},
		ForceAttemptHTTP2: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return err.Error()
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "homepage request failed: " + err.Error()
	}
	resp.Body.Close()
	switch {
	case strings.EqualFold(resp.Header.Get("Server"), "cloudflare") || resp.Header.Get("CF-RAY") != "":
		return "is served like a popular REALITY cover site (Cloudflare)"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		problem := "homepage redirects (" + strconv.Itoa(resp.StatusCode)
		if loc := resp.Header.Get("Location"); loc != "" {
			problem += " to " + loc
		}
		return problem + ")"
	}
	return ""
}

// nearFastest is how much slower than the quickest site a site may be and still be picked.
// Picking at random among the sites this close spreads servers in one region over several
// covers instead of all of them imitating the same one.
const nearFastest = 1.5

// Rank checks every host at once and returns the usable ones, quickest first.
func Rank(ctx context.Context, hosts []string, check func(context.Context, string) Result) []Result {
	results := make([]Result, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Go(func() { results[i] = check(ctx, host) })
	}
	wg.Wait()
	var usable []Result
	for i, r := range results {
		if r.OK {
			r.Host = hosts[i]
			usable = append(usable, r)
		}
	}
	slices.SortStableFunc(usable, func(a, b Result) int { return cmp.Compare(a.Latency, b.Latency) })
	return usable
}

// Shortlist orders ranked (quickest first, as Rank returns it) for picking: the sites whose
// handshake took at most nearFastest times the quickest one, in random order, then the rest,
// quickest first. intn returns a number in [0, n).
func Shortlist(ranked []Result, intn func(n int) int) []string {
	if len(ranked) == 0 {
		return nil
	}
	limit := time.Duration(float64(ranked[0].Latency) * nearFastest)
	var near, rest []string
	for _, r := range ranked {
		if r.Latency <= limit {
			near = append(near, r.Host)
		} else {
			rest = append(rest, r.Host)
		}
	}
	out := make([]string, 0, len(ranked))
	for len(near) > 0 {
		i := intn(len(near))
		out = append(out, near[i])
		near = slices.Delete(near, i, i+1)
	}
	return append(out, rest...)
}

// Fastest checks every host at once and picks one of the usable sites whose handshake took at
// most nearFastest times the quickest one, at random. intn of nil uses math/rand.
func Fastest(ctx context.Context, hosts []string, check func(context.Context, string) Result, intn func(int) int) (string, bool) {
	if intn == nil {
		intn = rand.IntN
	}
	list := Shortlist(Rank(ctx, hosts, check), intn)
	if len(list) == 0 {
		return "", false
	}
	return list[0], true
}

// USWestCampuses are large US west-coast university sites that spoke TLS 1.3 and HTTP/2 when checked in November 2026.
var USWestCampuses = []string{
	"www.stanford.edu", "www.berkeley.edu", "www.ucla.edu", "www.caltech.edu", "www.usc.edu",
	"www.ucdavis.edu", "www.ucsb.edu", "www.ucsc.edu", "www.washington.edu", "www.oregonstate.edu",
	"www.uoregon.edu", "www.sfsu.edu", "www.calpoly.edu", "www.pdx.edu", "www.asu.edu",
	"www.arizona.edu", "www.unlv.edu",
}

// GlobalSites are worldwide sites, probed first wherever nothing regional answers.
// Every host below spoke TLS 1.3 and HTTP/2 with a valid certificate when checked in November 2026.
var GlobalSites = []string{"www.oracle.com", "www.python.org"}

// regionSites lists, per server region, large and long-lived local sites: universities, public bodies,
// carriers and shops. Checked in November 2026 like GlobalSites.
var regionSites = map[string][]string{
	"jp": {
		"www.kyoto-u.ac.jp", "www.kyushu-u.ac.jp", "www.nii.ac.jp", "www.ritsumei.ac.jp", "www.chiba-u.ac.jp", "www.hosei.ac.jp",
		"www.chuo-u.ac.jp", "www.jma.go.jp",
	},
	"kr": {
		"www.snu.ac.kr", "www.uos.ac.kr", "www.kbs.co.kr", "www.lguplus.com", "www.kyobobook.co.kr",
	},
	"hk": {
		"www.gov.hk", "www.hkpl.gov.hk", "hkust.edu.hk", "www.hku.hk", "www.cityu.edu.hk", "www.hkapa.edu",
		"www.clp.com.hk", "www.mtr.com.hk", "www.discoverhongkong.com",
	},
	"tw": {
		"www.ncku.edu.tw", "www.ncu.edu.tw", "www.ntust.edu.tw", "www.ntou.edu.tw", "www.yzu.edu.tw", "www.twnic.tw",
		"www.books.com.tw",
	},
	"sg": {
		"www.ntu.edu.sg", "www.smu.edu.sg", "www.suss.edu.sg", "www.sp.edu.sg", "www.nyp.edu.sg", "www.rp.edu.sg",
		"www.ite.edu.sg", "www.a-star.edu.sg", "www.gov.sg", "www.nlb.gov.sg", "www.changiairport.com", "www.sgix.sg",
	},
	"us": USWestCampuses,
	"eu": {
		"www.cam.ac.uk", "www.ed.ac.uk", "ethz.ch", "www.kit.edu", "www.tu-berlin.de", "www.tudelft.nl",
		"www.uva.nl", "www.helsinki.fi", "www.uio.no", "www.sorbonne-universite.fr", "www.polimi.it", "www.univie.ac.at",
	},
	// other has no list of its own: it draws on every list, see fallbackSites.
	"other": nil,
}

// regionOrder fixes the order fallbackSites walks regionSites in.
var regionOrder = []string{"jp", "kr", "hk", "tw", "sg", "us", "eu"}

// fallbackSites is what is probed when the region's own sites all fail, and all that is probed
// for "other": GlobalSites first, then every other region's sites. GlobalSites alone is too short
// to rely on, and for a server in a region without a list, the quickest of all known sites is
// the best guess at one nearby.
func fallbackSites(region string) []string {
	out := append([]string(nil), GlobalSites...)
	seen := map[string]bool{}
	for _, h := range out {
		seen[h] = true
	}
	for _, r := range regionOrder {
		if r == region {
			continue
		}
		for _, h := range regionSites[r] {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

var ErrUnknownRegion = errors.New("unknown region")

func KnownRegion(region string) bool {
	_, ok := regionSites[region]
	return ok
}

// CoverSite picks a usable site for the region this server is in, or "" if none answers: one of
// the region's sites within nearFastest of its quickest, at random, else one of the fallback's
// the same way. An empty region keeps to USWestCampuses; any other falls back to fallbackSites.
func (p *Prober) CoverSite(ctx context.Context, region string) (string, error) {
	list, err := candidates(ctx, region, p.Check, p.Rand)
	if err != nil || len(list) == 0 {
		return "", err
	}
	return list[0], nil
}

// candidates lists every usable site for region in the order CoverSite prefers them: the
// region's own Shortlist, then the fallback's.
func candidates(ctx context.Context, region string, check func(context.Context, string) Result, intn func(int) int) ([]string, error) {
	if intn == nil {
		intn = rand.IntN
	}
	if region == "" {
		return Shortlist(Rank(ctx, USWestCampuses, check), intn), nil
	}
	sites, ok := regionSites[region]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownRegion, region)
	}
	// The fallback is probed alongside so that a dead region costs one timeout, not two.
	var fallback []Result
	var wg sync.WaitGroup
	wg.Go(func() { fallback = Rank(ctx, fallbackSites(region), check) })
	local := Rank(ctx, sites, check)
	wg.Wait()
	return append(Shortlist(local, intn), Shortlist(fallback, intn)...), nil
}
