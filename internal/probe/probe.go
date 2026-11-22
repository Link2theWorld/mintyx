// Package probe checks whether a website can serve as a REALITY cover site, and how close it is.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
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
	Timeout time.Duration
}

// Check does one TLS handshake with host. REALITY needs a cover site that speaks TLS 1.3 and HTTP/2.
func (p *Prober) Check(ctx context.Context, host string) Result {
	res := Result{Host: host}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, "443")
	if p.Address != nil {
		addr = p.Address(host)
	}
	dialer := &tls.Dialer{Config: &tls.Config{
		ServerName: host,
		RootCAs:    p.RootCAs,
		NextProtos: []string{"h2", "http/1.1"},
	}}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Problem = err.Error()
		return res
	}
	defer conn.Close()
	res.Latency = time.Since(start)

	state := conn.(*tls.Conn).ConnectionState()
	switch {
	case state.Version != tls.VersionTLS13:
		res.Problem = "does not support TLS 1.3"
	case state.NegotiatedProtocol != "h2":
		res.Problem = "does not support HTTP/2"
	default:
		res.OK = true
	}
	return res
}

// Fastest checks every host at once and returns the usable one with the quickest handshake.
func Fastest(ctx context.Context, hosts []string, check func(context.Context, string) Result) (string, bool) {
	results := make([]Result, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Go(func() { results[i] = check(ctx, host) })
	}
	wg.Wait()

	best := -1
	for i, r := range results {
		if r.OK && (best < 0 || r.Latency < results[best].Latency) {
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	return hosts[best], true
}

// USWestCampuses are large US west-coast university sites that spoke TLS 1.3 and HTTP/2 when checked in November 2026.
var USWestCampuses = []string{
	"www.stanford.edu", "www.berkeley.edu", "www.ucla.edu", "www.caltech.edu", "www.usc.edu",
	"www.ucdavis.edu", "www.ucsb.edu", "www.ucsc.edu", "www.washington.edu", "www.oregonstate.edu",
	"www.uoregon.edu", "www.sfsu.edu", "www.calpoly.edu", "www.pdx.edu", "www.asu.edu",
	"www.arizona.edu", "www.unlv.edu",
}

// GlobalSites are worldwide vendor sites, the fallback wherever nothing regional answers.
// Every host below spoke TLS 1.3 and HTTP/2 with a valid certificate when checked in November 2026.
var GlobalSites = []string{
	"www.amazon.com", "aws.amazon.com", "www.nvidia.com", "www.amd.com", "www.intel.com", "www.oracle.com",
	"www.cisco.com", "www.dell.com", "www.samsung.com", "www.adobe.com", "www.tesla.com", "www.python.org",
}

// regionSites lists, per server region, large and long-lived local sites: universities, public bodies,
// carriers and shops. Checked in November 2026 like GlobalSites.
var regionSites = map[string][]string{
	"jp": {
		"www.kyoto-u.ac.jp", "www.kyushu-u.ac.jp", "www.nii.ac.jp", "www.ritsumei.ac.jp", "www.chiba-u.ac.jp", "www.hosei.ac.jp",
		"www.chuo-u.ac.jp", "www.jma.go.jp", "www.lawson.co.jp", "www.biglobe.ne.jp", "www.nifty.com", "www.itmedia.co.jp",
	},
	"kr": {
		"www.snu.ac.kr", "www.uos.ac.kr", "www.kbs.co.kr", "www.nexon.com", "www.gmarket.co.kr", "www.auction.co.kr",
		"www.lguplus.com", "www.hyundai.com", "www.kia.com", "www.kyobobook.co.kr",
	},
	"hk": {
		"www.gov.hk", "www.hkpl.gov.hk", "hkust.edu.hk", "www.hku.hk", "www.cityu.edu.hk", "www.hkapa.edu",
		"www.clp.com.hk", "www.mtr.com.hk", "www.discoverhongkong.com", "www.hsbc.com.hk", "www.hangseng.com",
	},
	"tw": {
		"www.ncku.edu.tw", "www.ncu.edu.tw", "www.ntust.edu.tw", "www.ntou.edu.tw", "www.yzu.edu.tw", "www.twnic.tw",
		"www.pchome.com.tw", "www.books.com.tw", "www.tsmc.com", "www.synology.com", "www.advantech.com", "www.asus.com",
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
	"other": GlobalSites,
}

var ErrUnknownRegion = errors.New("unknown region")

func KnownRegion(region string) bool {
	_, ok := regionSites[region]
	return ok
}

// CoverSite returns the quickest usable site for the region this server is in, or "" if none answers.
// An empty region keeps to USWestCampuses; any other falls back to GlobalSites.
func (p *Prober) CoverSite(ctx context.Context, region string) (string, error) {
	return coverSite(ctx, region, p.Check)
}

func coverSite(ctx context.Context, region string, check func(context.Context, string) Result) (string, error) {
	if region == "" {
		site, _ := Fastest(ctx, USWestCampuses, check)
		return site, nil
	}
	sites, ok := regionSites[region]
	if !ok {
		return "", fmt.Errorf("%w %q", ErrUnknownRegion, region)
	}
	// The fallback is probed alongside so that a dead region costs one timeout, not two.
	var fallback string
	var wg sync.WaitGroup
	if region != "other" {
		wg.Go(func() { fallback, _ = Fastest(ctx, GlobalSites, check) })
	}
	site, ok := Fastest(ctx, sites, check)
	wg.Wait()
	if ok {
		return site, nil
	}
	return fallback, nil
}
