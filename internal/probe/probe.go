// Package probe checks whether a website can serve as a REALITY cover site, and how close it is.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// NearestCampus returns the campus site with the quickest handshake from this machine, or "" if none answers.
func (p *Prober) NearestCampus(ctx context.Context) string {
	site, _ := Fastest(ctx, USWestCampuses, p.Check)
	return site
}
