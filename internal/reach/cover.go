package reach

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	// CoverProbes is how many mainland probes judge a candidate cover site. A check runs three
	// measurements on the same probes, so it costs three times this many tests.
	CoverProbes = 3
	// CoverBudget is how many tests cover-site checks may spend in any hour. The loop keeps to
	// ScheduledBudget and a manual round costs at most MaxMeasurements*ProbesPerMeasurement (96),
	// so this still leaves room inside HourlyLimit for both: the line checks never go short.
	CoverBudget = 30
	// CoverTTL is how long a verdict about a site is reused before it is checked again.
	CoverTTL = 3 * 24 * time.Hour
)

// CoverCost is how many tests one cover-site check spends at most.
func CoverCost() int { return 3 * CoverProbes }

// CoverVerdict is what mainland probes concluded about a candidate cover site.
type CoverVerdict struct {
	OK bool `json:"ok"`
	// Problem says why the site was turned down; empty when OK.
	Problem string `json:"problem,omitempty"`
}

// CoverChecker checks a candidate cover site from mainland China; *Client is the real one.
type CoverChecker interface {
	CheckCover(ctx context.Context, host string) (CoverVerdict, error)
}

// ErrNoCoverData means no mainland probe returned anything to judge the site by.
var ErrNoCoverData = errors.New("reach: no mainland probe could check the site")

type dnsOptions struct {
	Query struct {
		Type string `json:"type"`
	} `json:"query"`
}

type httpOptions struct {
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"request"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type dnsMeasurement struct {
	Results []struct {
		Result struct {
			Status  string `json:"status"`
			Answers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"answers"`
		} `json:"result"`
	} `json:"results"`
}

type httpMeasurement struct {
	Results []struct {
		Result struct {
			Status        string `json:"status"`
			FailureSource string `json:"failureSource"`
			TLS           *struct {
				Protocol string `json:"protocol"`
			} `json:"tls"`
		} `json:"result"`
	} `json:"results"`
}

// CheckCover asks CoverProbes mainland probes about host, and turns it down when:
//   - their resolvers answer with an address in mainland China: the site serves mainland users
//     from inside, so a server abroad claiming its name stands out;
//   - most of them cannot load it over HTTPS: a blocked site makes a conspicuous cover;
//   - most that can do not get TLS 1.3.
//
// The AAAA and HTTP measurements reuse the A lookup's probes. HTTP is skipped when either DNS
// lookup turns the site down.
func (c *Client) CheckCover(ctx context.Context, host string) (CoverVerdict, error) {
	dnsCtx, cancel := context.WithTimeout(ctx, c.Deadline)
	defer cancel()
	var dnsOpts dnsOptions
	dnsOpts.Query.Type = "A"
	id, err := c.start(dnsCtx, createRequest{
		Type: "dns", Target: host,
		Locations: []location{{Country: mainland, Limit: CoverProbes}}, Options: dnsOpts,
	})
	if err != nil {
		return CoverVerdict{}, err
	}
	var dm dnsMeasurement
	if err := c.await(dnsCtx, id, &dm); err != nil {
		return CoverVerdict{}, err
	}
	if v := judgeDNS(dm); !v.OK {
		return v, nil
	}

	var aaaaOpts dnsOptions
	aaaaOpts.Query.Type = "AAAA"
	aaaaID, err := c.start(dnsCtx, createRequest{Type: "dns", Target: host, Locations: id, Options: aaaaOpts})
	if err != nil {
		return CoverVerdict{}, err
	}
	var aaaa dnsMeasurement
	if err := c.await(dnsCtx, aaaaID, &aaaa); err != nil {
		return CoverVerdict{}, err
	}
	if v := judgeDNS(aaaa); !v.OK {
		return v, nil
	}

	httpCtx, cancel := context.WithTimeout(ctx, c.Deadline)
	defer cancel()
	var httpOpts httpOptions
	httpOpts.Request.Method, httpOpts.Request.Path = "HEAD", "/"
	httpOpts.Protocol, httpOpts.Port = "HTTPS", 443
	hid, err := c.start(httpCtx, createRequest{Type: "http", Target: host, Locations: id, Options: httpOpts})
	if err != nil {
		return CoverVerdict{}, err
	}
	var hm httpMeasurement
	if err := c.await(httpCtx, hid, &hm); err != nil {
		return CoverVerdict{}, err
	}
	return judgeHTTP(hm)
}

// judgeDNS turns the site down when any mainland resolver answered with a mainland address.
func judgeDNS(m dnsMeasurement) CoverVerdict {
	for _, r := range m.Results {
		if r.Result.Status != "finished" {
			continue
		}
		for _, a := range r.Result.Answers {
			if a.Type != "A" && a.Type != "AAAA" {
				continue
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(a.Value))
			if err == nil && InMainland(ip) {
				return CoverVerdict{Problem: fmt.Sprintf("resolves to %s, a mainland China address, from mainland probes", ip)}
			}
		}
	}
	return CoverVerdict{OK: true}
}

// judgeHTTP turns the site down when most probes with a result could not load it, or when most
// that could did not get TLS 1.3. A probe that broke on its own side says nothing.
func judgeHTTP(m httpMeasurement) (CoverVerdict, error) {
	var reached, unreached, tls13 int
	other := ""
	for _, r := range m.Results {
		switch {
		case r.Result.Status == "finished":
			reached++
			if r.Result.TLS != nil && r.Result.TLS.Protocol == "TLSv1.3" {
				tls13++
			} else if r.Result.TLS != nil && other == "" {
				other = r.Result.TLS.Protocol
			}
		case r.Result.Status == "failed" && r.Result.FailureSource == "target":
			unreached++
		}
	}
	switch {
	case reached+unreached == 0:
		return CoverVerdict{}, ErrNoCoverData
	case unreached > reached:
		return CoverVerdict{Problem: fmt.Sprintf("cannot be loaded from mainland China (%d of %d probes failed)", unreached, reached+unreached)}, nil
	case tls13*2 < reached:
		if other == "" {
			other = "no TLS"
		}
		return CoverVerdict{Problem: fmt.Sprintf("mainland probes do not get TLS 1.3 (got %s)", other)}, nil
	}
	return CoverVerdict{OK: true}, nil
}

// CoverEntry is a remembered verdict.
type CoverEntry struct {
	CoverVerdict
	CheckedAt time.Time `json:"checkedAt"`
}

// CoverCache remembers verdicts about cover sites and what checking them spent. It is persisted
// as one JSON value.
type CoverCache struct {
	Sites map[string]CoverEntry `json:"sites,omitempty"`
	// Spent holds when each check of the last hour started; each cost up to CoverCost tests.
	Spent []time.Time `json:"spent,omitempty"`
	// RetryAt is set after a rate-limit refusal: no check before it.
	RetryAt time.Time `json:"retryAt,omitzero"`
}

// Lookup returns the verdict about host, if one younger than CoverTTL is remembered.
func (c CoverCache) Lookup(host string, now time.Time) (CoverVerdict, bool) {
	e, ok := c.Sites[strings.ToLower(host)]
	if !ok || now.Sub(e.CheckedAt) >= CoverTTL || now.Before(e.CheckedAt) {
		return CoverVerdict{}, false
	}
	return e.CoverVerdict, true
}

// CanCheck reports whether one more check fits in CoverBudget now.
func (c CoverCache) CanCheck(now time.Time) bool {
	if now.Before(c.RetryAt) {
		return false
	}
	recent := 0
	for _, t := range c.Spent {
		if now.Sub(t) < time.Hour && !now.Before(t) {
			recent++
		}
	}
	return (recent+1)*CoverCost() <= CoverBudget
}

// prune forgets verdicts past CoverTTL and spending older than an hour.
func (c *CoverCache) prune(now time.Time) {
	for h, e := range c.Sites {
		if now.Sub(e.CheckedAt) >= CoverTTL {
			delete(c.Sites, h)
		}
	}
	kept := c.Spent[:0]
	for _, t := range c.Spent {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	c.Spent = kept
}

// VetCover says what mainland probes make of host: a remembered verdict when there is a fresh
// one, else a new check when mayCheck allows one and CoverBudget has room. known is false when
// there is no verdict and none could be had now; checked is whether a check was started. err
// says why a started check gave no verdict. The cache is updated in place.
func VetCover(ctx context.Context, cc CoverChecker, cache *CoverCache, host string, mayCheck bool, now time.Time) (v CoverVerdict, known, checked bool, err error) {
	cache.prune(now)
	if v, ok := cache.Lookup(host, now); ok {
		return v, true, false, nil
	}
	if !mayCheck || !cache.CanCheck(now) {
		return CoverVerdict{}, false, false, nil
	}
	cache.Spent = append(cache.Spent, now)
	v, err = cc.CheckCover(ctx, host)
	if err != nil {
		var limited *RateLimitError
		if errors.As(err, &limited) {
			cache.RetryAt = now.Add(max(limited.Reset, time.Minute))
		}
		return CoverVerdict{}, false, true, err
	}
	if cache.Sites == nil {
		cache.Sites = map[string]CoverEntry{}
	}
	cache.Sites[strings.ToLower(host)] = CoverEntry{CoverVerdict: v, CheckedAt: now}
	return v, true, true, nil
}
