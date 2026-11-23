package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startSite(t *testing.T, h2 bool, maxVersion uint16) (*Prober, string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.EnableHTTP2 = h2
	srv.TLS = &tls.Config{MaxVersion: maxVersion}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	// httptest's certificate is issued for example.com, so that is the name being probed.
	return &Prober{RootCAs: pool, Address: func(string) string { return addr }, Timeout: 5 * time.Second}, "example.com"
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name        string
		h2          bool
		maxVersion  uint16
		wantOK      bool
		wantProblem string
	}{
		{"TLS 1.3 with HTTP/2 is usable", true, tls.VersionTLS13, true, ""},
		{"TLS 1.2 only is rejected", true, tls.VersionTLS12, false, "TLS 1.3"},
		{"no HTTP/2 is rejected", false, tls.VersionTLS13, false, "HTTP/2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, host := startSite(t, tt.h2, tt.maxVersion)
			got := p.Check(context.Background(), host)
			if got.OK != tt.wantOK || !strings.Contains(got.Problem, tt.wantProblem) {
				t.Fatalf("Check = %+v, want OK=%v with problem mentioning %q", got, tt.wantOK, tt.wantProblem)
			}
			if tt.wantOK && got.Latency <= 0 {
				t.Fatalf("Latency = %v, want a measured handshake time", got.Latency)
			}
		})
	}
}

func TestCheckRejectsACertificateForAnotherName(t *testing.T) {
	p, _ := startSite(t, true, tls.VersionTLS13)
	got := p.Check(context.Background(), "not-the-cert-name.test")
	if got.OK || got.Problem == "" {
		t.Fatalf("Check = %+v, want a failure: a site that does not own the name cannot be imitated", got)
	}
}

func TestFastest(t *testing.T) {
	results := map[string]Result{
		"slow.test":   {OK: true, Latency: 90 * time.Millisecond},
		"fast.test":   {OK: true, Latency: 12 * time.Millisecond},
		"broken.test": {OK: false, Latency: time.Millisecond, Problem: "no TLS 1.3"},
	}
	check := func(_ context.Context, host string) Result { return results[host] }

	got, ok := Fastest(context.Background(), []string{"slow.test", "broken.test", "fast.test"}, check)
	if !ok || got != "fast.test" {
		t.Fatalf("Fastest = %q, %v; want fast.test: the quickest usable site, not the quickest reply", got, ok)
	}
	if got, ok := Fastest(context.Background(), []string{"broken.test"}, check); ok {
		t.Fatalf("Fastest = %q, true with no usable site; want false", got)
	}
}

func TestCoverSite(t *testing.T) {
	regional, campus, global, neighbour := regionSites["jp"][1], USWestCampuses[0], GlobalSites[1], regionSites["kr"][0]
	usable := func(hosts map[string]time.Duration) func(context.Context, string) Result {
		return func(_ context.Context, host string) Result {
			latency, ok := hosts[host]
			return Result{Host: host, OK: ok, Latency: latency}
		}
	}
	tests := []struct {
		name   string
		region string
		hosts  map[string]time.Duration
		want   string
	}{
		{"a regional site wins over a quicker global one", "jp",
			map[string]time.Duration{regional: 80 * time.Millisecond, global: 5 * time.Millisecond}, regional},
		{"no usable regional site falls back to the global list", "jp",
			map[string]time.Duration{global: 5 * time.Millisecond}, global},
		{"the fallback also draws on other regions' sites", "jp",
			map[string]time.Duration{global: 50 * time.Millisecond, neighbour: 5 * time.Millisecond}, neighbour},
		{"other probes every known site", "other",
			map[string]time.Duration{global: 50 * time.Millisecond, regionSites["eu"][3]: 5 * time.Millisecond}, regionSites["eu"][3]},
		{"other with nothing usable suggests nothing", "other", nil, ""},
		{"nothing usable suggests nothing", "jp", nil, ""},
		{"no region keeps to the campus list", "",
			map[string]time.Duration{campus: 40 * time.Millisecond, global: 5 * time.Millisecond}, campus},
		{"no region does not fall back to the global list", "",
			map[string]time.Duration{global: 5 * time.Millisecond}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := coverSite(context.Background(), tt.region, usable(tt.hosts))
			if err != nil || got != tt.want {
				t.Fatalf("coverSite(%q) = %q, %v; want %q", tt.region, got, err, tt.want)
			}
		})
	}
}

func TestCoverSiteRejectsAnUnknownRegionWithoutProbing(t *testing.T) {
	check := func(_ context.Context, host string) Result {
		t.Errorf("probed %s for a region that does not exist", host)
		return Result{Host: host}
	}
	got, err := coverSite(context.Background(), "mars", check)
	if got != "" || !errors.Is(err, ErrUnknownRegion) {
		t.Fatalf("coverSite(mars) = %q, %v; want ErrUnknownRegion so the API can name the bad field", got, err)
	}
}

func TestFallbackSitesListEachKnownSiteOnce(t *testing.T) {
	got := fallbackSites("jp")
	if len(got) < 2 || got[0] != GlobalSites[0] || got[1] != GlobalSites[1] {
		t.Fatalf("fallbackSites(jp) = %v, want GlobalSites first", got)
	}
	seen := map[string]bool{}
	for _, h := range got {
		if seen[h] {
			t.Fatalf("fallbackSites(jp) lists %s twice", h)
		}
		seen[h] = true
	}
	for _, h := range regionSites["jp"] {
		if seen[h] {
			t.Fatalf("fallbackSites(jp) repeats the region's own site %s", h)
		}
	}
	for _, h := range regionSites["eu"] {
		if !seen[h] {
			t.Fatalf("fallbackSites(jp) misses %s", h)
		}
	}
}

// droppedSites were taken off the lists in November 2026 (Link2theWorld/mintyx#1). They must not
// come back without being checked again.
var droppedSites = []string{
	"www.adobe.com", "www.dell.com", "www.samsung.com", "www.intel.com", "aws.amazon.com",
	"www.nvidia.com", "www.tesla.com", "www.amd.com", "www.cisco.com", "www.amazon.com",
	"www.lawson.co.jp", "www.nifty.com", "www.biglobe.ne.jp", "www.itmedia.co.jp",
	"www.nexon.com", "www.gmarket.co.kr", "www.auction.co.kr", "www.hyundai.com", "www.kia.com",
	"www.tsmc.com", "www.asus.com", "www.advantech.com", "www.synology.com", "www.pchome.com.tw",
	"www.hsbc.com.hk", "www.hangseng.com",
}

func TestSiteListsLeaveOutDroppedAndPopularSites(t *testing.T) {
	dropped := map[string]bool{}
	for _, h := range droppedSites {
		dropped[h] = true
	}
	for _, h := range fallbackSites("other") {
		if dropped[h] {
			t.Errorf("%s is listed again", h)
		}
		if brand := PopularDest(h); brand != "" {
			t.Errorf("%s is listed but is a popular cover site (%s)", h, brand)
		}
	}
}
