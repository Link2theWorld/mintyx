package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
