package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckWantsX25519(t *testing.T) {
	cert, leaf := newCert(t, certOpts{names: []string{"cover.test"}})
	p := startCertSite(t, cert, leaf, nil, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256} })
	got := p.Check(context.Background(), "cover.test")
	if got.OK || !strings.Contains(got.Problem, "X25519") {
		t.Fatalf("Check = %+v, want a failure: the server only does P-256", got)
	}

	p = startCertSite(t, cert, leaf, nil, func(c *tls.Config) { c.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.X25519} })
	if got := p.Check(context.Background(), "cover.test"); !got.OK {
		t.Fatalf("Check = %+v, want a pass: the server accepts the X25519 key share it was offered", got)
	}
}

func TestCheckWantsAValidCertificateForTheName(t *testing.T) {
	valid, validLeaf := newCert(t, certOpts{names: []string{"cover.test"}})
	expired, expiredLeaf := newCert(t, certOpts{
		names: []string{"cover.test"}, notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-24 * time.Hour),
	})
	tests := []struct {
		name    string
		cert    tls.Certificate
		trusted *x509.Certificate
		host    string
		want    string
	}{
		{"expired", expired, expiredLeaf, "cover.test", "expired"},
		{"for another name", valid, validLeaf, "other.test", "does not cover other.test"},
		{"from an unknown issuer", valid, nil, "cover.test", "trusted authority"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := startCertSite(t, tt.cert, validLeaf, nil, nil)
			if tt.trusted != nil {
				p.RootCAs = x509.NewCertPool()
				p.RootCAs.AddCert(tt.trusted)
			} else {
				p.RootCAs = x509.NewCertPool() // trusts nothing
			}
			got := p.Check(context.Background(), tt.host)
			if got.OK || !strings.Contains(got.Problem, tt.want) {
				t.Fatalf("Check = %+v, want a failure mentioning %q", got, tt.want)
			}
		})
	}
}

func TestCheckRefusesAHomepageThatRedirects(t *testing.T) {
	cert, leaf := newCert(t, certOpts{names: []string{"cover.test"}})
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.Redirect(w, r, "https://elsewhere.test/en/", code)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		got := startCertSite(t, cert, leaf, h, nil).Check(context.Background(), "cover.test")
		if got.OK || !strings.Contains(got.Problem, "redirects") || !strings.Contains(got.Problem, "elsewhere.test") {
			t.Fatalf("Check with a %d homepage = %+v, want a failure naming where it redirects", code, got)
		}
	}

	// Anything but a redirect is how the real site answers, and is fine to imitate.
	for _, code := range []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound} {
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
		if got := startCertSite(t, cert, leaf, h, nil).Check(context.Background(), "cover.test"); !got.OK {
			t.Fatalf("Check with a %d homepage = %+v, want a pass", code, got)
		}
	}
}

func TestCheckRefusesASiteServedByCloudflare(t *testing.T) {
	cert, leaf := newCert(t, certOpts{names: []string{"cover.test"}})
	for name, header := range map[string][2]string{
		"server header": {"Server", "cloudflare"},
		"ray id":        {"CF-RAY", "8f1c2d3e4a5b6c7d-NRT"},
	} {
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(header[0], header[1])
			w.WriteHeader(http.StatusOK)
		})
		got := startCertSite(t, cert, leaf, h, nil).Check(context.Background(), "cover.test")
		if got.OK || !strings.Contains(got.Problem, "Cloudflare") {
			t.Fatalf("%s: Check = %+v, want a failure naming Cloudflare", name, got)
		}
	}
}

func TestCheckAsksForTheHomepageOverTheProbedConnection(t *testing.T) {
	cert, leaf := newCert(t, certOpts{names: []string{"cover.test"}})
	var conns atomic.Int32
	var proto, host atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto.Store(r.Proto)
		host.Store(r.Host)
		w.WriteHeader(http.StatusOK)
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	addr := srv.Listener.Addr().String()
	p := &Prober{RootCAs: pool, Address: func(string) string { return addr }, Timeout: 5 * time.Second}

	if got := p.Check(context.Background(), "cover.test"); !got.OK {
		t.Fatalf("Check = %+v, want a pass", got)
	}
	if n := conns.Load(); n != 1 {
		t.Fatalf("server saw %d connections, want 1: the homepage must come over the probed one", n)
	}
	if proto.Load() != "HTTP/2.0" || host.Load() != "cover.test" {
		t.Fatalf("homepage request was %v for %v, want HTTP/2.0 for cover.test", proto.Load(), host.Load())
	}
}
