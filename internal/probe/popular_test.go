package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPopularDest(t *testing.T) {
	tests := []struct{ host, want string }{
		{"www.microsoft.com", "Microsoft"},
		{"login.live.com", "Microsoft"},
		{"www.apple.com", "Apple"},
		{"www.apple.com.cn", "Apple"},
		{"swdist.apple.com", "Apple"},
		{"*.icloud.com", "Apple"},
		{"www.cloudflare.com", "Cloudflare"},
		{"one.one.one.one", "Cloudflare"},
		{"sni.cloudflaressl.com", "Cloudflare"},
		{"blog.example.workers.dev", "Cloudflare"},
		{"www.lovelive-anime.jp", "lovelive-anime.jp"},
		{"lovelive-anime.jp.", "lovelive-anime.jp"},
		{"www.speedtest.net", "Speedtest"},
		{"discord.com", "Discord"},
		{"cdn.discordapp.com", "Discord"},
		{"WWW.MICROSOFT.COM", "Microsoft"},
		{"www.applebees.com", ""},
		{"notlive.com", ""},
		{"www.stanford.edu", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := PopularDest(tt.host); got != tt.want {
			t.Errorf("PopularDest(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestCheckRejectsAPopularDestWithoutConnecting(t *testing.T) {
	p := &Prober{Address: func(host string) string {
		t.Errorf("dialled %s, which the name alone rules out", host)
		return "127.0.0.1:1"
	}}
	got := p.Check(context.Background(), "www.microsoft.com")
	if got.OK || !strings.Contains(got.Problem, "Microsoft") {
		t.Fatalf("Check = %+v, want a failure naming Microsoft", got)
	}
}

type certOpts struct {
	names     []string
	org       string
	notBefore time.Time
	notAfter  time.Time
}

// newCert makes a self-signed certificate; being its own issuer, org is also the issuer's organisation.
func newCert(t *testing.T, o certOpts) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.names[0], Organization: []string{o.org}},
		DNSNames:              o.names,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// startCertSite serves h (404 everywhere when nil) over TLS 1.3 and HTTP/2 with cert, trusting
// leaf; cfg may adjust the server's TLS config.
func startCertSite(t *testing.T, cert tls.Certificate, leaf *x509.Certificate, h http.Handler, cfg func(*tls.Config)) *Prober {
	t.Helper()
	if h == nil {
		h = http.NotFoundHandler()
	}
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	if cfg != nil {
		cfg(srv.TLS)
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	addr := srv.Listener.Addr().String()
	return &Prober{RootCAs: pool, Address: func(string) string { return addr }, Timeout: 5 * time.Second}
}

func TestCheckRejectsACertificateThatGivesAPopularDestAway(t *testing.T) {
	tests := []struct {
		name  string
		opts  certOpts
		brand string
	}{
		{"a name on the certificate", certOpts{names: []string{"cover.test", "sni.cloudflaressl.com"}}, "Cloudflare"},
		{"Cloudflare as the issuer", certOpts{names: []string{"cover.test"}, org: "Cloudflare, Inc."}, "Cloudflare"},
		{"an Apple name", certOpts{names: []string{"cover.test", "*.apple.com"}}, "Apple"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, leaf := newCert(t, tt.opts)
			p := startCertSite(t, cert, leaf, nil, nil)
			got := p.Check(context.Background(), "cover.test")
			if got.OK || !strings.Contains(got.Problem, tt.brand) {
				t.Fatalf("Check = %+v, want a failure naming %s", got, tt.brand)
			}
		})
	}

	cert, leaf := newCert(t, certOpts{names: []string{"cover.test"}, org: "Example Trust"})
	if got := startCertSite(t, cert, leaf, nil, nil).Check(context.Background(), "cover.test"); !got.OK {
		t.Fatalf("Check = %+v, want an ordinary certificate to pass", got)
	}
}
