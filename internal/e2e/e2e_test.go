// Package e2e drives real Xray and mihomo binaries through configs built by engine and share.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/engine"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/share"
	"gopkg.in/yaml.v3"
)

const (
	// publicURL is an IP literal: a fake-ip resolver on the test host (TUN proxies) maps names into
	// 198.18.0.0/15, which the server rightly blocks. publicName exercises the name path when DNS is real.
	publicURL    = "https://1.1.1.1/cdn-cgi/trace"
	publicStatus = http.StatusOK
	publicName   = "www.gstatic.com"
	publicByName = "http://" + publicName + "/generate_204"

	// realitySite is the REALITY target and SNI, a large TLS 1.3 site that offers X25519MLKEM768.
	realitySite = "www.apple.com"

	certDomain = "edge.mintyx.test"
	dialHost   = "127.0.0.1"
)

// clients returns the one client the server knows and one it does not, with secrets of the given shape.
func clients(newSecret func() string) (good, wrong model.Client) {
	good = model.Client{ID: 1, Name: "good", Secret: newSecret(), SubToken: "good"}
	wrong = model.Client{ID: 2, Name: "wrong", Secret: newSecret(), SubToken: "wrong"}
	return good, wrong
}

var (
	internetOnce sync.Once
	internetErr  error
)

func xrayBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN not set")
	}
	return bin
}

// requireInternet fails with a plain "no internet" message so an offline machine is not read as a product bug.
func requireInternet(t *testing.T) {
	t.Helper()
	internetOnce.Do(func() {
		c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
		resp, err := c.Get(publicURL)
		if err != nil {
			internetErr = err
			return
		}
		resp.Body.Close()
		if resp.StatusCode != publicStatus {
			internetErr = fmt.Errorf("status %d, want %d", resp.StatusCode, publicStatus)
		}
	})
	if internetErr != nil {
		t.Fatalf("NO INTERNET (not a product bug): direct GET %s without any proxy failed: %v", publicURL, internetErr)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		// The API inbound needs the same number free on TCP only if they collide; keep them apart.
		if l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			l.Close()
			return port
		}
	}
	t.Fatal("no free UDP port")
	return 0
}

type certFiles struct {
	certFile, keyFile string
	certPEM           []byte
	tls               tls.Certificate
}

// selfSignedCert makes a CA-flagged self-signed cert for certDomain so clients can trust it directly.
func selfSignedCert(t *testing.T) certFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: certDomain},
		DNSNames:              []string{certDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	cf := certFiles{certFile: filepath.Join(dir, "cert.pem"), keyFile: filepath.Join(dir, "key.pem"), certPEM: certPEM}
	if err := os.WriteFile(cf.certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cf.keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cf.tls, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cf
}

type server struct {
	sup     *engine.Supervisor
	apiAddr string
}

// startServer runs the product's own config for line and good under the product's supervisor.
func startServer(t *testing.T, line model.Line, good model.Client) *server {
	t.Helper()
	return startServerWith(t, []model.Line{line}, []model.Client{good}, nil)
}

// startServerWith runs the product's config for several lines, clients and exits.
func startServerWith(t *testing.T, lines []model.Line, cl []model.Client, exits []model.Exit) *server {
	t.Helper()
	bin := xrayBin(t)
	opt := engine.Options{APIPort: freeTCPPort(t), LogLevel: "info"}
	cfg, err := engine.BuildConfig(lines, cl, exits, opt)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := engine.Validate(ctx, bin, cfg); err != nil {
		t.Fatalf("Validate: %v\nconfig:\n%s", err, cfg)
	}
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	sup := engine.NewSupervisor(bin, path, engine.SupervisorOptions{StopTimeout: 3 * time.Second})
	if err := sup.Start(); err != nil {
		t.Fatalf("supervisor start: %v", err)
	}
	t.Cleanup(func() {
		sup.Stop()
		if t.Failed() {
			t.Logf("server config:\n%s", cfg)
			t.Logf("server log:\n%s", strings.Join(sup.Logs(), "\n"))
		}
	})
	s := &server{sup: sup, apiAddr: opt.APIAddr()}
	waitTCP(t, s.apiAddr, "server API inbound", func() string { return strings.Join(sup.Logs(), "\n") })
	return s
}

func waitTCP(t *testing.T, addr, what string, logs func() string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never listened on %s; log:\n%s", what, addr, logs())
}

// syncBuffer collects a child's output; exec writes to it from its own goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startChild runs a client binary and kills and reaps it at test end, failed or not.
func startChild(t *testing.T, name string, args ...string) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s %v output:\n%s", filepath.Base(name), args, out.String())
		}
	})
	return out
}

func writeJSON(t *testing.T, name string, v any) (string, []byte) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// startMihomo runs mihomo on the product's mihomo subscription for c, adding only a local mixed port.
// trustPEM, when set, is the self-signed server cert the proxy pins by fingerprint (a test-only concern).
func startMihomo(t *testing.T, line model.Line, c model.Client, trustPEM []byte) string {
	t.Helper()
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("MIHOMO_BIN not set")
	}
	body, _, err := share.Render(share.FormatMihomo, []model.Line{line}, nil, c, dialHost)
	if err != nil {
		t.Fatalf("share.Render mihomo: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("share.Render produced invalid YAML: %v\n%s", err, body)
	}
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 1 {
		t.Fatalf("want exactly one proxy, got:\n%s", body)
	}
	if trustPEM != nil {
		proxies[0].(map[string]any)["fingerprint"] = certFingerprint(t, trustPEM)
	}
	port := freeTCPPort(t)
	doc["mixed-port"] = port
	doc["bind-address"] = dialHost
	doc["allow-lan"] = false
	doc["log-level"] = "warning"
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out := startChild(t, bin, "-d", dir, "-f", path)
	addr := net.JoinHostPort(dialHost, strconv.Itoa(port))
	waitTCP(t, addr, "mihomo mixed port", func() string { return out.String() + "\nconfig:\n" + string(data) })
	return addr
}

// certFingerprint is the SHA-256 of the certificate's DER, which mihomo's fingerprint field pins.
func certFingerprint(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("trust certificate is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func mihomoClient(trustPEM []byte) func(*testing.T, model.Line, model.Client) string {
	return func(t *testing.T, l model.Line, c model.Client) string {
		return startMihomo(t, l, c, trustPEM)
	}
}

// xrayOutboundFromLink maps a vless:// share URI to an Xray client outbound, parameter by parameter.
func xrayOutboundFromLink(t *testing.T, link string, trustPEM []byte) map[string]any {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("share link does not parse: %v\n%s", err, link)
	}
	if u.Scheme != "vless" {
		t.Fatalf("scheme %q, want vless: %s", u.Scheme, link)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("share link port: %v\n%s", err, link)
	}
	q := u.Query()
	stream := map[string]any{"network": q.Get("type"), "security": q.Get("security")}
	switch q.Get("type") {
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"host": q.Get("host"), "path": q.Get("path")}
	case "tcp":
	default:
		t.Fatalf("unsupported type %q in %s", q.Get("type"), link)
	}
	user := map[string]any{"id": u.User.Username(), "encryption": q.Get("encryption")}
	if flow := q.Get("flow"); flow != "" {
		user["flow"] = flow
	}
	switch q.Get("security") {
	case "reality":
		stream["realitySettings"] = map[string]any{
			"serverName": q.Get("sni"), "fingerprint": q.Get("fp"),
			"password": q.Get("pbk"), "shortId": q.Get("sid"),
		}
	case "tls":
		tlsObj := map[string]any{"serverName": q.Get("sni"), "fingerprint": q.Get("fp")}
		if trustPEM != nil {
			tlsObj["certificates"] = []any{map[string]any{
				"usage":       "verify",
				"certificate": strings.Split(strings.TrimSpace(string(trustPEM)), "\n"),
			}}
		}
		stream["tlsSettings"] = tlsObj
	case "none", "":
	default:
		t.Fatalf("unsupported security %q in %s", q.Get("security"), link)
	}
	return map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{"vnext": []any{map[string]any{
			"address": u.Hostname(),
			"port":    port,
			"users":   []any{user},
		}}},
		"streamSettings": stream,
	}
}

// startXrayClient runs Xray as a client with outbound and a local SOCKS inbound; returns the SOCKS address.
func startXrayClient(t *testing.T, outbound map[string]any) string {
	t.Helper()
	bin := xrayBin(t)
	port := freeTCPPort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"tag": "in", "listen": dialHost, "port": port, "protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{outbound},
	}
	path, data := writeJSON(t, "xray-client.json", cfg)
	out := startChild(t, bin, "run", "-c", path)
	addr := net.JoinHostPort(dialHost, strconv.Itoa(port))
	waitTCP(t, addr, "xray client SOCKS inbound", func() string { return out.String() + "\nconfig:\n" + string(data) })
	return addr
}

// fetch GETs target through the SOCKS5 proxy at proxyAddr with keep-alives off, so no idle tunnel lingers.
func fetch(proxyAddr, target string, timeout time.Duration) (int, error) {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: proxyAddr}),
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: timeout}
	resp, err := c.Get(target)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// fetchEventually retries while the server finishes starting; the first success ends it.
func fetchEventually(proxyAddr string) error {
	var lastErr error
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, err := fetch(proxyAddr, publicURL, 8*time.Second)
		if err == nil && status == publicStatus {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("status %d, want %d", status, publicStatus)
		}
		lastErr = err
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("GET %s through the proxy never succeeded (internet itself is reachable): %w", publicURL, lastErr)
}

func queryTraffic(t *testing.T, s *server) map[string]model.Traffic {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := engine.QueryTraffic(ctx, xrayBin(t), s.apiAddr)
	if err != nil {
		t.Fatalf("QueryTraffic: %v", err)
	}
	return got
}

type scenario struct {
	line        model.Line
	good, wrong model.Client
	// startClient launches a client for c from the product's share output and returns its SOCKS5 address.
	startClient func(t *testing.T, line model.Line, c model.Client) string
	// before runs after the server starts, e.g. a CDN stand-in in front of a plain XHTTP line.
	before func(t *testing.T, line *model.Line)
}

// logsContain polls the server log briefly: Xray may log a routing decision after the client already saw it.
func logsContain(s *server, sub string) bool {
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		for _, l := range s.sup.Logs() {
			if strings.Contains(l, sub) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// checkByName fetches a public host by name, which the server resolves under IPIfNonMatch before routing.
// A fake-ip resolver on this machine makes that name private, so then the server must block it instead.
func checkByName(t *testing.T, s *server, proxy string) {
	t.Helper()
	ips, err := net.LookupIP(publicName)
	if err != nil || len(ips) == 0 {
		t.Fatalf("NO DNS (not a product bug): lookup %s: %v", publicName, err)
	}
	status, err := fetch(proxy, publicByName, 8*time.Second)
	if !ips[0].IsPrivate() && !inFakeIPRange(ips[0]) {
		if err != nil || status != http.StatusNoContent {
			t.Errorf("GET %s by name through the proxy: status %d, err %v; want 204", publicByName, status, err)
		}
		return
	}
	t.Logf("local resolver maps %s to %s (fake-ip); expecting the server to block it", publicName, ips[0])
	if err == nil && status == http.StatusNoContent {
		t.Errorf("%s resolved to %s yet was fetched; private-range blocking missed a resolved name", publicName, ips[0])
	}
	if !logsContain(s, publicName+":80 [") || !logsContain(s, "-> block]") {
		t.Errorf("server log does not show %s routed to block", publicName)
	}
}

func inFakeIPRange(ip net.IP) bool {
	_, fake, _ := net.ParseCIDR("198.18.0.0/15")
	return fake.Contains(ip)
}

func run(t *testing.T, sc scenario) {
	requireInternet(t)
	srv := startServer(t, sc.line, sc.good)
	if sc.before != nil {
		sc.before(t, &sc.line)
	}

	proxy := sc.startClient(t, sc.line, sc.good)
	if err := fetchEventually(proxy); err != nil {
		if sc.line.Protocol == model.VLESSReality && logsContain(srv, "REALITY: processed invalid connection") {
			t.Fatalf("%v\nThe Xray server rejected the REALITY ClientHello itself (key, short ID and SNI come from the "+
				"same share output that works with an Xray client), so suspect this client's REALITY handshake against "+
				"this Xray version before the share output; compare XTLS/Xray-core#6477.", err)
		}
		t.Fatal(err)
	}

	var lanHits atomic.Int64
	lan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lanHits.Add(1)
	}))
	defer lan.Close()
	status, err := fetch(proxy, lan.URL, 8*time.Second)
	if err == nil && status == http.StatusOK || lanHits.Load() != 0 {
		t.Errorf("loopback destination %s was reachable through the server (status %d, err %v, hits %d); LAN blocking failed",
			lan.URL, status, err, lanHits.Load())
	}
	// The refusal must come from the server's routing, not from the client or the tunnel.
	lanPort := lan.Listener.Addr().(*net.TCPAddr).Port
	blocked := fmt.Sprintf("127.0.0.1:%d [%s -> block]", lanPort, engine.InboundTag(sc.line.ID))
	if !logsContain(srv, blocked) {
		t.Errorf("server log has no %q: the loopback request was not refused by the block rule", blocked)
	}

	checkByName(t, srv, proxy)

	// Lets the last bytes of the closed tunnels reach the counters before the reset.
	time.Sleep(500 * time.Millisecond)
	tag := sc.good.StatsTag()
	first := queryTraffic(t, srv)
	if tr := first[tag]; tr.Up <= 0 || tr.Down <= 0 {
		t.Errorf("QueryTraffic after traffic: %s = %+v (all: %v), want non-zero up and down", tag, tr, first)
	}
	second := queryTraffic(t, srv)
	if tr := second[tag]; tr.Up != 0 || tr.Down != 0 {
		t.Errorf("QueryTraffic second call: %s = %+v, want zero after reset", tag, tr)
	}

	wrong := sc.startClient(t, sc.line, sc.wrong)
	status, err = fetch(wrong, publicURL, 8*time.Second)
	if err == nil && status == publicStatus {
		t.Errorf("client with a secret the server does not know fetched %s (status %d)", publicURL, status)
	}
	if tr, ok := queryTraffic(t, srv)[sc.wrong.StatsTag()]; ok {
		t.Errorf("unknown client got counted: %+v", tr)
	}
}

// TestXrayVersion checks the parser against the real `xray version` banner.
func TestXrayVersion(t *testing.T) {
	bin := xrayBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, err := engine.Version(ctx, bin)
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil || len(parts) != 3 {
			t.Fatalf("Version = %q, want three numeric fields", v)
		}
	}
	t.Logf("xray version %s", v)
}

func TestVLESSReality(t *testing.T) {
	xrayBin(t)
	priv, pub, err := engine.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	line := model.Line{
		ID: 1, Name: "reality", Protocol: model.VLESSReality, Port: freeTCPPort(t), Enabled: true,
		Reality: &model.RealityParams{
			PrivateKey: priv, PublicKey: pub, ShortID: engine.NewShortID(),
			ServerName: realitySite, Target: realitySite + ":443",
		},
	}
	good, wrong := clients(engine.NewUUID)
	t.Run("mihomo", func(t *testing.T) {
		run(t, scenario{line: line, good: good, wrong: wrong, startClient: mihomoClient(nil)})
	})
	t.Run("xray-from-link", func(t *testing.T) {
		run(t, scenario{line: line, good: good, wrong: wrong, startClient: xrayLinkClient(nil, nil)})
	})
	t.Run("xray-via-exit-builder", func(t *testing.T) {
		run(t, scenario{line: line, good: good, wrong: wrong, startClient: exitBuilderClient(nil)})
	})
}

func TestHysteria2(t *testing.T) {
	for _, obfs := range []string{"", engine.NewPassword()} {
		name := "plain"
		if obfs != "" {
			name = "salamander"
		}
		t.Run(name, func(t *testing.T) {
			xrayBin(t)
			cert := selfSignedCert(t)
			line := model.Line{
				ID: 3, Name: "hy2", Protocol: model.Hysteria2, Port: freeUDPPort(t), Enabled: true,
				Hysteria2: &model.Hysteria2Params{
					Domain: certDomain, CertFile: cert.certFile, KeyFile: cert.keyFile, ObfsPassword: obfs,
				},
			}
			good, wrong := clients(engine.NewPassword)
			t.Run("mihomo", func(t *testing.T) {
				run(t, scenario{line: line, good: good, wrong: wrong, startClient: mihomoClient(cert.certPEM)})
			})
			t.Run("xray-via-exit-builder", func(t *testing.T) {
				run(t, scenario{line: line, good: good, wrong: wrong, startClient: exitBuilderClient(cert.certPEM)})
			})
		})
	}
}

func xrayLinkClient(trust []byte, redirect func() (host string, port int)) func(*testing.T, model.Line, model.Client) string {
	return func(t *testing.T, l model.Line, c model.Client) string {
		link, err := share.Link(l, c, dialHost)
		if err != nil {
			t.Fatalf("share.Link: %v", err)
		}
		out := xrayOutboundFromLink(t, link, trust)
		if redirect != nil {
			// The link names the CDN edge; the test dials its local stand-in instead.
			host, port := redirect()
			vnext := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
			vnext["address"], vnext["port"] = host, port
		}
		return startXrayClient(t, out)
	}
}

func TestVLESSXHTTPTLS(t *testing.T) {
	xrayBin(t)
	cert := selfSignedCert(t)
	line := model.Line{
		ID: 2, Name: "xhttp-tls", Protocol: model.VLESSXHTTP, Port: freeTCPPort(t), Enabled: true,
		XHTTP: &model.XHTTPParams{
			Path: "/xh-" + engine.NewShortID(), Domain: certDomain, Security: model.XHTTPTLS,
			CertFile: cert.certFile, KeyFile: cert.keyFile,
		},
	}
	good, wrong := clients(engine.NewUUID)
	t.Run("xray-from-link", func(t *testing.T) {
		run(t, scenario{line: line, good: good, wrong: wrong, startClient: xrayLinkClient(cert.certPEM, nil)})
	})
	t.Run("xray-via-exit-builder", func(t *testing.T) {
		run(t, scenario{line: line, good: good, wrong: wrong, startClient: exitBuilderClient(cert.certPEM)})
	})
}

// TestVLESSXHTTPPlain puts a TLS-terminating HTTP/2 reverse proxy in front of the plain line, as a CDN would.
func TestVLESSXHTTPPlain(t *testing.T) {
	xrayBin(t)
	cert := selfSignedCert(t)
	line := model.Line{
		ID: 2, Name: "xhttp-cdn", Protocol: model.VLESSXHTTP, Port: freeTCPPort(t), Enabled: true,
		XHTTP: &model.XHTTPParams{Path: "/cdn-" + engine.NewShortID(), Domain: certDomain, Security: model.XHTTPPlain},
	}
	var edge string
	before := func(t *testing.T, l *model.Line) {
		origin := &url.URL{Scheme: "http", Host: net.JoinHostPort(dialHost, strconv.Itoa(l.Port))}
		rp := httputil.NewSingleHostReverseProxy(origin)
		rp.FlushInterval = -1
		cdn := httptest.NewUnstartedServer(rp)
		cdn.EnableHTTP2 = true
		cdn.TLS = &tls.Config{Certificates: []tls.Certificate{cert.tls}}
		cdn.StartTLS()
		t.Cleanup(cdn.Close)
		edge = cdn.Listener.Addr().String()
	}
	redirect := func() (string, int) {
		host, port, _ := net.SplitHostPort(edge)
		n, _ := strconv.Atoi(port)
		return host, n
	}
	good, wrong := clients(engine.NewUUID)
	run(t, scenario{line: line, good: good, wrong: wrong, before: before, startClient: xrayLinkClient(cert.certPEM, redirect)})
}
