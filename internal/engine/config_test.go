package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// testPrivateKey is RFC 7748 §6.1 Alice's private key in base64url.
const testPrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo"

func realityLine(id int64, port int) model.Line {
	return model.Line{ID: id, Protocol: model.VLESSReality, Port: port, Enabled: true, Reality: &model.RealityParams{
		PrivateKey: testPrivateKey, PublicKey: "unused", ShortID: "0123abcd",
		ServerName: "www.example.com", Target: "www.example.com:443",
	}}
}

func xhttpLine(id int64, port int, sec model.XHTTPSecurity) model.Line {
	p := &model.XHTTPParams{Path: "/x", Domain: "cdn.example.com", Security: sec}
	if sec == model.XHTTPTLS {
		p.CertFile, p.KeyFile = "/etc/ssl/a.crt", "/etc/ssl/a.key"
	}
	return model.Line{ID: id, Protocol: model.VLESSXHTTP, Port: port, Enabled: true, XHTTP: p}
}

func hy2Line(id int64, port int, obfs string) model.Line {
	return model.Line{ID: id, Protocol: model.Hysteria2, Port: port, Enabled: true, Hysteria2: &model.Hysteria2Params{
		Domain: "hy.example.com", CertFile: "/etc/ssl/h.crt", KeyFile: "/etc/ssl/h.key", ObfsPassword: obfs,
	}}
}

var testClients = []model.Client{
	{ID: 7, Secret: "b831381d-6324-4d53-ad4f-8cda48b30811"},
	{ID: 2, Secret: "2c0d4a2f-7c16-4e41-9a49-8a1b6a0f0b9e"},
	{ID: 3, Secret: "e2b7b8f0-0a37-4f8a-9e5b-1d1d4b3a9f00", Disabled: model.DisabledQuota},
}

type jsonObj = map[string]any

func buildJSON(t *testing.T, lines []model.Line, clients []model.Client) jsonObj {
	t.Helper()
	out, err := BuildConfig(lines, clients, nil, Options{APIPort: 10085})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var cfg jsonObj
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	return cfg
}

// at walks a decoded JSON value by object keys and array indexes.
func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(jsonObj)
			if !ok {
				t.Fatalf("at %v: %v is not an object", path, v)
			}
			v, ok = m[k]
			if !ok {
				t.Fatalf("at %v: key %q missing", path, k)
			}
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("at %v: index %d not in %v", path, k, v)
			}
			v = a[k]
		}
	}
	return v
}

func inboundByTag(t *testing.T, cfg jsonObj, tag string) jsonObj {
	t.Helper()
	for _, in := range at(t, cfg, "inbounds").([]any) {
		if in.(jsonObj)["tag"] == tag {
			return in.(jsonObj)
		}
	}
	t.Fatalf("no inbound tagged %q", tag)
	return nil
}

func assertEqual(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		gj, _ := json.Marshal(got)
		wj, _ := json.Marshal(want)
		t.Errorf("%s =\n  %s\nwant\n  %s", what, gj, wj)
	}
}

func TestBuildConfigReality(t *testing.T) {
	cfg := buildJSON(t, []model.Line{realityLine(1, 443)}, testClients)
	in := inboundByTag(t, cfg, "line-1")
	assertEqual(t, "protocol", in["protocol"], "vless")
	assertEqual(t, "port", in["port"], float64(443))
	assertEqual(t, "settings", in["settings"], jsonObj{
		"decryption": "none",
		"clients": []any{
			jsonObj{"id": "2c0d4a2f-7c16-4e41-9a49-8a1b6a0f0b9e", "email": "c2", "flow": "xtls-rprx-vision"},
			jsonObj{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "c7", "flow": "xtls-rprx-vision"},
		},
	})
	assertEqual(t, "streamSettings", in["streamSettings"], jsonObj{
		"network":  "raw",
		"security": "reality",
		"realitySettings": jsonObj{
			"target":      "www.example.com:443",
			"serverNames": []any{"www.example.com"},
			"privateKey":  testPrivateKey,
			"shortIds":    []any{"0123abcd"},
		},
	})
}

func TestBuildConfigXHTTP(t *testing.T) {
	cfg := buildJSON(t, []model.Line{xhttpLine(4, 8443, model.XHTTPTLS), xhttpLine(5, 8080, model.XHTTPPlain)}, testClients)

	tlsIn := inboundByTag(t, cfg, "line-4")
	assertEqual(t, "tls clients[0]", at(t, tlsIn, "settings", "clients", 0),
		jsonObj{"id": "2c0d4a2f-7c16-4e41-9a49-8a1b6a0f0b9e", "email": "c2"})
	assertEqual(t, "tls streamSettings", tlsIn["streamSettings"], jsonObj{
		"network":       "xhttp",
		"xhttpSettings": jsonObj{"path": "/x", "mode": "auto"},
		"security":      "tls",
		"tlsSettings": jsonObj{
			"serverName":   "cdn.example.com",
			"certificates": []any{jsonObj{"certificateFile": "/etc/ssl/a.crt", "keyFile": "/etc/ssl/a.key"}},
		},
	})

	plainIn := inboundByTag(t, cfg, "line-5")
	assertEqual(t, "plain streamSettings", plainIn["streamSettings"], jsonObj{
		"network":       "xhttp",
		"xhttpSettings": jsonObj{"path": "/x", "mode": "auto"},
		"security":      "none",
	})
}

func TestBuildConfigHysteria2(t *testing.T) {
	cfg := buildJSON(t, []model.Line{hy2Line(9, 443, "obfs-pass"), hy2Line(10, 8443, "")}, testClients)

	in := inboundByTag(t, cfg, "line-9")
	assertEqual(t, "protocol", in["protocol"], "hysteria")
	assertEqual(t, "settings", in["settings"], jsonObj{
		"version": float64(2),
		"users": []any{
			jsonObj{"auth": "2c0d4a2f-7c16-4e41-9a49-8a1b6a0f0b9e", "email": "c2"},
			jsonObj{"auth": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "c7"},
		},
	})
	assertEqual(t, "streamSettings", in["streamSettings"], jsonObj{
		"network":  "hysteria",
		"security": "tls",
		"tlsSettings": jsonObj{
			"serverName":   "hy.example.com",
			"alpn":         []any{"h3"},
			"certificates": []any{jsonObj{"certificateFile": "/etc/ssl/h.crt", "keyFile": "/etc/ssl/h.key"}},
		},
		"hysteriaSettings": jsonObj{"version": float64(2)},
		"finalmask": jsonObj{"udp": []any{jsonObj{
			"type": "salamander", "settings": jsonObj{"password": "obfs-pass"},
		}}},
	})

	noObfs := at(t, inboundByTag(t, cfg, "line-10"), "streamSettings").(jsonObj)
	if _, ok := noObfs["finalmask"]; ok {
		t.Errorf("finalmask present without an obfs password: %v", noObfs["finalmask"])
	}
}

func TestBuildConfigStatsAPIAndRouting(t *testing.T) {
	cfg := buildJSON(t, []model.Line{realityLine(1, 443)}, testClients)
	assertEqual(t, "api", cfg["api"], jsonObj{"tag": "api", "services": []any{"HandlerService", "StatsService"}})
	assertEqual(t, "stats", cfg["stats"], jsonObj{})
	assertEqual(t, "policy", cfg["policy"], jsonObj{"levels": jsonObj{"0": jsonObj{
		"connIdle": float64(180), "statsUserUplink": true, "statsUserDownlink": true,
	}}})
	assertEqual(t, "api inbound", inboundByTag(t, cfg, "api"), jsonObj{
		"tag": "api", "listen": "127.0.0.1", "port": float64(10085),
		"protocol": "tunnel", "settings": jsonObj{"rewriteAddress": "127.0.0.1"},
	})
	assertEqual(t, "outbounds", cfg["outbounds"], []any{
		jsonObj{"tag": "direct", "protocol": "freedom"},
		jsonObj{"tag": "block", "protocol": "blackhole"},
	})
	assertEqual(t, "rule 0", at(t, cfg, "routing", "rules", 0), jsonObj{"inboundTag": []any{"api"}, "outboundTag": "api"})
	blockRule := at(t, cfg, "routing", "rules", 1).(jsonObj)
	assertEqual(t, "rule 1 outbound", blockRule["outboundTag"], "block")
	ips := map[any]bool{}
	for _, ip := range blockRule["ip"].([]any) {
		ips[ip] = true
	}
	for _, lan := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"} {
		if !ips[lan] {
			t.Errorf("private range %s is not blocked", lan)
		}
	}
	assertEqual(t, "log", cfg["log"], jsonObj{"loglevel": "warning"})
}

func TestBuildConfigOmitsDisabledLinesAndClients(t *testing.T) {
	off := realityLine(2, 8443)
	off.Enabled = false
	off.Reality = nil // a disabled line with broken params must not block the build
	cfg := buildJSON(t, []model.Line{realityLine(1, 443), off, hy2Line(3, 443, "")}, testClients)

	var tags []any
	for _, in := range at(t, cfg, "inbounds").([]any) {
		tags = append(tags, in.(jsonObj)["tag"])
	}
	assertEqual(t, "inbound tags", tags, []any{"api", "line-1", "line-3"})
	for _, tag := range []string{"line-1", "line-3"} {
		users := at(t, inboundByTag(t, cfg, tag), "settings").(jsonObj)
		list, _ := users["clients"].([]any)
		if list == nil {
			list = users["users"].([]any)
		}
		var emails []any
		for _, u := range list {
			emails = append(emails, u.(jsonObj)["email"])
		}
		assertEqual(t, tag+" emails (disabled c3 absent, StatsTag on every line)", emails, []any{"c2", "c7"})
	}
}

func TestBuildConfigWithNoClientsEmitsEmptyUserLists(t *testing.T) {
	cfg := buildJSON(t, []model.Line{realityLine(1, 443), hy2Line(2, 443, "")}, nil)
	assertEqual(t, "vless clients", at(t, inboundByTag(t, cfg, "line-1"), "settings", "clients"), []any{})
	assertEqual(t, "hysteria users", at(t, inboundByTag(t, cfg, "line-2"), "settings", "users"), []any{})
}

func TestBuildConfigDeterministic(t *testing.T) {
	lines := []model.Line{hy2Line(3, 443, "x"), realityLine(1, 443), xhttpLine(2, 80, model.XHTTPPlain)}
	a, err := BuildConfig(lines, testClients, nil, Options{APIPort: 10085})
	if err != nil {
		t.Fatal(err)
	}
	reversed := []model.Line{lines[2], lines[1], lines[0]}
	clients := []model.Client{testClients[2], testClients[1], testClients[0]}
	for range 20 {
		b, err := BuildConfig(reversed, clients, nil, Options{APIPort: 10085})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("output differs between runs / input orders:\n%s\n---\n%s", a, b)
		}
	}
}

func TestBuildConfigErrors(t *testing.T) {
	mismatch := realityLine(1, 443)
	mismatch.XHTTP = &model.XHTTPParams{Path: "/x", Security: model.XHTTPPlain}
	nilReality := realityLine(1, 443)
	nilReality.Reality = nil
	badShortID := realityLine(1, 443)
	badShortID.Reality.ShortID = "XYZ"
	badKey := realityLine(1, 443)
	badKey.Reality.PrivateKey = "short"
	badTarget := realityLine(1, 443)
	badTarget.Reality.Target = "example.com"
	tlsNoCert := xhttpLine(4, 443, model.XHTTPTLS)
	tlsNoCert.XHTTP.CertFile = ""
	badPath := xhttpLine(4, 443, model.XHTTPPlain)
	badPath.XHTTP.Path = "x"
	hyNoKey := hy2Line(6, 443, "")
	hyNoKey.Hysteria2.KeyFile = ""
	unknown := realityLine(8, 443)
	unknown.Protocol = "trojan"

	cases := []struct {
		name  string
		lines []model.Line
		want  LineError
	}{
		{"reality line with nil params", []model.Line{nilReality}, LineError{1, "Reality", "missing for protocol vless-reality"}},
		{"reality line with xhttp params too", []model.Line{mismatch}, LineError{1, "XHTTP", "set on a vless-reality line"}},
		{"bad short id", []model.Line{badShortID}, LineError{1, "Reality.ShortID", `"XYZ" is not 0-16 lowercase hex digits of even length`}},
		{"bad private key", []model.Line{badKey}, LineError{1, "Reality.PrivateKey", "not a base64url X25519 key"}},
		{"target without port", []model.Line{badTarget}, LineError{1, "Reality.Target", `"example.com" is not host:port`}},
		{"xhttp tls without cert", []model.Line{tlsNoCert}, LineError{4, "XHTTP.CertFile", "empty with tls security"}},
		{"xhttp relative path", []model.Line{badPath}, LineError{4, "XHTTP.Path", `"x" must start with /`}},
		{"hysteria2 without key", []model.Line{hyNoKey}, LineError{6, "Hysteria2.KeyFile", "empty"}},
		{"unknown protocol", []model.Line{unknown}, LineError{8, "Protocol", `unknown protocol "trojan"`}},
		{"two tcp lines on one port", []model.Line{realityLine(1, 443), xhttpLine(2, 443, model.XHTTPPlain)}, LineError{2, "Port", "443 is already used by line 1"}},
		{"line on the api port", []model.Line{realityLine(1, 10085)}, LineError{1, "Port", "10085 is already used by the API inbound"}},
		{"port out of range", []model.Line{realityLine(1, 70000)}, LineError{1, "Port", "70000 is not a port number"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildConfig(tc.lines, testClients, nil, Options{APIPort: 10085})
			var le *LineError
			if !errors.As(err, &le) {
				t.Fatalf("err = %v, want *LineError", err)
			}
			if *le != tc.want {
				t.Errorf("err = %+v, want %+v", *le, tc.want)
			}
		})
	}
}

func TestBuildConfigClientAndOptionErrors(t *testing.T) {
	_, err := BuildConfig(nil, []model.Client{{ID: 5}}, nil, Options{APIPort: 10085})
	var ce *ClientError
	if !errors.As(err, &ce) || *ce != (ClientError{5, "Secret", "empty"}) {
		t.Errorf("empty secret: err = %v, want ClientError for client 5", err)
	}
	_, err = BuildConfig(nil, nil, nil, Options{})
	var oe *OptionsError
	if !errors.As(err, &oe) || oe.Field != "APIPort" {
		t.Errorf("zero api port: err = %v, want OptionsError on APIPort", err)
	}
	_, err = BuildConfig(nil, nil, nil, Options{APIPort: 1, LogLevel: "loud"})
	if !errors.As(err, &oe) || oe.Field != "LogLevel" {
		t.Errorf("bad log level: err = %v, want OptionsError on LogLevel", err)
	}
	_, err = BuildConfig(nil, nil, nil, Options{APIPort: 1, ConnIdle: -1})
	if !errors.As(err, &oe) || oe.Field != "ConnIdle" {
		t.Errorf("negative conn idle: err = %v, want OptionsError on ConnIdle", err)
	}
}

func TestBuildConfigConnIdle(t *testing.T) {
	out, err := BuildConfig(nil, nil, nil, Options{APIPort: 10085, ConnIdle: 600})
	if err != nil {
		t.Fatal(err)
	}
	var cfg jsonObj
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	level := at(t, cfg, "policy", "levels", "0").(jsonObj)
	if level["connIdle"] != float64(600) {
		t.Errorf("connIdle = %v, want 600 from Options", level["connIdle"])
	}
}

// TestBuildConfigValidatesWithRealXray needs a real binary: XRAY_BIN=/path/to/xray go test ./internal/engine/
func TestBuildConfigValidatesWithRealXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN not set")
	}
	certFile, keyFile := writeSelfSignedCert(t)
	priv, _, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	reality := realityLine(1, 24431)
	reality.Reality.PrivateKey = priv
	reality.Reality.ShortID = NewShortID()
	xtls := xhttpLine(2, 24432, model.XHTTPTLS)
	xtls.XHTTP.CertFile, xtls.XHTTP.KeyFile = certFile, keyFile
	hy := hy2Line(3, 24433, NewPassword())
	hy.Hysteria2.CertFile, hy.Hysteria2.KeyFile = certFile, keyFile
	lines := []model.Line{reality, xtls, xhttpLine(4, 24434, model.XHTTPPlain), hy}
	clients := []model.Client{{ID: 1, Secret: NewUUID()}, {ID: 2, Secret: NewUUID()}}

	cfg, err := BuildConfig(lines, clients, nil, Options{APIPort: 24430})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(context.Background(), bin, cfg); err != nil {
		t.Fatalf("xray rejected the generated config: %v\n%s", err, cfg)
	}
	if err := Validate(context.Background(), bin, []byte(`{"inbounds":[{"protocol":"nope"}]}`)); err == nil {
		t.Error("xray accepted an unknown protocol; Validate is not reporting failures")
	}
	if v, err := Version(context.Background(), bin); err != nil || v == "" {
		t.Errorf("Version = %q, %v", v, err)
	}
}

func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"hy.example.com", "cdn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
