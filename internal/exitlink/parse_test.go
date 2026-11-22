package exitlink

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/engine"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/share"
)

const (
	tUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
	// tPBKStd and tPBKURL are one 32-byte X25519 key in the two base64 alphabets.
	tPBKStd = "++//++//++//++//++//++//++//++//++//++//++8="
	tPBKURL = "--__--__--__--__--__--__--__--__--__--__--8"
	// tSS is base64 of "aes-256-gcm:pa?>ss~"; the standard alphabet gives '/', the URL one '_'.
	tSSStd = "YWVzLTI1Ni1nY206cGE/PnNzfg=="
	tSSURL = "YWVzLTI1Ni1nY206cGE_PnNzfg"
	tSSPW  = "pa?>ss~"
	// 2022 keys: base64 of "0123456789abcdef", of "fedcba9876543210", and of 32 bytes that need '+' and '/'.
	tKey16a = "MDEyMzQ1Njc4OWFiY2RlZg=="
	tKey16b = "ZmVkY2JhOTg3NjU0MzIxMA=="
	tKey32  = "+//7//v/+//7//v/+//7//v/+//7//v/+//7//v/+/8="
)

var (
	tPQV      = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb, 0xef, 0x01}, 651)[:mldsa65KeyLen])
	tPinColon = strings.Repeat("AB:", 31) + "AB"
	tPin      = strings.Repeat("ab", 32)
	tPin2     = strings.Repeat("0123456789abcdef", 4)
)

type validCase struct {
	name string
	link string
	want model.ExitParams
	tag  string
}

func validCases() []validCase {
	raw := model.ExitTransport{Network: model.ExitRaw}
	return []validCase{
		{
			name: "vless reality vision with spx and pqv",
			link: "  vless://B831381D-6324-4D53-AD4F-8CDA48B30811@203.0.113.7:443?encryption=none" +
				"&flow=xtls-rprx-vision&security=reality&sni=WWW.Example.com&fp=firefox&pbk=" + tPBKStd +
				"&sid=6BA85179&spx=%2Fsearch%3Fq%3D1&pqv=" + tPQV + "&type=tcp&headerType=none" +
				"&allowInsecure=0&remarks=x&remarks2=%zz#Tokyo%20%231  ",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "203.0.113.7", Port: 443, Secret: tUUID,
				Flow: visionFlow, Encryption: "none", Transport: raw,
				Reality: &model.ExitReality{
					ServerName: "www.example.com", Fingerprint: "firefox", PublicKey: tPBKURL,
					ShortID: "6ba85179", SpiderX: "/search?q=1", MLDSA65Verify: tPQV,
				},
			},
			tag: "Tokyo #1",
		},
		{
			name: "vless reality over xhttp with url-safe pbk and empty keys",
			link: "VLESS://" + tUUID + "@Edge.Example.NET:8443/?security=reality&sni=www.example.com&pbk=" +
				tPBKURL + "&sid=&spx=&flow=&type=xhttp&path=%2Fx&mode=stream-one#",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "edge.example.net", Port: 8443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{Network: model.ExitXHTTP, Path: "/x", Mode: "stream-one"},
				Reality:   &model.ExitReality{ServerName: "www.example.com", Fingerprint: "chrome", PublicKey: tPBKURL},
			},
		},
		{
			name: "vless xhttp tls with mode and alpn",
			link: "vless://" + tUUID + "@xh.example.com:8443?encryption=none&security=tls&sni=xh.example.com" +
				"&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=cdn.example.com&path=%2Fxh&mode=packet-up#XH",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "xh.example.com", Port: 8443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{Network: model.ExitXHTTP, Path: "/xh", Host: "cdn.example.com", Mode: "packet-up"},
				TLS:       &model.ExitTLS{ServerName: "xh.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}},
			},
			tag: "XH",
		},
		{
			name: "vless xhttp tls defaults path and mode",
			link: "vless://" + tUUID + "@xh.example.com:443?security=tls&type=xhttp",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "xh.example.com", Port: 443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{Network: model.ExitXHTTP, Path: "/", Mode: "auto"},
				TLS:       &model.ExitTLS{Fingerprint: "chrome"},
			},
		},
		{
			name: "vless ws tls with early data in the path over ipv6",
			link: "vless://" + tUUID + "@[2001:DB8::1]:443?type=ws&security=tls&sni=ws.example.com&fp=random" +
				"&path=%2Fws%3Fed%3D2048&host=ws.example.com",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "2001:db8::1", Port: 443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{Network: model.ExitWS, Path: "/ws?ed=2048", Host: "ws.example.com"},
				TLS:       &model.ExitTLS{ServerName: "ws.example.com", Fingerprint: "random"},
			},
		},
		{
			name: "vless grpc multi with authority, pins that excuse allowInsecure, and verify names",
			link: "vless://" + tUUID + "@grpc.example.com:443?type=grpc&serviceName=my%2Fsvc&authority=api.example.com" +
				"&mode=multi&security=tls&pcs=" + tPinColon + "," + tPin2 + "&vcn=a.example.com,B.example.com&allowInsecure=1",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "grpc.example.com", Port: 443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{
					Network: model.ExitGRPC, ServiceName: "my/svc", Authority: "api.example.com", MultiMode: true,
				},
				TLS: &model.ExitTLS{
					Fingerprint: "chrome", PinSHA256: tPin + "," + tPin2, VerifyName: "a.example.com,b.example.com",
				},
			},
		},
		{
			name: "vless grpc gun over reality",
			link: "vless://" + tUUID + "@198.51.100.4:443?type=grpc&serviceName=svc&mode=gun&security=reality" +
				"&sni=www.example.com&fp=safari&pbk=" + tPBKURL + "&sid=0123456789ABCDEF",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "198.51.100.4", Port: 443, Secret: tUUID, Encryption: "none",
				Transport: model.ExitTransport{Network: model.ExitGRPC, ServiceName: "svc"},
				Reality: &model.ExitReality{
					ServerName: "www.example.com", Fingerprint: "safari", PublicKey: tPBKURL, ShortID: "0123456789abcdef",
				},
			},
		},
		{
			name: "vless encryption without tls allows vision over raw to a public address",
			link: "vless://short-id@198.51.100.9:8080?encryption=mlkem768x25519plus.native.0rtt.AbC_d-e9" +
				"&flow=xtls-rprx-vision-udp443&security=none&type=raw",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "198.51.100.9", Port: 8080, Secret: "short-id",
				Flow: visionUDP443Flow, Encryption: "mlkem768x25519plus.native.0rtt.AbC_d-e9",
				Transport: model.ExitTransport{Network: model.ExitRaw},
			},
		},
		{
			name: "vless plain text to a private address",
			link: "vless://" + tUUID + "@10.0.0.1:1234?security=none#lan",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "10.0.0.1", Port: 1234, Secret: tUUID, Encryption: "none", Transport: raw,
			},
			tag: "lan",
		},
		{
			name: "vless bare-hex uuid in plain text to ipv6 loopback",
			link: "vless://B831381D63244D53AD4F8CDA48B30811@[::1]:10086",
			want: model.ExitParams{
				Protocol: model.ExitVLESS, Host: "::1", Port: 10086, Secret: tUUID, Encryption: "none", Transport: raw,
			},
		},
		{
			name: "trojan with peer alias, a colon in the password and the default port",
			link: "trojan://pa:ss%40word@Trojan.Example.com?peer=tls.example.com&fp=safari#T",
			want: model.ExitParams{
				Protocol: model.ExitTrojan, Host: "trojan.example.com", Port: 443, Secret: "pa:ss@word", Transport: raw,
				TLS: &model.ExitTLS{ServerName: "tls.example.com", Fingerprint: "safari"},
			},
			tag: "T",
		},
		{
			name: "trojan over reality",
			link: "trojan://secret@203.0.113.9:8443?security=reality&sni=www.example.com&pbk=" + tPBKURL + "&type=raw",
			want: model.ExitParams{
				Protocol: model.ExitTrojan, Host: "203.0.113.9", Port: 8443, Secret: "secret", Transport: raw,
				Reality: &model.ExitReality{ServerName: "www.example.com", Fingerprint: "chrome", PublicKey: tPBKURL},
			},
		},
		{
			name: "trojan plain text to loopback ignores keys of an unused security",
			link: "trojan://pw@127.0.0.1:1080?security=none&sni=x.example.com&alpn=h9&pbk=bad",
			want: model.ExitParams{
				Protocol: model.ExitTrojan, Host: "127.0.0.1", Port: 1080, Secret: "pw", Transport: raw,
			},
		},
		{
			name: "ss base64url userinfo without padding",
			link: "ss://" + tSSURL + "@ss.example.com:8388#SS",
			want: model.ExitParams{
				Protocol: model.ExitShadowsocks, Host: "ss.example.com", Port: 8388, Method: "aes-256-gcm", Secret: tSSPW,
			},
			tag: "SS",
		},
		{
			name: "ss standard base64 userinfo with padding and a trailing slash",
			link: "ss://" + tSSStd + "@198.51.100.2:8388/?plugin=&outline=1#Std",
			want: model.ExitParams{
				Protocol: model.ExitShadowsocks, Host: "198.51.100.2", Port: 8388, Method: "aes-256-gcm", Secret: tSSPW,
			},
			tag: "Std",
		},
		{
			name: "ss plain 2022 userinfo with two keys",
			link: "ss://2022-BLAKE3-AES-128-GCM:MDEyMzQ1Njc4OWFiY2RlZg%3D%3D:" + tKey16b + "@[2001:db8::2]:443/",
			want: model.ExitParams{
				Protocol: model.ExitShadowsocks, Host: "2001:db8::2", Port: 443, Method: "2022-blake3-aes-128-gcm",
				Secret: tKey16a + ":" + tKey16b,
			},
		},
		{
			name: "ss plain 2022 userinfo with raw + and / in the key",
			link: "ss://2022-blake3-aes-256-gcm:" + tKey32 + "@ss.example.com:443",
			want: model.ExitParams{
				Protocol: model.ExitShadowsocks, Host: "ss.example.com", Port: 443, Method: "2022-blake3-aes-256-gcm",
				Secret: tKey32,
			},
		},
		{
			name: "ss legacy whole-body base64",
			link: "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:se@cret@192.0.2.1:8388")) +
				"#legacy",
			want: model.ExitParams{
				Protocol: model.ExitShadowsocks, Host: "192.0.2.1", Port: 8388, Method: "chacha20-ietf-poly1305",
				Secret: "se@cret",
			},
			tag: "legacy",
		},
		{
			name: "socks5 without authentication",
			link: "socks5://proxy.example.com:1080",
			want: model.ExitParams{Protocol: model.ExitSOCKS, Host: "proxy.example.com", Port: 1080},
		},
		{
			name: "socks5h with user and password",
			link: "socks5h://us%3Aer:p%40ss@198.51.100.1:1080#S",
			want: model.ExitParams{
				Protocol: model.ExitSOCKS, Host: "198.51.100.1", Port: 1080, Username: "us:er", Secret: "p@ss",
			},
			tag: "S",
		},
		{
			name: "socks with v2rayN base64 userinfo",
			link: "socks://" + base64.StdEncoding.EncodeToString([]byte("user:pa ss")) + "@[2001:db8::3]:1080",
			want: model.ExitParams{
				Protocol: model.ExitSOCKS, Host: "2001:db8::3", Port: 1080, Username: "user", Secret: "pa ss",
			},
		},
		{
			name: "hy2 alias with user:pass auth and salamander",
			link: "hy2://user:pa%20ss@hy.example.com:8443/?sni=sni.example.com&obfs=salamander&obfs-password=ob%26fs#H%C3%BC",
			want: model.ExitParams{
				Protocol: model.ExitHysteria2, Host: "hy.example.com", Port: 8443, Secret: "user:pa ss",
				ObfsPassword: "ob&fs", TLS: &model.ExitTLS{ServerName: "sni.example.com", ALPN: []string{"h3"}},
			},
			tag: "Hü",
		},
		{
			name: "hysteria2 default port, colon pin and insecure excused by the pin",
			link: "hysteria2://auth@203.0.113.5?pinSHA256=" + tPinColon + "&insecure=1",
			want: model.ExitParams{
				Protocol: model.ExitHysteria2, Host: "203.0.113.5", Port: 443, Secret: "auth",
				TLS: &model.ExitTLS{ALPN: []string{"h3"}, PinSHA256: tPin},
			},
		},
	}
}

func show(p model.ExitParams) string {
	s := fmt.Sprintf("%+v", p)
	if p.TLS != nil {
		s += fmt.Sprintf("\n  TLS: %+v", *p.TLS)
	}
	if p.Reality != nil {
		s += fmt.Sprintf("\n  Reality: %+v", *p.Reality)
	}
	return s
}

func TestParseValid(t *testing.T) {
	for _, tc := range validCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, tag, err := Parse(tc.link)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("params =\n%s\nwant\n%s", show(got), show(tc.want))
			}
			if tag != tc.tag {
				t.Errorf("name = %q, want %q", tag, tc.tag)
			}
		})
	}
}

func TestParseLengthLimit(t *testing.T) {
	base := "vless://" + tUUID + "@10.0.0.1:443?pad="
	exact := base + strings.Repeat("a", maxLinkLen-len(base))
	if _, _, err := Parse(exact); err != nil {
		t.Fatalf("link of exactly 8 KiB: %v", err)
	}
	if _, _, err := Parse(exact + "a"); err == nil {
		t.Fatal("link one byte over 8 KiB accepted")
	}
}

func TestParseErrors(t *testing.T) {
	v := "vless://" + tUUID + "@example.com:443"
	tlsV := v + "?security=tls&"
	reality := v + "?security=reality&sni=www.example.com&pbk=" + tPBKURL
	cases := []struct {
		name, link, part, problem string
	}{
		// Whole link.
		{"empty", "   ", "text", "empty"},
		{"too long", v + "?x=" + strings.Repeat("a", maxLinkLen), "text", "8 KiB"},
		{"control character", "vless://" + tUUID + "@example.com:443?type=tcp\x01#x", "text", "control character"},
		{"tab inside", "vless://" + tUUID + "@example.com:443?type=\ttcp", "text", "control character"},
		{"invalid utf-8", v + "#\xff", "text", "UTF-8"},
		{"path after port", v + "/ws?security=tls", "text", "after the port"},
		{"broken escape in a query key", tlsV + "%zz=1", "text", "query key"},
		{"duplicate key", tlsV + "type=ws&type=tcp", "type", "more than once"},
		{"duplicate key spelt with an escape", tlsV + "sni=a.example.com&%73ni=b.example.com", "sni", "more than once"},
		{"duplicate unknown key", tlsV + "x=1&x=2", "x", "more than once"},
		{"broken escape in a value", tlsV + "sni=a%zz", "sni", "%-escape"},
		{"escaped control character in a value", tlsV + "sni=a%0Ab.example.com", "sni", "control character"},
		{"broken escape in the name", v + "?security=tls#a%zz", "name", "%-escape"},
		{"escaped control character in the name", v + "?security=tls#a%00b", "name", "control character"},

		// Scheme.
		{"no scheme", "example.com:443", "scheme", "missing"},
		{"vmess", "vmess://eyJhZGQiOiIxIn0=", "scheme", "vless, trojan, ss, socks5 or hysteria2"},
		{"tuic", "tuic://u:p@example.com:443", "scheme", "not supported"},
		{"wireguard", "wireguard://key@example.com:51820", "scheme", "not supported"},
		{"http", "http://example.com:8080", "scheme", "not supported"},
		{"hysteria v1", "hysteria://example.com:443?auth=x", "scheme", "Hysteria 1"},
		{"socks4", "socks4://example.com:1080", "scheme", "SOCKS4"},
		{"socks4a", "socks4a://example.com:1080", "scheme", "SOCKS4"},

		// Host.
		{"idn host", "vless://" + tUUID + "@例え.jp:443?security=tls", "host", "punycode"},
		{"missing host", "vless://" + tUUID + "@:443?security=tls", "host", "missing"},
		{"bare ipv6", "vless://" + tUUID + "@2001:db8::1:443?security=tls", "host", "brackets"},
		{"unclosed bracket", "vless://" + tUUID + "@[2001:db8::1:443?security=tls", "host", "closing"},
		{"ipv4 in brackets", "vless://" + tUUID + "@[192.0.2.1]:443?security=tls", "host", "not an IPv6"},
		{"ipv6 zone", "vless://" + tUUID + "@[fe80::1%25en0]:443?security=tls", "host", "not an IPv6"},
		{"junk after bracket", "vless://" + tUUID + "@[::1]x:443", "host", "after \"]\""},
		{"underscore", "vless://" + tUUID + "@a_b.example.com:443?security=tls", "host", "hostname cannot"},
		{"leading hyphen", "vless://" + tUUID + "@-a.example.com:443?security=tls", "host", "\"-\""},
		{"empty label", "vless://" + tUUID + "@a..example.com:443?security=tls", "host", "empty label"},
		{"trailing dot", "vless://" + tUUID + "@example.com.:443?security=tls", "host", "empty label"},
		{"label of 64", "vless://" + tUUID + "@" + strings.Repeat("a", 64) + ".com:443?security=tls", "host", "63"},
		{"host of 254", "vless://" + tUUID + "@" + strings.Repeat("abcdefghi.", 25) + "abcd:443?security=tls", "host", "253"},
		{"numeric top label", "vless://" + tUUID + "@1.2.3:443?security=tls", "host", "neither"},
		{"leading zero ipv4", "vless://" + tUUID + "@010.0.0.1:443?security=tls", "host", "neither"},
		{"unspecified address", "vless://" + tUUID + "@0.0.0.0:443?security=tls", "host", "dialled"},
		{"multicast address", "vless://" + tUUID + "@[ff02::1]:443?security=tls", "host", "multicast"},

		// Port.
		{"port 0", "vless://" + tUUID + "@example.com:0?security=tls", "port", "1 to 65535"},
		{"port 70000", "vless://" + tUUID + "@example.com:70000?security=tls", "port", "1 to 65535"},
		{"port not a number", "vless://" + tUUID + "@example.com:https?security=tls", "port", "1 to 65535"},
		{"port empty", "vless://" + tUUID + "@example.com:?security=tls", "port", "empty"},
		{"vless port missing", "vless://" + tUUID + "@example.com?security=tls", "port", "required"},
		{"port list outside hysteria2", "vless://" + tUUID + "@example.com:443,444?security=tls", "port", "1 to 65535"},

		// VLESS.
		{"vless id missing", "vless://example.com:443?security=tls", "userinfo", "missing"},
		{"vless id empty", "vless://@example.com:443?security=tls", "userinfo", "missing"},
		{"vless id of 31 bytes", "vless://" + strings.Repeat("a", 31) + "@example.com:443?security=tls", "userinfo", "1 to 30"},
		{"vless malformed uuid", "vless://b831381d-6324-4d53-ad4f-8cda48b3081g@example.com:443?security=tls", "userinfo", "UUID"},
		{"bad encryption", tlsV + "encryption=aes-128-gcm", "encryption", "VLESS Encryption"},
		{"encryption with bad characters", tlsV + "encryption=mlkem768x25519plus.a%2Bb", "encryption", "VLESS Encryption"},
		{"encryption prefix only", tlsV + "encryption=mlkem768x25519plus.", "encryption", "VLESS Encryption"},
		{"vision over xhttp even with encryption", "vless://short-id@198.51.100.9:8080?encryption=mlkem768x25519plus.native.0rtt.AbC_d-e9" +
			"&flow=xtls-rprx-vision&security=none&type=xhttp", "flow", "type=raw"},
		{"unknown flow", tlsV + "flow=xtls-rprx-direct", "flow", "not supported"},
		{"vision over ws", tlsV + "flow=xtls-rprx-vision&type=ws", "flow", "type=raw"},
		{"vision without security", "vless://" + tUUID + "@10.0.0.1:443?flow=xtls-rprx-vision", "flow", "security tls or reality"},
		{"type kcp", tlsV + "type=kcp", "type", "not supported"},
		{"type http", tlsV + "type=http", "type", "not supported"},
		{"type quic", tlsV + "type=quic", "type", "not supported"},
		{"type httpupgrade", tlsV + "type=httpupgrade", "type", "not supported"},
		{"type splithttp", tlsV + "type=splithttp", "type", "not supported"},
		{"header type http", tlsV + "headerType=http", "headerType", "only none"},
		{"security xtls", v + "?security=xtls", "security", "none, tls or reality"},
		{"reality over ws", reality + "&type=ws", "security", "REALITY only supports RAW, XHTTP and gRPC"},
		{"reality without sni", v + "?security=reality&pbk=" + tPBKURL, "sni", "required"},
		{"reality sni is an ip", v + "?security=reality&sni=192.0.2.1&pbk=" + tPBKURL, "sni", "neither"},
		{"reality without pbk", v + "?security=reality&sni=www.example.com", "pbk", "required"},
		{"pbk of 31 bytes", v + "?security=reality&sni=www.example.com&pbk=" +
			base64.RawURLEncoding.EncodeToString(make([]byte, 31)), "pbk", "32 bytes"},
		{"pbk not base64", v + "?security=reality&sni=www.example.com&pbk=not%20base64", "pbk", "32 bytes"},
		{"sid odd", reality + "&sid=abc", "sid", "even"},
		{"sid of 18", reality + "&sid=" + strings.Repeat("ab", 9), "sid", "16 hex"},
		{"sid not hex", reality + "&sid=zz", "sid", "hex"},
		{"spx without slash", reality + "&spx=search", "spx", "\"/\""},
		{"pqv wrong size", reality + "&pqv=" + base64.RawURLEncoding.EncodeToString(make([]byte, 100)), "pqv", "1952"},
		{"reality fp random", reality + "&fp=random", "fp", "chrome, firefox or safari"},
		{"tls fp unknown", tlsV + "fp=netscape", "fp", "randomized"},
		{"alpn h4", tlsV + "alpn=h2,h4", "alpn", "h2, http/1.1 or h3"},
		{"alpn empty item", tlsV + "alpn=h2,,h3", "alpn", "not supported"},
		{"pcs too short", tlsV + "pcs=abcd", "pcs", "64 hex"},
		{"pcs not hex", tlsV + "pcs=" + strings.Repeat("zz", 32), "pcs", "64 hex"},
		{"vcn not a hostname", tlsV + "vcn=a.example.com,bad_name", "vcn", "hostname cannot"},
		{"tls sni idn", tlsV + "sni=%E4%BE%8B%E3%81%88.jp", "sni", "punycode"},
		{"allowInsecure without pin", tlsV + "allowInsecure=1", "allowInsecure", "Xray 26 removed allowInsecure; pin the certificate with pcs instead"},
		{"insecure true without pin", tlsV + "insecure=true", "insecure", "pcs"},
		{"insecure not a flag", tlsV + "insecure=yes", "insecure", "1, 0, true or false"},
		{"ws path without slash", tlsV + "type=ws&path=ws", "path", "\"/\""},
		{"xhttp mode unknown", tlsV + "type=xhttp&mode=stream", "mode", "stream-one"},
		{"grpc without serviceName", tlsV + "type=grpc", "serviceName", "required"},
		{"grpc mode unknown", tlsV + "type=grpc&serviceName=s&mode=tun", "mode", "gun or multi"},
		{"ech", tlsV + "ech=AEn%2B", "ech", "not supported yet"},
		{"fm", tlsV + "fm=x", "fm", "not supported yet"},
		{"extra", tlsV + "type=xhttp&extra=%7B%7D", "extra", "not supported yet"},
		{"plain vless to a hostname", v + "?type=tcp", "security", "prohibits vless"},
		{"plain vless to a public ip", "vless://" + tUUID + "@8.8.8.8:443?security=none", "security", "prohibits vless"},
		{"plain vless to a link-local ip", "vless://" + tUUID + "@169.254.1.1:443", "security", "prohibits vless"},

		// Trojan.
		{"trojan without password", "trojan://example.com:443", "userinfo", "missing"},
		{"trojan empty password", "trojan://@example.com:443", "userinfo", "missing"},
		{"trojan flow", "trojan://pw@example.com:443?flow=xtls-rprx-vision", "flow", "Trojan has no flow"},
		{"trojan peer differs from sni", "trojan://pw@example.com?sni=a.example.com&peer=b.example.com", "peer", "differs"},
		{"plain trojan to a public ip", "trojan://pw@203.0.113.1:443?security=none", "security", "prohibits trojan"},
		{"trojan type kcp", "trojan://pw@example.com?type=kcp", "type", "not supported"},

		// Shadowsocks.
		{"ss method none", "ss://none:pw@example.com:8388", "userinfo", "\"none\" is not supported"},
		{"ss method plain", "ss://plain:pw@example.com:8388", "userinfo", "not supported"},
		{"ss stream cipher", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-cfb:pw")) + "@example.com:8388",
			"userinfo", "\"aes-256-cfb\" is not supported"},
		{"ss rc4-md5", "ss://rc4-md5:pw@example.com:8388", "userinfo", "not supported"},
		{"ss empty password", "ss://aes-256-gcm:@example.com:8388", "userinfo", "password is missing"},
		{"ss userinfo not base64", "ss://not!base64@example.com:8388", "userinfo", "neither"},
		{"ss base64 without colon", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm")) + "@example.com:8388",
			"userinfo", "neither"},
		{"ss legacy without host", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")), "userinfo", "neither"},
		{"ss legacy not base64", "ss://!!!", "userinfo", "neither"},
		{"ss plugin", "ss://" + tSSURL + "@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp", "plugin", "Xray does not run SIP003 plugins"},
		{"ss without port", "ss://" + tSSURL + "@example.com", "port", "required"},
		{"ss 2022 chacha with two keys", "ss://2022-blake3-chacha20-poly1305:" + tKey32 + ":" + tKey32 + "@example.com:443",
			"userinfo", "single key"},

		// SOCKS.
		{"socks user without password", "socks5://user@example.com:1080", "userinfo", "no password"},
		{"socks empty password", "socks5://user:@example.com:1080", "userinfo", "password must be"},
		{"socks empty user", "socks5://:pass@example.com:1080", "userinfo", "user must be"},
		{"socks empty userinfo", "socks5://@example.com:1080", "userinfo", "empty"},
		{"socks user of 256 bytes", "socks5://" + strings.Repeat("u", 256) + ":p@example.com:1080", "userinfo", "1 to 255"},
		{"socks password of 256 bytes", "socks5://u:" + strings.Repeat("p", 256) + "@example.com:1080", "userinfo", "1 to 255"},
		{"socks base64 is only for socks://", "socks5://" + base64.StdEncoding.EncodeToString([]byte("u:p")) + "@example.com:1080",
			"userinfo", "no password"},
		{"socks base64 without colon", "socks://" + base64.StdEncoding.EncodeToString([]byte("user")) + "@example.com:1080",
			"userinfo", "no password"},
		{"socks without port", "socks5://example.com", "port", "required"},

		// Hysteria2.
		{"hy2 port hopping list", "hy2://auth@example.com:443,8443?sni=example.com", "port", "port hopping is not supported"},
		{"hy2 port hopping range", "hysteria2://auth@[2001:db8::1]:20000-30000/", "port", "port hopping is not supported"},
		{"hy2 without auth", "hy2://example.com:443", "userinfo", "auth is missing"},
		{"hy2 empty auth", "hy2://@example.com:443", "userinfo", "auth is missing"},
		{"hy2 obfs gecko", "hy2://auth@example.com?obfs=gecko&obfs-password=x", "obfs", "gecko"},
		{"hy2 obfs unknown", "hy2://auth@example.com?obfs=xor", "obfs", "not supported"},
		{"hy2 salamander without password", "hy2://auth@example.com?obfs=salamander", "obfs-password", "required"},
		{"hy2 obfs password without obfs", "hy2://auth@example.com?obfs-password=x", "obfs-password", "salamander"},
		{"hy2 insecure without pin", "hy2://auth@example.com?insecure=1", "insecure", "pinSHA256"},
		{"hy2 bad pin", "hy2://auth@example.com?pinSHA256=abc", "pinSHA256", "64 hex"},
		{"hy2 ech", "hy2://auth@example.com?ech=AEn", "ech", "not supported yet"},
		{"hy2 bad sni", "hy2://auth@example.com?sni=bad_name", "sni", "hostname cannot"},
		{"hy2 port 0", "hy2://auth@example.com:0", "port", "1 to 65535"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, tag, err := Parse(tc.link)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Parse(%q) = %s, %q, %v; want *Error", tc.link, show(p), tag, err)
			}
			if e.Part != tc.part || !strings.Contains(e.Problem, tc.problem) {
				t.Fatalf("error = %q (part %q); want part %q with %q", err, e.Part, tc.part, tc.problem)
			}
			if err.Error() != "link "+e.Part+": "+e.Problem {
				t.Fatalf("Error() = %q", err.Error())
			}
			if !reflect.DeepEqual(p, model.ExitParams{}) || tag != "" {
				t.Fatalf("failed Parse returned %s, %q", show(p), tag)
			}
		})
	}
}

// TestParseNeverEchoesKeys checks that problems with Shadowsocks 2022 keys name the rule, not the key.
func TestParseNeverEchoesKeys(t *testing.T) {
	short := base64.StdEncoding.EncodeToString([]byte("sixteen-byte-key"))
	unpadded := strings.TrimRight(tKey16a, "=")
	for _, link := range []string{
		"ss://2022-blake3-aes-256-gcm:" + short + "@example.com:443",
		"ss://2022-blake3-aes-128-gcm:" + unpadded + "@example.com:443",
		"ss://2022-blake3-aes-128-gcm:" + tKey16a + ":" + short + "x@example.com:443",
		"ss://" + base64.StdEncoding.EncodeToString([]byte("2022-blake3-aes-256-gcm:"+short)) + "@example.com:443",
	} {
		_, _, err := Parse(link)
		var e *Error
		if !errors.As(err, &e) || e.Part != "userinfo" || !strings.Contains(e.Problem, "standard base64") {
			t.Fatalf("Parse(%q) = %v; want a userinfo key error", link, err)
		}
		for _, secret := range []string{short, unpadded, "c2l4dGVlbi"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error %q echoes the key", err)
			}
		}
	}
}

// TestParsePanelLinks checks that the links this panel renders for its own lines parse back.
func TestParsePanelLinks(t *testing.T) {
	const host = "203.0.113.7"
	client := model.Client{ID: 7, Name: "phone", Secret: tUUID, SubToken: "tok"}
	hyClient := client
	hyClient.Secret = "pa:ss@w/rd é#?"
	cases := []struct {
		name   string
		line   model.Line
		client model.Client
		check  func(t *testing.T, p model.ExitParams)
	}{
		{
			name: "reality",
			line: model.Line{
				ID: 1, Name: "Tokyo #1", Protocol: model.VLESSReality, Port: 443, Enabled: true,
				Reality: &model.RealityParams{
					PrivateKey: "PRIV", PublicKey: tPBKURL, ShortID: "6ba85179e30d4fc2",
					ServerName: "www.example.com", Target: "www.example.com:443",
				},
			},
			client: client,
			check: func(t *testing.T, p model.ExitParams) {
				if p.Reality == nil || p.TLS != nil {
					t.Fatalf("security = %s, want reality", show(p))
				}
				r := p.Reality
				if r.ServerName != "www.example.com" || r.PublicKey != tPBKURL || r.ShortID != "6ba85179e30d4fc2" {
					t.Errorf("reality = %+v", *r)
				}
				if p.Flow != visionFlow || p.Transport.Network != model.ExitRaw {
					t.Errorf("flow %q network %q", p.Flow, p.Transport.Network)
				}
			},
		},
		{
			name: "xhttp tls",
			line: model.Line{
				ID: 2, Name: "XH", Protocol: model.VLESSXHTTP, Port: 8443, Enabled: true,
				XHTTP: &model.XHTTPParams{Path: "/x h?y", Domain: "xh.example.com", Security: model.XHTTPTLS},
			},
			client: client,
			check: func(t *testing.T, p model.ExitParams) {
				if p.TLS == nil || p.TLS.ServerName != "xh.example.com" {
					t.Fatalf("tls = %s", show(p))
				}
				if tr := p.Transport; tr.Network != model.ExitXHTTP || tr.Path != "/x h?y" || tr.Host != "xh.example.com" {
					t.Errorf("transport = %+v", tr)
				}
			},
		},
		{
			name: "xhttp plain behind a cdn",
			line: model.Line{
				ID: 3, Name: "CDN", Protocol: model.VLESSXHTTP, Port: 2080, Enabled: true,
				XHTTP: &model.XHTTPParams{Path: "/cdn", Domain: "cdn.example.com", Security: model.XHTTPPlain},
			},
			client: client,
			check: func(t *testing.T, p model.ExitParams) {
				if p.TLS == nil || p.TLS.ServerName != "cdn.example.com" {
					t.Fatalf("tls = %s", show(p))
				}
				if tr := p.Transport; tr.Network != model.ExitXHTTP || tr.Path != "/cdn" {
					t.Errorf("transport = %+v", tr)
				}
			},
		},
		{
			name: "hysteria2 without obfs",
			line: model.Line{
				ID: 4, Name: "Hy", Protocol: model.Hysteria2, Port: 8443, Enabled: true,
				Hysteria2: &model.Hysteria2Params{Domain: "hy.example.com"},
			},
			client: hyClient,
			check: func(t *testing.T, p model.ExitParams) {
				if p.ObfsPassword != "" || p.TLS == nil || p.TLS.ServerName != "hy.example.com" {
					t.Errorf("params = %s", show(p))
				}
			},
		},
		{
			name: "hysteria2 with salamander",
			line: model.Line{
				ID: 5, Name: "Hy obfs", Protocol: model.Hysteria2, Port: 8443, Enabled: true,
				Hysteria2: &model.Hysteria2Params{Domain: "hy.example.com", ObfsPassword: "ob&f s"},
			},
			client: hyClient,
			check: func(t *testing.T, p model.ExitParams) {
				if p.ObfsPassword != "ob&f s" || p.TLS == nil || p.TLS.ServerName != "hy.example.com" {
					t.Errorf("params = %s", show(p))
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, err := share.Link(tc.line, tc.client, host)
			if err != nil {
				t.Fatalf("share.Link: %v", err)
			}
			p, tag, err := Parse(link)
			if err != nil {
				t.Fatalf("Parse(%s): %v", link, err)
			}
			wantHost, wantPort := host, tc.line.Port
			if tc.line.XHTTP != nil && tc.line.XHTTP.Security == model.XHTTPPlain {
				wantHost, wantPort = tc.line.XHTTP.Domain, 443
			}
			if p.Host != wantHost || p.Port != wantPort {
				t.Errorf("dial %s:%d, want %s:%d", p.Host, p.Port, wantHost, wantPort)
			}
			if p.Secret != tc.client.Secret {
				t.Errorf("secret = %q, want %q", p.Secret, tc.client.Secret)
			}
			if tag != tc.line.Name {
				t.Errorf("name = %q, want %q", tag, tc.line.Name)
			}
			tc.check(t, p)
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, tc := range validCases() {
		f.Add(tc.link)
	}
	f.Add("ss://" + tSSStd)
	f.Add("hy2://a@[::1]:1-2,3")
	f.Fuzz(func(t *testing.T, link string) {
		p, _, err := Parse(link)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Part == "" || e.Problem == "" {
				t.Fatalf("Parse(%q) error %v is not a complete *Error", link, err)
			}
			return
		}
		if !p.Protocol.Valid() || p.Host == "" || p.Port < 1 || p.Port > 65535 {
			t.Fatalf("Parse(%q) = %s", link, show(p))
		}
		if p.TLS != nil && p.Reality != nil {
			t.Fatalf("Parse(%q) set both TLS and REALITY", link)
		}
		// What the parser accepts the engine must be able to dial: a link that saves but later
		// fails to build would only show up as a 502 when a line is wired to it.
		if _, err := engine.ExitOutbound(1, "via-1", p, "", false); err != nil {
			t.Fatalf("Parse(%q) accepted params the engine refuses: %v", link, err)
		}
	})
}
