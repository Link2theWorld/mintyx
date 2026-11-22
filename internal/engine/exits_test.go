package engine

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ysuhao/mintyx-next/internal/model"
)

// testPublicKey is RFC 7748 §6.1 Alice's public key in base64url.
const testPublicKey = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"

func realityExit(id int64, next int64) model.Exit {
	return model.Exit{ID: id, Name: "reality", NextID: next, Params: model.ExitParams{
		Protocol: model.ExitVLESS, Host: "203.0.113.7", Port: 443, Secret: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow: "xtls-rprx-vision", Encryption: "none", Transport: model.ExitTransport{Network: model.ExitRaw},
		Reality: &model.ExitReality{ServerName: "www.example.com", Fingerprint: "chrome", PublicKey: testPublicKey, ShortID: "0123abcd"},
	}}
}

func hy2Exit(id, next int64) model.Exit {
	return model.Exit{ID: id, Name: "hy2", NextID: next, Params: model.ExitParams{
		Protocol: model.ExitHysteria2, Host: "198.51.100.9", Port: 443, Secret: "hy-auth", ObfsPassword: "obfs-pass",
		TLS: &model.ExitTLS{ServerName: "hy.example.com", ALPN: []string{"h3"}},
	}}
}

func ssExit(id, next int64) model.Exit {
	return model.Exit{ID: id, Name: "ss", NextID: next, Params: model.ExitParams{
		Protocol: model.ExitShadowsocks, Host: "203.0.113.9", Port: 8388, Method: "2022-blake3-aes-128-gcm",
		Secret: "AAAAAAAAAAAAAAAAAAAAAA==",
	}}
}

func outboundByTag(t *testing.T, cfg jsonObj, tag string) jsonObj {
	t.Helper()
	for _, o := range at(t, cfg, "outbounds").([]any) {
		if o.(jsonObj)["tag"] == tag {
			return o.(jsonObj)
		}
	}
	t.Fatalf("no outbound tagged %q", tag)
	return nil
}

func buildWithExits(t *testing.T, lines []model.Line, exits []model.Exit) jsonObj {
	t.Helper()
	out, err := BuildConfig(lines, testClients, exits, Options{APIPort: 10085})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var cfg jsonObj
	if err := jsonUnmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestExitOutboundShapes(t *testing.T) {
	tests := []struct {
		name string
		exit model.Exit
		want string
	}{
		{"vless reality vision", realityExit(1, 0),
			`{"protocol":"vless","settings":{"address":"203.0.113.7","encryption":"none","flow":"xtls-rprx-vision","id":"b831381d-6324-4d53-ad4f-8cda48b30811","port":443},"streamSettings":{"network":"raw","realitySettings":{"fingerprint":"chrome","password":"` + testPublicKey + `","serverName":"www.example.com","shortId":"0123abcd"},"security":"reality"},"tag":"via-1"}`},
		{"trojan ws tls", model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitTrojan, Host: "t.example.com", Port: 443, Secret: "pw",
			Transport: model.ExitTransport{Network: model.ExitWS, Path: "/ws", Host: "cdn.example.com"},
			TLS:       &model.ExitTLS{ServerName: "t.example.com", ALPN: []string{"h2", "http/1.1"}, PinSHA256: "ab"}}},
			`{"protocol":"trojan","settings":{"address":"t.example.com","password":"pw","port":443},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"],"fingerprint":"chrome","pinnedPeerCertSha256":"ab","serverName":"t.example.com"},"wsSettings":{"host":"cdn.example.com","path":"/ws"}},"tag":"via-1"}`},
		{"vless xhttp tls", model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "x.example.com", Port: 443, Secret: "id",
			Transport: model.ExitTransport{Network: model.ExitXHTTP, Path: "/p"}, TLS: &model.ExitTLS{ServerName: "x.example.com"}}},
			`{"protocol":"vless","settings":{"address":"x.example.com","encryption":"none","id":"id","port":443},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"fingerprint":"chrome","serverName":"x.example.com"},"xhttpSettings":{"mode":"auto","path":"/p"}},"tag":"via-1"}`},
		{"vless grpc multi", model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "g.example.com", Port: 443, Secret: "id",
			Transport: model.ExitTransport{Network: model.ExitGRPC, ServiceName: "svc", Authority: "a.example.com", MultiMode: true},
			TLS:       &model.ExitTLS{ServerName: "g.example.com"}}},
			`{"protocol":"vless","settings":{"address":"g.example.com","encryption":"none","id":"id","port":443},"streamSettings":{"grpcSettings":{"authority":"a.example.com","multiMode":true,"serviceName":"svc"},"network":"grpc","security":"tls","tlsSettings":{"fingerprint":"chrome","serverName":"g.example.com"}},"tag":"via-1"}`},
		{"shadowsocks", ssExit(1, 0),
			`{"protocol":"shadowsocks","settings":{"address":"203.0.113.9","method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==","port":8388},"tag":"via-1"}`},
		{"socks with auth", model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitSOCKS, Host: "203.0.113.10", Port: 1080, Username: "u", Secret: "p"}},
			`{"protocol":"socks","settings":{"address":"203.0.113.10","pass":"p","port":1080,"user":"u"},"tag":"via-1"}`},
		{"socks without auth", model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitSOCKS, Host: "203.0.113.10", Port: 1080}},
			`{"protocol":"socks","settings":{"address":"203.0.113.10","port":1080},"tag":"via-1"}`},
		{"hysteria2 salamander", hy2Exit(1, 0),
			`{"protocol":"hysteria","settings":{"address":"198.51.100.9","port":443,"version":2},"streamSettings":{"finalmask":{"udp":[{"settings":{"password":"obfs-pass"},"type":"salamander"}]},"hysteriaSettings":{"auth":"hy-auth","version":2},"network":"hysteria","security":"tls","tlsSettings":{"alpn":["h3"],"serverName":"hy.example.com"}},"tag":"via-1"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ExitOutbound(tt.exit.ID, "via-1", tt.exit.Params, "", false)
			if err != nil {
				t.Fatal(err)
			}
			if got := mustJSON(t, out); got != tt.want {
				t.Errorf("outbound =\n  %s\nwant\n  %s", got, tt.want)
			}
		})
	}
}

func TestExitChainsShareOutboundsAndRouteAfterTheBlockRule(t *testing.T) {
	// L1 → 1 → 2 and L2 → 1 → 2 share both outbounds; L3 → 3 → 2 reaches 2 through another
	// dialer, so 2 is emitted twice under different paths; L4 has no exit.
	exits := []model.Exit{ssExit(2, 0), realityExit(1, 2), realityExit(3, 2), ssExit(9, 0)}
	lines := []model.Line{realityLine(1, 443), realityLine(2, 444), realityLine(3, 445), realityLine(4, 446)}
	lines[0].ExitID, lines[1].ExitID, lines[2].ExitID = 1, 1, 3
	cfg := buildWithExits(t, lines, exits)

	var tags []string
	for _, o := range at(t, cfg, "outbounds").([]any) {
		tags = append(tags, o.(jsonObj)["tag"].(string))
	}
	if want := []string{"direct", "block", "via-1", "via-1-2", "via-3", "via-3-2"}; !slices.Equal(tags, want) {
		t.Fatalf("outbound tags = %v, want %v (exit 9 is not wired, so absent)", tags, want)
	}
	assertEqual(t, "via-1-2 sockopt", at(t, outboundByTag(t, cfg, "via-1-2"), "streamSettings", "sockopt"), jsonObj{"dialerProxy": "via-1"})
	assertEqual(t, "via-3-2 sockopt", at(t, outboundByTag(t, cfg, "via-3-2"), "streamSettings", "sockopt"), jsonObj{"dialerProxy": "via-3"})
	if _, has := outboundByTag(t, cfg, "via-1")["streamSettings"].(jsonObj)["sockopt"]; has {
		t.Error("the first hop must dial directly")
	}

	if ds := at(t, cfg, "routing", "domainStrategy"); ds != "IPOnDemand" {
		t.Errorf("domainStrategy with exits = %v, want IPOnDemand so names are resolved for the block rule", ds)
	}
	rules := at(t, cfg, "routing", "rules").([]any)
	if len(rules) != 5 || rules[1].(jsonObj)["outboundTag"] != blockTag {
		t.Fatalf("rules = %v, want api, block, then one rule per chained line", rules)
	}
	for i, want := range []struct{ line, tag string }{{"line-1", "via-1-2"}, {"line-2", "via-1-2"}, {"line-3", "via-3-2"}} {
		assertEqual(t, "rule", rules[2+i], jsonObj{"inboundTag": []any{want.line}, "outboundTag": want.tag})
	}
}

func TestVisionLetsUDP443ThroughToAHysteria2Hop(t *testing.T) {
	lines := []model.Line{realityLine(1, 443), realityLine(2, 444)}
	lines[0].ExitID, lines[1].ExitID = 1, 3
	trojan := model.Exit{ID: 3, NextID: 4, Params: model.ExitParams{Protocol: model.ExitTrojan, Host: "t.example.com", Port: 443, Secret: "pw",
		TLS: &model.ExitTLS{ServerName: "t.example.com"}}}
	cfg := buildWithExits(t, lines, []model.Exit{realityExit(1, 2), hy2Exit(2, 0), trojan, hy2Exit(4, 0)})
	if flow := at(t, outboundByTag(t, cfg, "via-1"), "settings", "flow"); flow != visionUDP443Flow {
		t.Errorf("Vision in front of Hysteria2 has flow %v, want %s", flow, visionUDP443Flow)
	}
	if _, has := at(t, outboundByTag(t, cfg, "via-3"), "settings").(jsonObj)["flow"]; has {
		t.Error("Trojan in front of Hysteria2 gained a flow")
	}
	assertEqual(t, "hysteria hop dialer", at(t, outboundByTag(t, cfg, "via-1-2"), "streamSettings", "sockopt"), jsonObj{"dialerProxy": "via-1"})
}

func TestExitChainErrors(t *testing.T) {
	line := realityLine(1, 443)
	tests := []struct {
		name  string
		first int64
		exits []model.Exit
		check func(error) bool
	}{
		{"missing first exit", 5, nil, func(err error) bool {
			var le *LineError
			return errors.As(err, &le) && le.LineID == 1 && le.Field == "ExitID"
		}},
		{"missing next exit", 1, []model.Exit{realityExit(1, 8)}, func(err error) bool {
			var ee *ExitError
			return errors.As(err, &ee) && ee.ExitID == 1 && ee.Field == "NextID"
		}},
		{"loop", 1, []model.Exit{realityExit(1, 2), realityExit(2, 1)}, func(err error) bool {
			var ee *ExitError
			return errors.As(err, &ee) && ee.Field == "NextID" && strings.Contains(ee.Problem, "loop")
		}},
		{"too long", 1, []model.Exit{realityExit(1, 2), realityExit(2, 3), realityExit(3, 4), realityExit(4, 5), realityExit(5, 0)}, func(err error) bool {
			var ee *ExitError
			return errors.As(err, &ee) && ee.ExitID == 1 && strings.Contains(ee.Problem, "more than")
		}},
		{"bad params", 1, []model.Exit{{ID: 1, Params: model.ExitParams{Protocol: model.ExitShadowsocks, Host: "h", Port: 1, Method: "rc4-md5", Secret: "k"}}}, func(err error) bool {
			var ee *ExitError
			return errors.As(err, &ee) && ee.Field == "Method"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := line
			l.ExitID = tt.first
			_, err := BuildConfig([]model.Line{l}, testClients, tt.exits, Options{APIPort: 10085})
			if !tt.check(err) {
				t.Fatalf("err = %v", err)
			}
		})
	}

	// Broken exits nobody uses, or used only by a disabled line, never fail the build.
	broken := model.Exit{ID: 7, Params: model.ExitParams{Protocol: model.ExitShadowsocks, Host: "h", Port: 1, Method: "rc4-md5"}}
	off := realityLine(2, 444)
	off.Enabled, off.ExitID = false, 7
	if _, err := BuildConfig([]model.Line{line, off}, testClients, []model.Exit{broken}, Options{APIPort: 10085}); err != nil {
		t.Fatalf("an unwired broken exit failed the build: %v", err)
	}
}

func TestExitRoutingInvariantsOnRandomGraphs(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for round := range 200 {
		n := 1 + r.IntN(6)
		var exits []model.Exit
		for id := int64(1); id <= int64(n); id++ {
			var next int64
			if r.IntN(2) == 0 {
				next = 1 + r.Int64N(int64(n))
			}
			e := ssExit(id, next)
			if r.IntN(3) == 0 {
				e = hy2Exit(id, next)
			}
			exits = append(exits, e)
		}
		var lines []model.Line
		for id := int64(1); id <= 4; id++ {
			l := realityLine(id, 440+int(id))
			if r.IntN(4) > 0 {
				l.ExitID = 1 + r.Int64N(int64(n))
			}
			lines = append(lines, l)
		}
		out, err := BuildConfig(lines, testClients, exits, Options{APIPort: 10085})
		if err != nil {
			var ee *ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("round %d: unexpected error type %v", round, err)
			}
			continue // loops and long chains are refused; that is fine
		}
		var cfg jsonObj
		if err := jsonUnmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		outs := at(t, cfg, "outbounds").([]any)
		if outs[0].(jsonObj)["tag"] != directTag {
			t.Fatalf("round %d: first outbound is %v, want direct", round, outs[0])
		}
		tags := map[string]bool{}
		for _, o := range outs {
			tag := o.(jsonObj)["tag"].(string)
			if tags[tag] {
				t.Fatalf("round %d: duplicate tag %s", round, tag)
			}
			tags[tag] = true
		}
		for _, o := range outs {
			stream, _ := o.(jsonObj)["streamSettings"].(jsonObj)
			sockopt, _ := stream["sockopt"].(jsonObj)
			if d, ok := sockopt["dialerProxy"].(string); ok {
				tag := o.(jsonObj)["tag"].(string)
				if !tags[d] || !strings.HasPrefix(tag, d+"-") {
					t.Fatalf("round %d: %s dials through %s, which is missing or not its prefix", round, tag, d)
				}
			}
		}
		for _, rule := range at(t, cfg, "routing", "rules").([]any) {
			if tag := rule.(jsonObj)["outboundTag"].(string); !tags[tag] && tag != apiTag {
				t.Fatalf("round %d: rule points at missing outbound %s", round, tag)
			}
		}
	}
}

func TestExitConfigIsDeterministic(t *testing.T) {
	exits := []model.Exit{ssExit(2, 0), realityExit(1, 2), hy2Exit(3, 0)}
	lines := []model.Line{realityLine(1, 443), realityLine(2, 444), realityLine(3, 445)}
	lines[0].ExitID, lines[1].ExitID = 1, 3
	first, err := BuildConfig(lines, testClients, exits, Options{APIPort: 10085})
	if err != nil {
		t.Fatal(err)
	}
	r := rand.New(rand.NewPCG(3, 4))
	for range 20 {
		r.Shuffle(len(exits), func(i, j int) { exits[i], exits[j] = exits[j], exits[i] })
		r.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
		again, err := BuildConfig(lines, testClients, exits, Options{APIPort: 10085})
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("shuffled input changed the config")
		}
	}
}

// TestExitConfigValidatesWithRealXray needs a real binary: XRAY_BIN=/path/to/xray go test ./internal/engine/
func TestExitConfigValidatesWithRealXray(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN not set")
	}
	priv, pub, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	reality := realityExit(1, 2)
	reality.Params.Reality.PublicKey = pub
	trojanWS := model.Exit{ID: 4, NextID: 5, Params: model.ExitParams{Protocol: model.ExitTrojan, Host: "t.example.com", Port: 443, Secret: "pw",
		Transport: model.ExitTransport{Network: model.ExitWS, Path: "/ws"}, TLS: &model.ExitTLS{ServerName: "t.example.com"}}}
	grpc := model.Exit{ID: 5, NextID: 6, Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "g.example.com", Port: 443, Secret: NewUUID(),
		Transport: model.ExitTransport{Network: model.ExitGRPC, ServiceName: "svc", MultiMode: true}, TLS: &model.ExitTLS{ServerName: "g.example.com"}}}
	xhttp := model.Exit{ID: 6, Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "x.example.com", Port: 443, Secret: NewUUID(),
		Transport: model.ExitTransport{Network: model.ExitXHTTP, Path: "/x"}, TLS: &model.ExitTLS{ServerName: "x.example.com", PinSHA256: strings.Repeat("ab", 32)}}}
	socks := model.Exit{ID: 7, NextID: 3, Params: model.ExitParams{Protocol: model.ExitSOCKS, Host: "203.0.113.10", Port: 1080, Username: "u", Secret: "p"}}
	exits := []model.Exit{reality, hy2Exit(2, 0), ssExit(3, 0), trojanWS, grpc, xhttp, socks}

	lines := []model.Line{realityLine(1, 24441), realityLine(2, 24442), realityLine(3, 24443)}
	for i := range lines {
		lines[i].Reality.PrivateKey = priv
	}
	lines[0].ExitID, lines[1].ExitID, lines[2].ExitID = 1, 4, 7
	cfg, err := BuildConfig(lines, []model.Client{{ID: 1, Secret: NewUUID()}}, exits, Options{APIPort: 24440})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(context.Background(), bin, cfg); err != nil {
		t.Fatalf("xray rejected the config with exits: %v\n%s", err, cfg)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// The parser checks only the shape of a VLESS Encryption string; Xray checks the rest, and the
// panel rolls wiring back when it refuses. This pins that Xray does refuse a misspelt mode.
func TestXrayRefusesAMisspeltVLESSEncryption(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN not set")
	}
	priv, _, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	exit := model.Exit{ID: 1, Params: model.ExitParams{Protocol: model.ExitVLESS, Host: "198.51.100.9", Port: 443, Secret: NewUUID(),
		Encryption: "mlkem768x25519plus.natve.0rtt.AbC_d-e9", Transport: model.ExitTransport{Network: model.ExitRaw}}}
	line := realityLine(1, 24451)
	line.Reality.PrivateKey, line.ExitID = priv, 1
	cfg, err := BuildConfig([]model.Line{line}, []model.Client{{ID: 1, Secret: NewUUID()}}, []model.Exit{exit}, Options{APIPort: 24450})
	if err != nil {
		t.Fatal(err)
	}
	var cte *ConfigTestError
	if err := Validate(context.Background(), bin, cfg); !errors.As(err, &cte) {
		t.Fatalf("Validate = %v, want Xray to refuse the misspelt encryption", err)
	}
}
