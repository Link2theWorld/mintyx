package e2e

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/engine"
	"github.com/Link2theWorld/mintyx/internal/exitlink"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/share"
)

// pinnedLink is the product's share link for l and c, with the self-signed certificate pinned
// the way an exit link to such a server would carry it.
func pinnedLink(t *testing.T, l model.Line, c model.Client, trustPEM []byte) string {
	t.Helper()
	link, err := share.Link(l, c, dialHost)
	if err != nil {
		t.Fatalf("share.Link: %v", err)
	}
	if trustPEM == nil {
		return link
	}
	key := "pcs"
	if l.Protocol == model.Hysteria2 {
		key = "pinSHA256"
	}
	body, frag, _ := strings.Cut(link, "#")
	sep := "&"
	if !strings.Contains(body, "?") {
		sep = "?"
	}
	return body + sep + key + "=" + certFingerprint(t, trustPEM) + "#" + frag
}

// exitBuilderClient runs an Xray client whose outbound comes from the product's share link
// through the exit parser and the exit outbound builder: what an exit pointing at this line uses.
func exitBuilderClient(trustPEM []byte) func(*testing.T, model.Line, model.Client) string {
	return func(t *testing.T, l model.Line, c model.Client) string {
		link := pinnedLink(t, l, c, trustPEM)
		p, _, err := exitlink.Parse(link)
		if err != nil {
			t.Fatalf("exitlink.Parse(%s): %v", link, err)
		}
		out, err := engine.ExitOutbound(1, "out", p, "", false)
		if err != nil {
			t.Fatalf("ExitOutbound: %v", err)
		}
		return startXrayClient(t, out)
	}
}

// middleHop is a hand-written Xray proxy that forwards anywhere, loopback included, so the
// product servers on 127.0.0.1 behind it are reachable. It logs every accepted destination.
type middleHop struct {
	link string
	out  *syncBuffer
}

// loopbackFreedom forwards to 127.0.0.1 too: Xray 26's freedom refuses private addresses by
// default, and here the next hop is a product server on loopback.
var loopbackFreedom = map[string]any{"protocol": "freedom", "settings": map[string]any{
	"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.0/8"}}},
}}

func startSS2022Hop(t *testing.T, key string) middleHop {
	t.Helper()
	port := freeTCPPort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": dialHost, "port": port, "protocol": "shadowsocks",
			"settings": map[string]any{"method": "2022-blake3-aes-128-gcm", "password": key, "network": "tcp,udp"},
		}},
		"outbounds": []any{loopbackFreedom},
	}
	path, data := writeJSON(t, "ss-hop.json", cfg)
	out := startChild(t, xrayBin(t), "run", "-c", path)
	waitTCP(t, net.JoinHostPort(dialHost, strconv.Itoa(port)), "SS hop", func() string { return out.String() + "\n" + string(data) })
	return middleHop{link: fmt.Sprintf("ss://2022-blake3-aes-128-gcm:%s@%s:%d#ss-hop", key, dialHost, port), out: out}
}

func startSOCKSHop(t *testing.T) middleHop {
	t.Helper()
	port := freeTCPPort(t)
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "info"},
		"inbounds": []any{map[string]any{
			"listen": dialHost, "port": port, "protocol": "socks",
			"settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "hop", "pass": "hop-pass"}}, "udp": true, "ip": dialHost},
		}},
		"outbounds": []any{loopbackFreedom},
	}
	path, data := writeJSON(t, "socks-hop.json", cfg)
	out := startChild(t, xrayBin(t), "run", "-c", path)
	waitTCP(t, net.JoinHostPort(dialHost, strconv.Itoa(port)), "SOCKS hop", func() string { return out.String() + "\n" + string(data) })
	return middleHop{link: fmt.Sprintf("socks5://hop:hop-pass@%s:%d#socks-hop", dialHost, port), out: out}
}

func ss2022Key() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func realityLineAt(t *testing.T, id int64) model.Line {
	t.Helper()
	priv, pub, err := engine.NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return model.Line{ID: id, Name: "reality", Protocol: model.VLESSReality, Port: freeTCPPort(t), Enabled: true,
		Reality: &model.RealityParams{PrivateKey: priv, PublicKey: pub, ShortID: engine.NewShortID(), ServerName: realitySite, Target: realitySite + ":443"}}
}

func parseExit(t *testing.T, id, next int64, link string) model.Exit {
	t.Helper()
	p, name, err := exitlink.Parse(link)
	if err != nil {
		t.Fatalf("exitlink.Parse(%s): %v", link, err)
	}
	return model.Exit{ID: id, Name: name, NextID: next, Params: p}
}

// TestExitChains sends a visitor's traffic in through an entry server's line, on through a middle
// hop, out of a last-hop product server, and checks each of them saw it pass.
func TestExitChains(t *testing.T) {
	xrayBin(t)
	requireInternet(t)
	cert := selfSignedCert(t)
	tests := []struct {
		name   string
		middle func(t *testing.T) middleHop
		last   func(t *testing.T) (model.Line, []byte)
		proto  string
	}{
		{"shadowsocks 2022 then REALITY", func(t *testing.T) middleHop { return startSS2022Hop(t, ss2022Key()) },
			func(t *testing.T) (model.Line, []byte) { return realityLineAt(t, 7), nil }, "tcp"},
		{"shadowsocks 2022 then Hysteria2 over UDP", func(t *testing.T) middleHop { return startSS2022Hop(t, ss2022Key()) },
			func(t *testing.T) (model.Line, []byte) {
				return model.Line{ID: 7, Name: "hy2", Protocol: model.Hysteria2, Port: freeUDPPort(t), Enabled: true,
					Hysteria2: &model.Hysteria2Params{Domain: certDomain, CertFile: cert.certFile, KeyFile: cert.keyFile, ObfsPassword: engine.NewPassword()}}, cert.certPEM
			}, "udp"},
		{"SOCKS5 then REALITY with Vision", startSOCKSHop,
			func(t *testing.T) (model.Line, []byte) { return realityLineAt(t, 7), nil }, "tcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastLine, trust := tt.last(t)
			lastClient, _ := clients(engine.NewUUID)
			if lastLine.Protocol == model.Hysteria2 {
				lastClient, _ = clients(engine.NewPassword)
			}
			last := startServerWith(t, []model.Line{lastLine}, []model.Client{lastClient}, nil)
			middle := tt.middle(t)

			entryLine := realityLineAt(t, 1)
			entryLine.ExitID = 1
			exits := []model.Exit{parseExit(t, 1, 2, middle.link), parseExit(t, 2, 0, pinnedLink(t, lastLine, lastClient, trust))}
			visitor, _ := clients(engine.NewUUID)
			entry := startServerWith(t, []model.Line{entryLine}, []model.Client{visitor}, exits)

			proxy := xrayLinkClient(nil, nil)(t, entryLine, visitor)
			if err := fetchEventually(proxy); err != nil {
				t.Fatal(err)
			}
			if !logsContain(entry, "[line-1 -> via-1-2]") {
				t.Error("entry server log does not show the line routed to via-1-2")
			}
			accepted := fmt.Sprintf("accepted %s:%s:%d", tt.proto, dialHost, lastLine.Port)
			for deadline := time.Now().Add(2 * time.Second); !strings.Contains(middle.out.String(), accepted); time.Sleep(50 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Errorf("middle hop never carried %q:\n%s", accepted, middle.out.String())
					break
				}
			}
			time.Sleep(500 * time.Millisecond)
			if tr := queryTraffic(t, last)[lastClient.StatsTag()]; tr.Up <= 0 || tr.Down <= 0 {
				t.Errorf("last hop counted %+v for the chain, want traffic both ways", tr)
			}

			// Private destinations stay blocked at the entry even when the line has exits.
			var hits atomic.Int64
			lan := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer lan.Close()
			if status, err := fetch(proxy, lan.URL, 8*time.Second); (err == nil && status == http.StatusOK) || hits.Load() != 0 {
				t.Errorf("loopback reached through a chained line (status %d, err %v)", status, err)
			}
			// A name for a private address must be resolved and blocked at the entry too, not
			// handed to the exit by the line's inbound-tag rule.
			byName := strings.Replace(lan.URL, "127.0.0.1", "localhost", 1)
			if status, err := fetch(proxy, byName, 8*time.Second); (err == nil && status == http.StatusOK) || hits.Load() != 0 {
				t.Errorf("%s reached through a chained line (status %d, err %v)", byName, status, err)
			}
			// Whatever the exit would do with it, the entry itself must refuse it.
			lanPort := lan.Listener.Addr().(*net.TCPAddr).Port
			if want := fmt.Sprintf("localhost:%d [line-1 -> block]", lanPort); !logsContain(entry, want) {
				t.Errorf("entry log has no %q: the name was not resolved and blocked at the entry", want)
			}
		})
	}
}

// TestBrokenExitFailsClosed: when an exit refuses the entry server, the visitor's traffic must
// fail rather than quietly leave through the entry server itself.
func TestBrokenExitFailsClosed(t *testing.T) {
	xrayBin(t)
	requireInternet(t)
	middle := startSS2022Hop(t, ss2022Key())
	// The same hop, but with a key it does not accept.
	wrong := "2022-blake3-aes-128-gcm:" + ss2022KeyFromLink(middle.link) + "@"
	link := strings.Replace(middle.link, wrong, "2022-blake3-aes-128-gcm:"+ss2022Key()+"@", 1)
	entryLine := realityLineAt(t, 1)
	entryLine.ExitID = 1
	visitor, _ := clients(engine.NewUUID)
	exit := parseExit(t, 1, 0, link)
	entry := startServerWith(t, []model.Line{entryLine}, []model.Client{visitor}, []model.Exit{exit})
	proxy := xrayLinkClient(nil, nil)(t, entryLine, visitor)
	time.Sleep(time.Second)
	for range 3 {
		if status, err := fetch(proxy, publicURL, 6*time.Second); err == nil && status == publicStatus {
			t.Fatalf("fetched %s although the only exit has the wrong key", publicURL)
		}
	}
	if logsContain(entry, "-> direct]") {
		t.Error("the entry server sent the chained line's traffic out directly")
	}
}

func ss2022KeyFromLink(link string) string {
	_, rest, _ := strings.Cut(link, "2022-blake3-aes-128-gcm:")
	key, _, _ := strings.Cut(rest, "@")
	return key
}
