package share

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/Link2theWorld/mintyx/internal/exitlink"
	"github.com/Link2theWorld/mintyx/internal/model"
)

// x25519Pub is RFC 7748 §6.1 Alice's public key in base64url: exitlink checks the key length.
const x25519Pub = "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"

func remoteFromLink(t *testing.T, id int64, link string) model.RemoteLine {
	t.Helper()
	p, name, err := exitlink.Parse(link)
	if err != nil {
		t.Fatalf("exitlink.Parse(%q): %v", link, err)
	}
	return model.RemoteLine{ID: id, ClientID: 7, Name: name, Params: p}
}

// Another Mintyx panel's links come back out of a subscription exactly as that panel wrote them.
func TestRemoteLinkRoundTripsMintyxLinks(t *testing.T) {
	reality := realityLine()
	reality.Reality.PublicKey = x25519Pub
	hyClient := testClient()
	hyClient.Secret = "p@ss word/#"
	cases := []struct {
		name   string
		line   model.Line
		client model.Client
	}{
		{"reality", reality, testClient()},
		{"xhttp tls", xhttpTLSLine(), testClient()},
		{"xhttp behind cdn", xhttpPlainLine(), testClient()},
		{"hysteria2", hy2Line(""), hyClient},
		{"hysteria2 salamander", hy2Line("ob&fs"), hyClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link, err := Link(tc.line, tc.client, "198.51.100.20")
			if err != nil {
				t.Fatal(err)
			}
			r := remoteFromLink(t, 1, link)
			if err := CheckRemote(r.Params); err != nil {
				t.Fatalf("CheckRemote: %v", err)
			}
			got, err := RemoteLink(r)
			if err != nil {
				t.Fatalf("RemoteLink: %v", err)
			}
			if got != link {
				t.Fatalf("RemoteLink =\n%s\nwant\n%s", got, link)
			}
		})
	}
}

func TestRemoteLinkKeepsLinkSettings(t *testing.T) {
	r := remoteFromLink(t, 1, "vless://"+testUUID+"@[2001:db8::1]:2083?security=tls&sni=a.example.com&fp=randomized"+
		"&type=xhttp&path=%2Fp&mode=packet-up#Far")
	r.Name = "Renamed"
	got, err := RemoteLink(r)
	if err != nil {
		t.Fatal(err)
	}
	want := "vless://" + testUUID + "@[2001:db8::1]:2083?encryption=none&security=tls&sni=a.example.com&fp=random" +
		"&type=xhttp&path=%2Fp&mode=packet-up#Renamed"
	if got != want {
		t.Fatalf("RemoteLink =\n%s\nwant\n%s", got, want)
	}
}

func TestCheckRemoteRefusesWhatASubscriptionCannotCarry(t *testing.T) {
	base := "@203.0.113.9:443?"
	cases := []struct{ link, part string }{
		{"trojan://pw" + base + "sni=t.example.com", "scheme"},
		{"ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@203.0.113.9:8388", "scheme"},
		{"vless://" + testUUID + base + "security=tls&sni=a.example.com&type=raw", "security"},
		{"vless://" + testUUID + base + "security=tls&sni=a.example.com&type=ws", "type"},
		{"vless://" + testUUID + base + "security=reality&sni=a.example.com&pbk=" + x25519Pub + "&type=xhttp", "security"},
		{"vless://" + testUUID + base + "security=reality&sni=a.example.com&pbk=" + x25519Pub + "&flow=xtls-rprx-vision-udp443", "flow"},
		{"vless://" + testUUID + base + "security=tls&sni=a.example.com&type=xhttp&pcs=" + strings.Repeat("ab", 32), "pcs"},
		{"vless://" + testUUID + base + "security=tls&sni=a.example.com&type=xhttp&vcn=b.example.com", "vcn"},
		{"hysteria2://auth" + base + "sni=h.example.com&pinSHA256=" + strings.Repeat("ab", 32), "pinSHA256"},
	}
	for _, tc := range cases {
		t.Run(tc.part+" "+tc.link[:8], func(t *testing.T) {
			p, _, err := exitlink.Parse(tc.link)
			if err != nil {
				t.Fatalf("exitlink.Parse: %v", err)
			}
			var re *RemoteError
			if err := CheckRemote(p); !errors.As(err, &re) || re.Part != tc.part {
				t.Fatalf("CheckRemote = %v, want a RemoteError on %q", err, tc.part)
			}
		})
	}
}

type balanceDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []map[string]any `yaml:"proxy-groups"`
	Rules   []string         `yaml:"rules"`
}

func renderBalance(t *testing.T, lines []model.Line, remotes []model.RemoteLine, c model.Client) balanceDoc {
	t.Helper()
	body, _, err := Render(FormatMihomo, lines, remotes, c, "203.0.113.7")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc balanceDoc
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("yaml: %v\n%s", err, body)
	}
	return doc
}

func TestRenderMergesRemoteLinesIntoALoadBalanceGroup(t *testing.T) {
	seoul := remoteFromLink(t, 1, "vless://"+testUUID+"@198.51.100.8:443?encryption=none&flow=xtls-rprx-vision"+
		"&security=reality&sni=www.example.org&fp=firefox&pbk="+x25519Pub+"&sid=0a1b&type=tcp#Tokyo")
	hk := remoteFromLink(t, 2, "hysteria2://hk-auth@hk.example.net:8443/?sni=hk.example.net#HK")
	broken := model.RemoteLine{ID: 3, Name: "Trojan", Params: model.ExitParams{Protocol: model.ExitTrojan, Host: "x", Port: 1, Secret: "s"}}
	doc := renderBalance(t, []model.Line{realityLine()}, []model.RemoteLine{seoul, hk, broken}, testClient())

	var names []string
	for _, p := range doc.Proxies {
		names = append(names, p["name"].(string))
	}
	// The remote line named like a local one is renamed; the one no format can carry is left out.
	if want := []string{"Tokyo", "Tokyo (2)", "HK"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("proxies = %v, want %v", names, want)
	}
	r := doc.Proxies[1]
	for k, want := range map[string]any{"server": "198.51.100.8", "uuid": testUUID, "flow": "xtls-rprx-vision",
		"servername": "www.example.org", "client-fingerprint": "firefox",
		"reality-opts": map[string]any{"public-key": x25519Pub, "short-id": "0a1b", "support-x25519mlkem768": true}} {
		if !reflect.DeepEqual(r[k], want) {
			t.Errorf("remote reality %s = %#v, want %#v", k, r[k], want)
		}
	}
	if h := doc.Proxies[2]; h["type"] != "hysteria2" || h["password"] != "hk-auth" || h["port"] != 8443 || h["sni"] != "hk.example.net" {
		t.Errorf("remote hysteria2 = %v", h)
	}

	want := []map[string]any{
		{"name": "Proxy", "type": "select", "proxies": []any{"Load Balance", "Tokyo", "Tokyo (2)", "HK", "DIRECT"}},
		{"name": "Load Balance", "type": "load-balance", "proxies": []any{"Tokyo", "Tokyo (2)", "HK"},
			"strategy": "consistent-hashing", "url": "https://www.gstatic.com/generate_204", "interval": 300},
	}
	if !reflect.DeepEqual(doc.Groups, want) {
		t.Fatalf("groups =\n%v\nwant\n%v", doc.Groups, want)
	}
	if !reflect.DeepEqual(doc.Rules, []string{"MATCH,Proxy"}) {
		t.Errorf("rules = %v", doc.Rules)
	}

	body, _, err := Render(FormatLinks, []model.Line{realityLine()}, []model.RemoteLine{seoul, hk, broken}, testClient(), "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(string(body))
	uris := strings.Split(string(raw), "\n")
	if len(uris) != 3 || !strings.HasPrefix(uris[1], "vless://"+testUUID+"@198.51.100.8:443?") ||
		!strings.HasPrefix(uris[2], "hysteria2://hk-auth@hk.example.net:8443/?") {
		t.Fatalf("links = %q", uris)
	}
}

func TestRenderBalancesOnlyWhenItMergesAndHasAChoice(t *testing.T) {
	hk := remoteFromLink(t, 2, "hysteria2://hk-auth@hk.example.net:8443/?sni=hk.example.net#HK")
	off := testClient()
	off.Disabled = model.DisabledManual
	cases := []struct {
		name    string
		lines   []model.Line
		remotes []model.RemoteLine
		c       model.Client
		proxies int
	}{
		{"own lines only", []model.Line{realityLine(), hy2Line("")}, nil, testClient(), 2},
		{"a single remote line", nil, []model.RemoteLine{hk}, testClient(), 1},
		{"disabled client", []model.Line{realityLine()}, []model.RemoteLine{hk}, off, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := renderBalance(t, tc.lines, tc.remotes, tc.c)
			if len(doc.Proxies) != tc.proxies || len(doc.Groups) != 1 || doc.Groups[0]["type"] != "select" {
				t.Fatalf("proxies %d (want %d), groups %v", len(doc.Proxies), tc.proxies, doc.Groups)
			}
		})
	}
}
