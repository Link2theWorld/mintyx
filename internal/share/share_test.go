package share

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Link2theWorld/mintyx/internal/model"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func realityLine() model.Line {
	return model.Line{
		ID: 1, Name: "Tokyo", Protocol: model.VLESSReality, Port: 443, Enabled: true,
		Reality: &model.RealityParams{
			PrivateKey: "PRIV", PublicKey: "Zm9vYmFyYmF6cHVibGlja2V5", ShortID: "6ba85179e30d4fc2",
			ServerName: "www.example.com", Target: "www.example.com:443",
		},
	}
}

func xhttpTLSLine() model.Line {
	return model.Line{
		ID: 2, Name: "XH", Protocol: model.VLESSXHTTP, Port: 8443, Enabled: true,
		XHTTP: &model.XHTTPParams{Path: "/xh", Domain: "xh.example.com", Security: model.XHTTPTLS},
	}
}

func xhttpPlainLine() model.Line {
	return model.Line{
		ID: 3, Name: "CDN", Protocol: model.VLESSXHTTP, Port: 2080, Enabled: true,
		XHTTP: &model.XHTTPParams{Path: "/cdn", Domain: "cdn.example.com", Security: model.XHTTPPlain},
	}
}

func hy2Line(obfs string) model.Line {
	return model.Line{
		ID: 4, Name: "Hy", Protocol: model.Hysteria2, Port: 8443, Enabled: true,
		Hysteria2: &model.Hysteria2Params{Domain: "hy.example.com", ObfsPassword: obfs},
	}
}

func testClient() model.Client {
	return model.Client{ID: 7, Name: "phone", Secret: testUUID, SubToken: "tok"}
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestLinkExact(t *testing.T) {
	hyClient := testClient()
	hyClient.Secret = "p@ss word/#"
	cases := []struct {
		name   string
		line   model.Line
		client model.Client
		want   string
	}{
		{
			name: "reality vision", line: realityLine(), client: testClient(),
			want: "vless://" + testUUID + "@203.0.113.7:443?encryption=none&flow=xtls-rprx-vision" +
				"&security=reality&sni=www.example.com&fp=chrome&pbk=Zm9vYmFyYmF6cHVibGlja2V5" +
				"&sid=6ba85179e30d4fc2&type=tcp#Tokyo",
		},
		{
			name: "xhttp tls dials server on line port", line: xhttpTLSLine(), client: testClient(),
			want: "vless://" + testUUID + "@203.0.113.7:8443?encryption=none&security=tls" +
				"&sni=xh.example.com&fp=chrome&type=xhttp&host=xh.example.com&path=%2Fxh#XH",
		},
		{
			name: "xhttp plain dials cdn domain on 443 with tls", line: xhttpPlainLine(), client: testClient(),
			want: "vless://" + testUUID + "@cdn.example.com:443?encryption=none&security=tls" +
				"&sni=cdn.example.com&fp=chrome&type=xhttp&host=cdn.example.com&path=%2Fcdn#CDN",
		},
		{
			name: "hysteria2 no obfs", line: hy2Line(""), client: hyClient,
			want: "hysteria2://p%40ss%20word%2F%23@203.0.113.7:8443/?sni=hy.example.com#Hy",
		},
		{
			name: "hysteria2 salamander", line: hy2Line("ob&fs"), client: hyClient,
			want: "hysteria2://p%40ss%20word%2F%23@203.0.113.7:8443/?obfs=salamander" +
				"&obfs-password=ob%26fs&sni=hy.example.com#Hy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Link(tc.line, tc.client, "203.0.113.7")
			if err != nil {
				t.Fatalf("Link: %v", err)
			}
			if got != tc.want {
				t.Fatalf("Link =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

func TestLinkRoundTripsAwkwardStrings(t *testing.T) {
	name := "東京 #1 & more?=%"
	path := "/a b#c&d=é?%"
	l := xhttpTLSLine()
	l.Name = name
	l.XHTTP.Path = path
	got, err := Link(l, testClient(), "203.0.113.7")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	u := mustParse(t, got)
	q := u.Query()
	if u.Fragment != name {
		t.Errorf("fragment = %q, want %q", u.Fragment, name)
	}
	if q.Get("path") != path {
		t.Errorf("path = %q, want %q", q.Get("path"), path)
	}
	if q.Get("type") != "xhttp" || q.Get("security") != "tls" {
		t.Errorf("other params corrupted: %v", q)
	}
	// encodeURIComponent semantics: a literal space must not become '+', which JS clients keep as '+'.
	if strings.Contains(got, "+") {
		t.Errorf("link contains '+': %s", got)
	}

	hy := hy2Line("x y")
	hy.Name = name
	c := testClient()
	c.Secret = "pa:ss@w/rd é"
	got, err = Link(hy, c, "203.0.113.7")
	if err != nil {
		t.Fatalf("Link hy2: %v", err)
	}
	u = mustParse(t, got)
	if u.User.Username() != c.Secret {
		t.Errorf("auth = %q, want %q", u.User.Username(), c.Secret)
	}
	if u.Query().Get("obfs-password") != "x y" || u.Fragment != name {
		t.Errorf("hy2 round trip: obfs-password=%q fragment=%q", u.Query().Get("obfs-password"), u.Fragment)
	}
}

func TestLinkDialAddress(t *testing.T) {
	cases := []struct {
		name, lineHost, defaultHost, line string
		wantHost, wantPort                string
	}{
		{"ipv6 default host bracketed", "", "2001:db8::1", "reality", "2001:db8::1", "443"},
		{"already bracketed ipv6", "[2001:db8::2]", "203.0.113.7", "reality", "2001:db8::2", "443"},
		{"line host overrides default", "edge.example.net", "203.0.113.7", "reality", "edge.example.net", "443"},
		{"line host overrides cdn domain on plain xhttp", "104.16.0.1", "203.0.113.7", "plain", "104.16.0.1", "443"},
		{"ipv6 on hysteria2", "", "2001:db8::3", "hy2", "2001:db8::3", "8443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var l model.Line
			switch tc.line {
			case "reality":
				l = realityLine()
			case "plain":
				l = xhttpPlainLine()
			case "hy2":
				l = hy2Line("")
			}
			l.Host = tc.lineHost
			got, err := Link(l, testClient(), tc.defaultHost)
			if err != nil {
				t.Fatalf("Link: %v", err)
			}
			u := mustParse(t, got)
			if u.Hostname() != tc.wantHost || u.Port() != tc.wantPort {
				t.Fatalf("dial = %s:%s, want %s:%s (%s)", u.Hostname(), u.Port(), tc.wantHost, tc.wantPort, got)
			}
			if strings.Contains(tc.wantHost, ":") && !strings.Contains(u.Host, "["+tc.wantHost+"]") {
				t.Fatalf("ipv6 not bracketed: %s", got)
			}
		})
	}
}

func TestLinkRejectsUnbuildableLines(t *testing.T) {
	noHost := realityLine()
	noKey := realityLine()
	noKey.Reality.PublicKey = ""
	mismatch := realityLine()
	mismatch.Reality = nil
	badPort := hy2Line("")
	badPort.Port = 0
	noDomain := xhttpTLSLine()
	noDomain.XHTTP.Domain = ""
	cases := []struct {
		name        string
		line        model.Line
		client      model.Client
		defaultHost string
		want        string
	}{
		{"no host anywhere", noHost, testClient(), "", "no dial host"},
		{"missing public key", noKey, testClient(), "h", "public key"},
		{"params missing for protocol", mismatch, testClient(), "h", "missing reality parameters"},
		{"port out of range", badPort, testClient(), "h", "port 0"},
		{"xhttp needs a domain", noDomain, testClient(), "h", "domain"},
		{"empty secret", realityLine(), model.Client{ID: 1}, "h", "secret"},
		{"host with slash", realityLine(), testClient(), "evil.com/x", "invalid host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Link(tc.line, tc.client, tc.defaultHost)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Link = %q, %v; want error containing %q", got, err, tc.want)
			}
		})
	}
}

func allLines() []model.Line {
	disabled := hy2Line("")
	disabled.ID, disabled.Name, disabled.Port, disabled.Enabled = 9, "Off", 9999, false
	return []model.Line{realityLine(), xhttpPlainLine(), disabled, hy2Line("obfspw")}
}

func TestRenderLinks(t *testing.T) {
	body, ctype, err := Render(FormatLinks, allLines(), testClient(), "203.0.113.7")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ctype != "text/plain; charset=utf-8" {
		t.Errorf("content type = %q", ctype)
	}
	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("body is not std base64: %v", err)
	}
	var names []string
	for _, ln := range strings.Split(string(raw), "\n") {
		u := mustParse(t, ln)
		names = append(names, u.Scheme+":"+u.Fragment)
	}
	want := []string{"vless:Tokyo", "vless:CDN", "hysteria2:Hy"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("decoded entries = %v, want %v", names, want)
	}
}

func TestRenderEmpty(t *testing.T) {
	off := testClient()
	off.Disabled = model.DisabledQuota
	for _, f := range []Format{FormatLinks, FormatMihomo} {
		t.Run(string(f)+"/disabled client", func(t *testing.T) {
			body, _, err := Render(f, allLines(), off, "203.0.113.7")
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertNoProxies(t, f, body)
		})
		t.Run(string(f)+"/no lines", func(t *testing.T) {
			body, _, err := Render(f, nil, testClient(), "203.0.113.7")
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertNoProxies(t, f, body)
		})
	}
}

func assertNoProxies(t *testing.T, f Format, body []byte) {
	t.Helper()
	switch f {
	case FormatLinks:
		if len(body) != 0 {
			t.Fatalf("links body = %q, want empty", body)
		}
	case FormatMihomo:
		var doc mihomoDocParsed
		if err := yaml.Unmarshal(body, &doc); err != nil {
			t.Fatalf("yaml: %v", err)
		}
		if len(doc.Proxies) != 0 || len(doc.Groups) != 1 || !reflect.DeepEqual(doc.Groups[0].Proxies, []string{"DIRECT"}) {
			t.Fatalf("empty mihomo doc = %+v", doc)
		}
	}
}

type mihomoDocParsed struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func TestRenderMihomo(t *testing.T) {
	lines := allLines()
	dup := xhttpTLSLine()
	dup.Name = "Tokyo"
	lines = append(lines, dup)
	body, ctype, err := Render(FormatMihomo, lines, testClient(), "203.0.113.7")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if ctype != "text/yaml; charset=utf-8" {
		t.Errorf("content type = %q", ctype)
	}
	var doc mihomoDocParsed
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("yaml: %v\n%s", err, body)
	}
	if len(doc.Proxies) != 4 {
		t.Fatalf("got %d proxies, want 4:\n%s", len(doc.Proxies), body)
	}
	reality, plain, hy, tlsXH := doc.Proxies[0], doc.Proxies[1], doc.Proxies[2], doc.Proxies[3]
	check := func(p map[string]any, key string, want any) {
		t.Helper()
		if !reflect.DeepEqual(p[key], want) {
			t.Errorf("%v: %s = %#v, want %#v", p["name"], key, p[key], want)
		}
	}
	check(reality, "type", "vless")
	check(reality, "server", "203.0.113.7")
	check(reality, "port", 443)
	check(reality, "uuid", testUUID)
	check(reality, "flow", "xtls-rprx-vision")
	check(reality, "tls", true)
	check(reality, "servername", "www.example.com")
	check(reality, "client-fingerprint", "chrome")
	check(reality, "reality-opts", map[string]any{"public-key": "Zm9vYmFyYmF6cHVibGlja2V5", "short-id": "6ba85179e30d4fc2", "support-x25519mlkem768": true})

	check(plain, "server", "cdn.example.com")
	check(plain, "port", 443)
	check(plain, "network", "xhttp")
	check(plain, "servername", "cdn.example.com")
	check(plain, "xhttp-opts", map[string]any{"path": "/cdn", "host": "cdn.example.com"})
	check(plain, "flow", nil)

	check(hy, "type", "hysteria2")
	check(hy, "port", 8443)
	check(hy, "password", testUUID)
	check(hy, "obfs", "salamander")
	check(hy, "obfs-password", "obfspw")
	check(hy, "sni", "hy.example.com")

	check(tlsXH, "name", "Tokyo (2)")
	check(tlsXH, "port", 8443)

	if len(doc.Groups) != 1 || doc.Groups[0].Type != "select" {
		t.Fatalf("groups = %+v", doc.Groups)
	}
	wantMembers := []string{"Tokyo", "CDN", "Hy", "Tokyo (2)", "DIRECT"}
	if !reflect.DeepEqual(doc.Groups[0].Proxies, wantMembers) {
		t.Errorf("group members = %v, want %v", doc.Groups[0].Proxies, wantMembers)
	}
	if !reflect.DeepEqual(doc.Rules, []string{"MATCH," + doc.Groups[0].Name}) {
		t.Errorf("rules = %v", doc.Rules)
	}
	if got := Omitted(lines, "203.0.113.7"); len(got) != 0 {
		t.Errorf("mihomo omitted = %+v, want none", got)
	}
}

func TestRenderSkipsBrokenLineAndReportsIt(t *testing.T) {
	broken := realityLine()
	broken.ID, broken.Name = 5, "Broken"
	broken.Reality = &model.RealityParams{ServerName: "x"}
	lines := []model.Line{broken, hy2Line("")}
	body, _, err := Render(FormatLinks, lines, testClient(), "203.0.113.7")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(string(body))
	if u := mustParse(t, string(raw)); u.Fragment != "Hy" {
		t.Errorf("body = %q, want only the Hy line", raw)
	}
	om := Omitted(lines, "203.0.113.7")
	if len(om) != 1 || om[0].LineID != 5 || !strings.Contains(om[0].Reason, "public key") {
		t.Errorf("omitted = %+v", om)
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	for _, f := range []Format{"v2rayng", "clash"} {
		t.Run(string(f), func(t *testing.T) {
			body, ctype, err := Render(f, allLines(), testClient(), "h")
			if want := `unknown format "` + string(f) + `"`; err == nil || err.Error() != want || body != nil || ctype != "" {
				t.Fatalf("Render = %q, %q, %v; want nil body and error %q", body, ctype, err, want)
			}
		})
	}
}

func TestRenderMihomoRenamesLinesClashingWithReservedNames(t *testing.T) {
	proxy, direct, reject := hy2Line(""), hy2Line(""), hy2Line("")
	proxy.Name, direct.Name, reject.Name = "Proxy", "DIRECT", "REJECT"
	body, _, err := Render(FormatMihomo, []model.Line{proxy, direct, reject}, testClient(), "203.0.113.7")
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var doc mihomoDocParsed
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("yaml: %v\n%s", err, body)
	}
	var names []string
	for _, p := range doc.Proxies {
		names = append(names, p["name"].(string))
	}
	if want := []string{"Proxy (2)", "DIRECT (2)", "REJECT (2)"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("proxy names = %v, want %v", names, want)
	}
	if len(doc.Groups) != 1 || doc.Groups[0].Name != "Proxy" ||
		!reflect.DeepEqual(doc.Groups[0].Proxies, []string{"Proxy (2)", "DIRECT (2)", "REJECT (2)", "DIRECT"}) {
		t.Fatalf("groups = %+v", doc.Groups)
	}
}

func TestUserInfoHeader(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	cases := []struct {
		name string
		c    model.Client
		want string
	}{
		{"unlimited never expires", model.Client{UsedUp: 10, UsedDown: 20}, "upload=10; download=20"},
		{
			"quota and expiry", model.Client{UsedUp: 1, UsedDown: 2, QuotaBytes: 107374182400, ExpiresAt: &exp},
			"upload=1; download=2; total=107374182400; expire=1798859045",
		},
		{"expiry only", model.Client{ExpiresAt: &exp}, "upload=0; download=0; expire=1798859045"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UserInfoHeader(tc.c); got != tc.want {
				t.Fatalf("UserInfoHeader = %q, want %q", got, tc.want)
			}
		})
	}
}
