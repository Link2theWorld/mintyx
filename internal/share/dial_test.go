package share

import (
	"strconv"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func TestDialAddressMatchesShareLink(t *testing.T) {
	withHost := realityLine()
	withHost.Host = "[2001:db8::1]"
	for _, tc := range []struct {
		name     string
		line     model.Line
		fallback string
		host     string
		port     int
	}{
		{"panel-wide host", realityLine(), "vpn.example.com", "vpn.example.com", 443},
		{"line's own host wins", withHost, "vpn.example.com", "2001:db8::1", 443},
		{"plain xhttp is reached at the cdn edge", xhttpPlainLine(), "vpn.example.com", "cdn.example.com", 443},
		{"tls xhttp keeps its port", xhttpTLSLine(), "vpn.example.com", "vpn.example.com", 8443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := DialAddress(tc.line, tc.fallback)
			if err != nil {
				t.Fatal(err)
			}
			if host != tc.host || port != tc.port {
				t.Errorf("DialAddress = %s:%d, want %s:%d", host, port, tc.host, tc.port)
			}
			link, err := Link(tc.line, testClient(), tc.fallback)
			if err != nil {
				t.Fatal(err)
			}
			u := mustParse(t, link)
			if u.Hostname() != host || u.Port() != strconv.Itoa(port) {
				t.Errorf("share link dials %s, DialAddress says %s:%d", u.Host, host, port)
			}
		})
	}
	if _, _, err := DialAddress(realityLine(), ""); err == nil {
		t.Error("a line without any host must have no dial address")
	}
}
