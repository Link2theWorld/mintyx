package reach

import (
	"net/netip"
	"regexp"
	"testing"
)

func TestInMainland(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"114.114.114.114", true}, // a public resolver in Nanjing
		{"223.5.5.5", true},
		{"1.0.1.1", true}, // inside 1.0.1.0/24, the first CN block in the file
		{"240e::1", true},
		{"::ffff:223.5.5.5", true}, // IPv4-mapped is judged as IPv4
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.9", false},
		{"2001:4860::8888", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"::", false},
	}
	for _, tt := range tests {
		if got := InMainland(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("InMainland(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if InMainland(netip.Addr{}) {
		t.Error("InMainland(zero Addr) = true")
	}
}

func TestChnroutesNamesItsSourceAndDate(t *testing.T) {
	if !regexp.MustCompile(`(?m)^# Source: APNIC .*delegated-apnic-latest\r?$`).MatchString(chnroutes) ||
		!regexp.MustCompile(`(?m)^# APNIC file date: \d{8}\.`).MatchString(chnroutes) {
		t.Fatal("chnroutes.txt must say where it came from and how old it is")
	}
	var v4, v6 int
	for _, r := range mainlandRanges() {
		if r.first.Is4() {
			v4++
		} else {
			v6++
		}
		if r.last.Less(r.first) {
			t.Fatalf("range %v-%v ends before it starts", r.first, r.last)
		}
	}
	if v4 < 1000 || v6 < 100 {
		t.Fatalf("chnroutes.txt has %d IPv4 and %d IPv6 ranges, want thousands of the one and hundreds of the other", v4, v6)
	}
}

func TestLastAddr(t *testing.T) {
	for p, want := range map[string]string{
		"1.0.8.0/21":   "1.0.15.255",
		"10.0.0.0/8":   "10.255.255.255",
		"1.2.3.4/32":   "1.2.3.4",
		"240e::/18":    "240e:3fff:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001:db8::/0": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		if got := lastAddr(netip.MustParsePrefix(p).Masked()); got.String() != want {
			t.Errorf("lastAddr(%s) = %s, want %s", p, got, want)
		}
	}
}
