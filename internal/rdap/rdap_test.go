package rdap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// The answers below keep the structure each registry really uses, with documentation data.
const (
	// ARIN: no country member; the country is the last line of the registrant's address label.
	arinAnswer = `{"handle":"NET-192-0-2-0-1","name":"EXAMPLE-NET","startAddress":"192.0.2.0","endAddress":"192.0.2.255",
	 "cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}],
	 "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Hosting LLC"],
	   ["adr",{"label":"1 Main St\nSpringfield\nCA\n94000\nUnited States"},"text",["","","","","","",""]],["kind",{},"text","org"]]],
	   "entities":[{"roles":["administrative","technical"],"vcardArray":["vcard",[["fn",{},"text","NOC"],["email",{},"text","noc@example.com"]]]},
	               {"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@example.com"]]]}]}]}`
	// RIPE: a country member, and the abuse mailbox also flagged on the technical contact.
	ripeAnswer = `{"handle":"198.51.100.0 - 198.51.100.255","name":"EXAMPLE-RIPE","country":"nl","startAddress":"198.51.100.0","endAddress":"198.51.100.255",
	 "entities":[{"roles":["technical"],"vcardArray":["vcard",[["fn",{},"text","Ops"],["email",{"type":"abuse"},"text","abuse@example.nl"]]]},
	             {"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","EXAMPLE-MNT"],["kind",{},"text","individual"]]]},
	             {"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Example B.V."],["kind",{},"text","org"]]]}]}`
	// RIPE again, for a network whose only registrant is its maintainer: the network's own name is used.
	ripeMntAnswer = `{"name":"EXAMPLE-DMZ","country":"AD","startAddress":"198.51.100.0","endAddress":"198.51.100.255",
	 "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","MNT-EXAMPLE"],["kind",{},"text","individual"]]]},
	             {"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@example.ad"]]]}]}`
	// LACNIC: the name repeats the range, the country sits in the structured address, one contact holds every role.
	lacnicAnswer = `{"handle":"203.0.113.0/24","name":"203.0.113.0 - 203.0.113.255","startAddress":"203.0.113.0","endAddress":"203.0.113.255",
	 "cidr0_cidrs":[{"v4prefix":"203.0.113.0","length":24}],
	 "entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Ejemplo S.A."],["kind",{},"text","org"],["adr",{"label":"Calle 1\nMontevideo\nUY"},"text",["","Calle 1","","Montevideo","","11400","UY"]]]]},
	             {"roles":["administrative","technical","abuse"],"vcardArray":["vcard",[["fn",{},"text","Admin"],["email",{},"text","ipadmin@example.uy"]]]}]}`
	// Hostile: an abuse address that is not one plain mailbox, control characters, and an oversized name.
	hostileAnswer = `{"name":"EVIL\u0000\nNET","country":"<script>","startAddress":"2001:db8::","endAddress":"2001:db8::ffff",
	 "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","a@example.com?subject=x, b@example.com"]]]}]}`
)

type registry struct {
	srv     *httptest.Server
	lookups atomic.Int32
	answers map[string]string
	status  map[string]int
}

func newRegistry(t *testing.T) (*registry, *Client) {
	t.Helper()
	r := &registry{answers: map[string]string{}, status: map[string]int{}}
	mux := http.NewServeMux()
	r.srv = httptest.NewTLSServer(mux)
	t.Cleanup(r.srv.Close)
	bootstrap := func(prefixes ...string) string {
		return fmt.Sprintf(`{"services":[[["%s"],["http://plain.invalid/","%s/rdap/"]],[["192.0.2.128/25"],["%s/other"]]]}`,
			strings.Join(prefixes, `","`), r.srv.URL, r.srv.URL)
	}
	mux.HandleFunc("/v4.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, bootstrap("192.0.0.0/8", "198.0.0.0/8", "203.0.0.0/8"))
	})
	mux.HandleFunc("/v6.json", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, bootstrap("2001:db8::/32")) })
	mux.HandleFunc("/rdap/ip/", func(w http.ResponseWriter, req *http.Request) {
		r.lookups.Add(1)
		ip := strings.TrimPrefix(req.URL.Path, "/rdap/ip/")
		if code := r.status[ip]; code != 0 {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(code)
			return
		}
		body, ok := r.answers[ip]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, body)
	})
	mux.HandleFunc("/other/ip/", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/rdap/ip/192.0.2.1", http.StatusFound)
	})
	return r, NewWith(r.srv.Client(), r.srv.URL+"/v4.json", r.srv.URL+"/v6.json")
}

func TestLookupReadsEachRegistrysShape(t *testing.T) {
	r, c := newRegistry(t)
	r.answers["192.0.2.1"] = arinAnswer
	r.answers["198.51.100.9"] = ripeAnswer
	r.answers["203.0.113.5"] = lacnicAnswer
	r.answers["198.51.100.77"] = ripeMntAnswer
	r.answers["2001:db8::1"] = hostileAnswer

	host := strings.TrimPrefix(r.srv.URL, "https://")
	cases := map[string]model.Whois{
		"192.0.2.1":     {Country: "US", Network: "Example Hosting LLC", NetRange: "192.0.2.0/24", AbuseEmail: "abuse@example.com", Registry: host},
		"198.51.100.9":  {Country: "NL", Network: "Example B.V.", NetRange: "198.51.100.0 - 198.51.100.255", AbuseEmail: "abuse@example.nl", Registry: host},
		"198.51.100.77": {Country: "AD", Network: "EXAMPLE-DMZ", NetRange: "198.51.100.0 - 198.51.100.255", AbuseEmail: "abuse@example.ad", Registry: host},
		"203.0.113.5":   {Country: "UY", Network: "Ejemplo S.A.", NetRange: "203.0.113.0/24", AbuseEmail: "ipadmin@example.uy", Registry: host},
		"2001:db8::1":   {Country: "<script>", Network: "EVIL NET", NetRange: "2001:db8:: - 2001:db8::ffff", Registry: host},
		// The most specific bootstrap prefix wins, and its registry redirects to the one holding the record.
		"192.0.2.200": {Country: "US", Network: "Example Hosting LLC", NetRange: "192.0.2.0/24", AbuseEmail: "abuse@example.com", Registry: host},
	}
	for ip, want := range cases {
		got, err := c.Lookup(context.Background(), netip.MustParseAddr(ip))
		if err != nil || got != want {
			t.Errorf("%s: got %+v, %v\nwant %+v", ip, got, err, want)
		}
	}
}

func TestLookupErrors(t *testing.T) {
	r, c := newRegistry(t)
	r.status["192.0.2.9"] = http.StatusTooManyRequests
	r.status["192.0.2.10"] = http.StatusInternalServerError
	ctx := context.Background()

	if _, err := c.Lookup(ctx, netip.MustParseAddr("192.0.2.1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown address: %v, want ErrNotFound", err)
	}
	var limited *RateLimitError
	if _, err := c.Lookup(ctx, netip.MustParseAddr("192.0.2.9")); !errors.As(err, &limited) || limited.RetryAfter != 2*time.Minute {
		t.Errorf("429: %v (%+v)", err, limited)
	}
	if _, err := c.Lookup(ctx, netip.MustParseAddr("192.0.2.10")); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("500: %v, want a plain error", err)
	}
	if _, err := c.Lookup(ctx, netip.MustParseAddr("100.0.0.1")); !errors.Is(err, ErrNoRegistry) {
		t.Errorf("address outside the bootstrap data: %v, want ErrNoRegistry", err)
	}
}

func TestBootstrapIsFetchedOnceADayAndSurvivesAFailedRefresh(t *testing.T) {
	var fetches atomic.Int32
	fail := atomic.Bool{}
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	mux.HandleFunc("/boot.json", func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprintf(w, `{"services":[[["192.0.0.0/8"],["%s/"]]]}`, srv.URL)
	})
	mux.HandleFunc("/ip/", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, `{"name":"N","country":"JP"}`) })

	c := NewWith(srv.Client(), srv.URL+"/boot.json", srv.URL+"/boot.json")
	clock := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return clock }
	look := func() {
		t.Helper()
		if w, err := c.Lookup(context.Background(), netip.MustParseAddr("192.0.2.1")); err != nil || w.Country != "JP" {
			t.Fatalf("lookup: %+v, %v", w, err)
		}
	}
	look()
	look()
	if n := fetches.Load(); n != 2 {
		t.Fatalf("bootstrap fetched %d times for two lookups, want 2 (one per address family)", n)
	}
	clock = clock.Add(25 * time.Hour)
	fail.Store(true)
	look() // the stale data still answers
	if n := fetches.Load(); n != 3 {
		t.Errorf("after a day: %d fetches, want one more attempt", n)
	}
}

func TestFirstBootstrapFailureIsAnError(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	c := NewWith(srv.Client(), srv.URL+"/v4.json", srv.URL+"/v6.json")
	if _, err := c.Lookup(context.Background(), netip.MustParseAddr("192.0.2.1")); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("err = %v, want a bootstrap error", err)
	}
}
