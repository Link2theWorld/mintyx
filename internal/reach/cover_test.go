package reach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// coverAPI answers DNS measurements as d1/d2 and HTTP as h1 with the bodies given.
type coverAPI struct {
	mu       sync.Mutex
	created  []map[string]any
	bodies   map[string]string
	dnsCount int
}

func (a *coverAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/measurements", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request body %q: %v", raw, err)
		}
		a.mu.Lock()
		a.created = append(a.created, body)
		id := "h1"
		if body["type"] == "dns" {
			a.dnsCount++
			id = fmt.Sprintf("d%d", a.dnsCount)
		}
		a.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"` + id + `"}`))
	})
	mux.HandleFunc("GET /v1/measurements/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(a.bodies[r.PathValue("id")]))
	})
	return mux
}

func dnsBody(answers ...string) string {
	return dnsBodyType("A", answers...)
}

func dnsBodyType(recordType string, answers ...string) string {
	var rs []string
	for _, a := range answers {
		rs = append(rs, `{"probe":{"country":"CN"},"result":{"status":"finished","statusCodeName":"NOERROR","answers":[`+
			`{"name":"cover.example.","type":"CNAME","ttl":60,"class":"IN","value":"cdn.example.net."},`+
			`{"name":"cdn.example.net.","type":"`+recordType+`","ttl":60,"class":"IN","value":"`+a+`"}]}}`)
	}
	return `{"status":"finished","results":[` + strings.Join(rs, ",") + `]}`
}

func httpBody(results ...string) string {
	return `{"status":"finished","results":[` + strings.Join(results, ",") + `]}`
}

const (
	httpTLS13  = `{"probe":{"country":"CN"},"result":{"status":"finished","statusCode":200,"tls":{"protocol":"TLSv1.3","authorized":true}}}`
	httpTLS12  = `{"probe":{"country":"CN"},"result":{"status":"finished","statusCode":200,"tls":{"protocol":"TLSv1.2","authorized":true}}}`
	httpFailed = `{"probe":{"country":"CN"},"result":{"status":"failed","failureSource":"target","rawOutput":"timeout"}}`
	httpBroken = `{"probe":{"country":"CN"},"result":{"status":"failed","failureSource":"internal","rawOutput":"x"}}`
)

func TestCheckCover(t *testing.T) {
	tests := []struct {
		name     string
		dns      string
		aaaa     string
		http     string
		want     CoverVerdict
		wantErr  error
		wantAAAA bool
		wantHTTP bool
	}{
		{name: "abroad, reachable and TLS 1.3", dns: dnsBody("93.184.215.14", "93.184.215.14", "93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "2001:4860:4860::8888"), http: httpBody(httpTLS13, httpTLS13, httpFailed),
			want: CoverVerdict{OK: true}, wantAAAA: true, wantHTTP: true},
		{name: "one mainland answer is enough to turn it down", dns: dnsBody("93.184.215.14", "223.5.5.5", "93.184.215.14"),
			want: CoverVerdict{Problem: "223.5.5.5"}},
		{name: "a mainland IPv6 answer is enough to turn it down", dns: dnsBody("93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "240e::1"), http: httpBody(httpTLS13), want: CoverVerdict{Problem: "240e::1"},
			wantAAAA: true},
		{name: "blocked from the mainland", dns: dnsBody("93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "2001:4860:4860::8888"), http: httpBody(httpFailed, httpFailed, httpTLS13),
			want: CoverVerdict{Problem: "cannot be loaded"}, wantAAAA: true, wantHTTP: true},
		{name: "TLS 1.2 as the mainland sees it", dns: dnsBody("93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "2001:4860:4860::8888"), http: httpBody(httpTLS12, httpTLS12, httpTLS13),
			want: CoverVerdict{Problem: "TLSv1.2"}, wantAAAA: true, wantHTTP: true},
		{name: "an even TLS split is not a majority failure", dns: dnsBody("93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "2001:4860:4860::8888"), http: httpBody(httpTLS13, httpTLS12, httpBroken),
			want: CoverVerdict{OK: true}, wantAAAA: true, wantHTTP: true},
		{name: "only broken probes", dns: dnsBody("93.184.215.14"),
			aaaa: dnsBodyType("AAAA", "2001:4860:4860::8888"), http: httpBody(httpBroken, httpBroken),
			wantErr: ErrNoCoverData, wantAAAA: true, wantHTTP: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &coverAPI{bodies: map[string]string{"d1": tt.dns, "d2": tt.aaaa, "h1": tt.http}}
			c := newTestClient(t, api.handler(t))
			got, err := c.CheckCover(context.Background(), "cover.example")
			if !errors.Is(err, tt.wantErr) || got.OK != tt.want.OK || !strings.Contains(got.Problem, tt.want.Problem) {
				t.Fatalf("CheckCover = %+v, %v; want %+v, %v", got, err, tt.want, tt.wantErr)
			}
			wantMeasurements := 1
			if tt.wantAAAA {
				wantMeasurements++
			}
			if tt.wantHTTP {
				wantMeasurements++
			}
			if len(api.created) != wantMeasurements {
				t.Fatalf("made %d measurements, want %d", len(api.created), wantMeasurements)
			}
			dns := api.created[0]
			if dns["type"] != "dns" || dns["target"] != "cover.example" {
				t.Fatalf("first measurement = %v, want a dns lookup of the site", dns)
			}
			locs, _ := json.Marshal(dns["locations"])
			if string(locs) != `[{"country":"CN","limit":3}]` {
				t.Fatalf("dns locations = %s, want three mainland probes", locs)
			}
			if opts, _ := json.Marshal(dns["measurementOptions"]); string(opts) != `{"query":{"type":"A"}}` {
				t.Fatalf("dns options = %s", opts)
			}
			if tt.wantAAAA {
				aaaa := api.created[1]
				opts, _ := json.Marshal(aaaa["measurementOptions"])
				if aaaa["type"] != "dns" || aaaa["target"] != "cover.example" || aaaa["locations"] != "d1" ||
					string(opts) != `{"query":{"type":"AAAA"}}` {
					t.Fatalf("second measurement = %v (options %s), want an AAAA lookup on the original dns probes", aaaa, opts)
				}
			}
			if tt.wantHTTP {
				h := api.created[wantMeasurements-1]
				opts, _ := json.Marshal(h["measurementOptions"])
				if h["type"] != "http" || h["target"] != "cover.example" || h["locations"] != "d1" ||
					string(opts) != `{"port":443,"protocol":"HTTPS","request":{"method":"HEAD","path":"/"}}` {
					t.Fatalf("HTTP measurement = %v (options %s), want HTTPS to the site on the dns probes", h, opts)
				}
			}
		})
	}
}

type fakeCoverChecker struct {
	verdicts map[string]CoverVerdict
	err      error
	calls    []string
}

func (f *fakeCoverChecker) CheckCover(_ context.Context, host string) (CoverVerdict, error) {
	f.calls = append(f.calls, host)
	return f.verdicts[host], f.err
}

func TestVetCoverRemembersVerdictsForCoverTTL(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cc := &fakeCoverChecker{verdicts: map[string]CoverVerdict{"bad.example": {Problem: "mainland address"}}}
	var cache CoverCache

	v, known, checked, err := VetCover(context.Background(), cc, &cache, "bad.example", true, now)
	if err != nil || !known || !checked || v.OK {
		t.Fatalf("first VetCover = %+v, %v, %v, %v; want a fresh rejection", v, known, checked, err)
	}
	v, known, checked, _ = VetCover(context.Background(), cc, &cache, "BAD.example", true, now.Add(CoverTTL-time.Minute))
	if !known || checked || v.OK || len(cc.calls) != 1 {
		t.Fatalf("VetCover within CoverTTL = %+v, %v, %v after %d checks; want the remembered verdict", v, known, checked, len(cc.calls))
	}
	if _, known, checked, _ = VetCover(context.Background(), cc, &cache, "bad.example", true, now.Add(CoverTTL)); !known || !checked {
		t.Fatalf("VetCover after CoverTTL did not check again")
	}
}

func TestVetCoverKeepsToItsBudget(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cc := &fakeCoverChecker{verdicts: map[string]CoverVerdict{}}
	var cache CoverCache
	perHour := CoverBudget / CoverCost()
	if perHour < 1 || perHour*CoverCost()+ProbesPerMeasurement()*MaxMeasurements+ScheduledBudget > HourlyLimit {
		t.Fatalf("CoverBudget %d leaves no room for the line checks inside %d tests an hour", CoverBudget, HourlyLimit)
	}
	for i := range perHour {
		if _, _, checked, _ := VetCover(context.Background(), cc, &cache, "s"+string(rune('a'+i)), true, now); !checked {
			t.Fatalf("check %d of %d was not started", i+1, perHour)
		}
	}
	if _, known, checked, _ := VetCover(context.Background(), cc, &cache, "one-more", true, now.Add(59*time.Minute)); known || checked {
		t.Fatal("a check past CoverBudget was started")
	}
	if _, _, checked, _ := VetCover(context.Background(), cc, &cache, "one-more", true, now.Add(time.Hour)); !checked {
		t.Fatal("no check an hour later, when the budget has refilled")
	}
	if _, known, checked, _ := VetCover(context.Background(), cc, &cache, "not-allowed", false, now.Add(2*time.Hour)); known || checked {
		t.Fatal("a check was started though the caller did not allow one")
	}
}

func TestVetCoverBacksOffAfterARateLimit(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cc := &fakeCoverChecker{err: &RateLimitError{Reset: 20 * time.Minute}}
	var cache CoverCache
	if _, known, checked, err := VetCover(context.Background(), cc, &cache, "a.example", true, now); known || !checked || err == nil {
		t.Fatalf("VetCover on a refusal = %v, %v, %v; want no verdict and the error", known, checked, err)
	}
	cc.err = nil
	if _, _, checked, _ := VetCover(context.Background(), cc, &cache, "a.example", true, now.Add(19*time.Minute)); checked {
		t.Fatal("checked again before the allowance refilled")
	}
	if _, _, checked, _ := VetCover(context.Background(), cc, &cache, "a.example", true, now.Add(20*time.Minute)); !checked {
		t.Fatal("no check once the allowance refilled")
	}
}
