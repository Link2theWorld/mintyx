package reach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// coverAPI answers a dns measurement as "d1" and an http one as "h1" with the bodies given.
type coverAPI struct {
	mu      sync.Mutex
	created []map[string]any
	bodies  map[string]string
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
		a.mu.Unlock()
		id := map[any]string{"dns": "d1", "http": "h1"}[body["type"]]
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"` + id + `"}`))
	})
	mux.HandleFunc("GET /v1/measurements/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(a.bodies[r.PathValue("id")]))
	})
	return mux
}

func dnsBody(answers ...string) string {
	var rs []string
	for _, a := range answers {
		rs = append(rs, `{"probe":{"country":"CN"},"result":{"status":"finished","statusCodeName":"NOERROR","answers":[`+
			`{"name":"cover.example.","type":"CNAME","ttl":60,"class":"IN","value":"cdn.example.net."},`+
			`{"name":"cdn.example.net.","type":"A","ttl":60,"class":"IN","value":"`+a+`"}]}}`)
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
		http     string
		want     CoverVerdict
		wantErr  error
		wantHTTP bool
	}{
		{"abroad, reachable and TLS 1.3", dnsBody("93.184.215.14", "93.184.215.14", "93.184.215.14"),
			httpBody(httpTLS13, httpTLS13, httpFailed), CoverVerdict{OK: true}, nil, true},
		{"one mainland answer is enough to turn it down", dnsBody("93.184.215.14", "223.5.5.5", "93.184.215.14"),
			"", CoverVerdict{Problem: "223.5.5.5"}, nil, false},
		{"blocked from the mainland", dnsBody("93.184.215.14"),
			httpBody(httpFailed, httpFailed, httpTLS13), CoverVerdict{Problem: "cannot be loaded"}, nil, true},
		{"TLS 1.2 as the mainland sees it", dnsBody("93.184.215.14"),
			httpBody(httpTLS12, httpTLS12, httpTLS13), CoverVerdict{Problem: "TLSv1.2"}, nil, true},
		{"an even TLS split is not a majority failure", dnsBody("93.184.215.14"),
			httpBody(httpTLS13, httpTLS12, httpBroken), CoverVerdict{OK: true}, nil, true},
		{"only broken probes", dnsBody("93.184.215.14"),
			httpBody(httpBroken, httpBroken), CoverVerdict{}, ErrNoCoverData, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := &coverAPI{bodies: map[string]string{"d1": tt.dns, "h1": tt.http}}
			c := newTestClient(t, api.handler(t))
			got, err := c.CheckCover(context.Background(), "cover.example")
			if !errors.Is(err, tt.wantErr) || got.OK != tt.want.OK || !strings.Contains(got.Problem, tt.want.Problem) {
				t.Fatalf("CheckCover = %+v, %v; want %+v, %v", got, err, tt.want, tt.wantErr)
			}
			if got := len(api.created) == 2; got != tt.wantHTTP {
				t.Fatalf("made %d measurements; want the http one only when DNS did not decide", len(api.created))
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
			if tt.wantHTTP {
				h := api.created[1]
				opts, _ := json.Marshal(h["measurementOptions"])
				if h["type"] != "http" || h["target"] != "cover.example" || h["locations"] != "d1" ||
					string(opts) != `{"port":443,"protocol":"HTTPS","request":{"method":"HEAD","path":"/"}}` {
					t.Fatalf("second measurement = %v (options %s), want HTTPS to the site on the dns probes", h, opts)
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
