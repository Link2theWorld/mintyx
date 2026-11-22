package reach

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeAPI serves the two Globalping endpoints the client uses and records what it was sent.
type fakeAPI struct {
	mu      sync.Mutex
	created []map[string]any
	agents  []string
	// polls holds the bodies successive GETs return; the last one repeats.
	polls []string
	gets  int
}

func (a *fakeAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/measurements", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request body %q: %v", raw, err)
		}
		a.mu.Lock()
		a.created = append(a.created, body)
		a.agents = append(a.agents, r.Header.Get("User-Agent"))
		a.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"m1","probesCount":8}`))
	})
	mux.HandleFunc("GET /v1/measurements/m1", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		i := min(a.gets, len(a.polls)-1)
		a.gets++
		a.mu.Unlock()
		_, _ = w.Write([]byte(a.polls[i]))
	})
	return mux
}

func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL, HTTP: srv.Client(), PollEvery: time.Millisecond, Deadline: 5 * time.Second}
}

// finishedBody mirrors a live answer: a blocked ping is "finished" with rcv 0, not "failed".
const finishedBody = `{"status":"finished","results":[
 {"probe":{"country":"CN"},"result":{"status":"finished","stats":{"rcv":3,"total":3}}},
 {"probe":{"country":"CN"},"result":{"status":"finished","stats":{"rcv":1,"total":3}}},
 {"probe":{"country":"CN"},"result":{"status":"finished","stats":{"rcv":0,"total":3,"min":null}}},
 {"probe":{"country":"CN"},"result":{"status":"failed","failureSource":"target","rawOutput":"x"}},
 {"probe":{"country":"CN"},"result":{"status":"failed","failureSource":"internal","rawOutput":"x"}},
 {"probe":{"country":"JP"},"result":{"status":"offline","rawOutput":"x"}},
 {"probe":{"country":"HK"},"result":{"status":"finished","stats":{"rcv":3,"total":3}}},
 {"probe":{"country":"DE"},"result":{"status":"failed","rawOutput":"x"}}]}`

func TestPingClassifiesProbes(t *testing.T) {
	api := &fakeAPI{polls: []string{`{"status":"in-progress","results":[]}`, finishedBody}}
	c := newTestClient(t, api.handler(t))
	got, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	want := PingResult{ID: "m1", Probes: []ProbeResult{
		{China: true, Outcome: Reached},
		{China: true, Outcome: Reached},
		{China: true, Outcome: Unreached},
		{China: true, Outcome: Unreached},
		{China: true, Outcome: NoData},
		{China: false, Outcome: NoData},
		{China: false, Outcome: Reached},
		{China: false, Outcome: NoData},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("result = %+v\nwant     %+v", got, want)
	}
	if api.gets != 2 {
		t.Errorf("polled %d times, want 2: it must wait out in-progress and stop at finished", api.gets)
	}
}

func TestPingRequestBodies(t *testing.T) {
	api := &fakeAPI{polls: []string{finishedBody}}
	c := newTestClient(t, api.handler(t))
	for _, req := range []PingRequest{
		{Host: "[2001:db8::1]"},
		{Host: "vpn.example.com", Port: 8443, Reuse: "anchor9"},
	} {
		if _, err := c.Ping(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	want := []map[string]any{
		{
			"type": "ping", "target": "2001:db8::1",
			"locations": []any{
				map[string]any{"country": "CN", "limit": 5.0},
				map[string]any{"country": "JP", "limit": 1.0},
				map[string]any{"country": "US", "limit": 1.0},
				map[string]any{"country": "DE", "limit": 1.0},
			},
			"measurementOptions": map[string]any{"packets": 3.0},
		},
		{
			"type": "ping", "target": "vpn.example.com", "locations": "anchor9",
			"measurementOptions": map[string]any{"packets": 3.0, "protocol": "TCP", "port": 8443.0},
		},
	}
	if !reflect.DeepEqual(api.created, want) {
		t.Errorf("sent %v\nwant %v", api.created, want)
	}
	if api.agents[0] != userAgent {
		t.Errorf("User-Agent = %q, want %q", api.agents[0], userAgent)
	}
}

func TestPingRateLimited(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Reset", "1234")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_exceeded","message":"too many"}}`))
	}))
	_, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"})
	var rl *RateLimitError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want *RateLimitError", err)
	}
	if rl.Reset != 1234*time.Second {
		t.Errorf("Reset = %s, want 20m34s", rl.Reset)
	}
}

func TestPingAPIError(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"type":"no_probes_found","message":"No matching IPv4 probes available."}}`))
	}))
	_, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if want := (APIError{Status: 422, Type: "no_probes_found", Message: "No matching IPv4 probes available."}); *ae != want {
		t.Errorf("error = %+v, want %+v", *ae, want)
	}
}

func TestPingDeadlineKeepsPartialResults(t *testing.T) {
	api := &fakeAPI{polls: []string{`{"status":"in-progress","results":[
 {"probe":{"country":"CN"},"result":{"status":"finished","stats":{"rcv":0}}},
 {"probe":{"country":"CN"},"result":{"status":"in-progress","rawOutput":""}}]}`}}
	c := newTestClient(t, api.handler(t))
	c.Deadline = 150 * time.Millisecond
	got, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	want := []ProbeResult{{China: true, Outcome: Unreached}, {China: true, Outcome: NoData}}
	if !reflect.DeepEqual(got.Probes, want) {
		t.Errorf("probes = %+v, want %+v", got.Probes, want)
	}
}

func TestPingSurvivesPollThrottling(t *testing.T) {
	var gets int
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/measurements", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"m1"}`))
	})
	mux.HandleFunc("GET /v1/measurements/m1", func(w http.ResponseWriter, r *http.Request) {
		gets++
		if gets == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(finishedBody))
	})
	c := newTestClient(t, mux)
	got, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"})
	if err != nil {
		t.Fatalf("a throttled status poll must be retried, got %v", err)
	}
	if len(got.Probes) != 8 {
		t.Errorf("got %d probes, want 8", len(got.Probes))
	}
}

func TestPingRetriesADroppedConnectionOnce(t *testing.T) {
	api := &fakeAPI{polls: []string{finishedBody}}
	inner := api.handler(t)
	var mu sync.Mutex
	drops := 1
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		drop := drops > 0
		drops--
		mu.Unlock()
		if drop {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		inner.ServeHTTP(w, r)
	}))
	if _, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"}); err != nil {
		t.Fatalf("one dropped connection failed the measurement: %v", err)
	}
	if len(api.created) != 1 {
		t.Errorf("created %d measurements, want 1", len(api.created))
	}

	mu.Lock()
	drops = 2
	mu.Unlock()
	if _, err := c.Ping(context.Background(), PingRequest{Host: "203.0.113.9"}); err == nil {
		t.Error("two dropped connections in a row must surface as an error, not retry forever")
	}
}
