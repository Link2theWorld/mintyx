package reach

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// scriptedPinger answers each measurement from a table keyed "host:port" and records the calls.
type scriptedPinger struct {
	mu      sync.Mutex
	answers map[string][]ProbeResult
	errs    map[string]error
	calls   []PingRequest
}

func (p *scriptedPinger) Ping(_ context.Context, req PingRequest) (PingResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, req)
	key := fmt.Sprintf("%s:%d", req.Host, req.Port)
	if err := p.errs[key]; err != nil {
		return PingResult{}, err
	}
	return PingResult{ID: "id-" + key, Probes: p.answers[key]}, nil
}

// probes builds a result: cn of 5 China probes and ctl of 3 control probes reach the target.
func probes(cn, ctl int) []ProbeResult {
	var out []ProbeResult
	for i := range 5 {
		o := Unreached
		if i < cn {
			o = Reached
		}
		out = append(out, ProbeResult{China: true, Outcome: o})
	}
	for i := range 3 {
		o := Unreached
		if i < ctl {
			o = Reached
		}
		out = append(out, ProbeResult{Outcome: o})
	}
	return out
}

func verdicts(r Round) map[int64]Verdict {
	out := map[int64]Verdict{}
	for id, o := range r.Results {
		out[id] = o.Verdict
	}
	return out
}

func TestRunRoundJudgesEachLine(t *testing.T) {
	p := &scriptedPinger{answers: map[string][]ProbeResult{
		"a.example:0":    probes(5, 3),
		"a.example:443":  probes(0, 3),
		"a.example:8443": probes(4, 3),
		"b.example:0":    probes(0, 3),
		"b.example:443":  probes(1, 3),
		"c.example:0":    probes(5, 3),
		"c.example:443":  probes(0, 0),
	}}
	targets := []Target{
		{ID: 1, Host: "A.example", Port: 443},
		{ID: 2, Host: "a.example", Port: 8443},
		{ID: 3, Host: "a.example", Port: 8443, IPOnly: true},
		{ID: 4, Host: "b.example", Port: 443},
		{ID: 5, Host: "c.example", Port: 443},
	}
	r := RunRound(context.Background(), p, targets, 0)
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	want := map[int64]Verdict{1: PortBlocked, 2: OK, 3: OK, 4: IPBlocked, 5: Down}
	if got := verdicts(r); !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts = %v, want %v", got, want)
	}
	if got, want := r.Results[1], (Observation{PortBlocked, Tally{0, 5}, Tally{3, 3}}); got != want {
		t.Errorf("tcp line shows %+v, want the port's own counts %+v", got, want)
	}
	if got, want := r.Results[3], (Observation{OK, Tally{5, 5}, Tally{3, 3}}); got != want {
		t.Errorf("udp line shows %+v, want the ping counts %+v", got, want)
	}

	// One ping per host plus one TCP ping per distinct port: the UDP line adds none.
	if len(p.calls) != 7 {
		t.Fatalf("made %d measurements, want 7: %+v", len(p.calls), p.calls)
	}
	if first := p.calls[0]; first != (PingRequest{Host: "a.example"}) {
		t.Errorf("first measurement = %+v, want the anchor ping without Reuse", first)
	}
	for _, c := range p.calls[1:] {
		if c.Reuse != "id-a.example:0" {
			t.Errorf("%+v does not reuse the anchor's probes", c)
		}
	}
}

func TestRunRoundRateLimitStopsAndReportsUnknown(t *testing.T) {
	p := &scriptedPinger{errs: map[string]error{"a.example:0": &RateLimitError{Reset: time.Minute}}}
	targets := []Target{{ID: 1, Host: "a.example", Port: 443}, {ID: 2, Host: "a.example", Port: 8443}}
	r := RunRound(context.Background(), p, targets, 0)
	var rl *RateLimitError
	if !errors.As(r.Err, &rl) || rl.Reset != time.Minute {
		t.Fatalf("Err = %v, want the rate limit with its reset", r.Err)
	}
	if want := (map[int64]Verdict{1: Unknown, 2: Unknown}); !reflect.DeepEqual(verdicts(r), want) {
		t.Errorf("verdicts = %v, want %v: a refusal is not a block", verdicts(r), want)
	}
	if len(p.calls) != 1 {
		t.Errorf("made %d requests after being refused, want 1", len(p.calls))
	}
}

func TestRunRoundSurvivesOneFailedMeasurement(t *testing.T) {
	boom := &APIError{Status: 500, Type: "x", Message: "y"}
	p := &scriptedPinger{
		errs:    map[string]error{"a.example:0": boom},
		answers: map[string][]ProbeResult{"a.example:443": probes(5, 3)},
	}
	r := RunRound(context.Background(), p, []Target{{ID: 1, Host: "a.example", Port: 443}}, 0)
	if !errors.Is(r.Err, boom) {
		t.Errorf("Err = %v, want %v", r.Err, boom)
	}
	if got := r.Results[1].Verdict; got != OK {
		t.Errorf("verdict = %q, want ok from the measurement that did work", got)
	}
	if got := p.calls[1]; got.Reuse != "" {
		t.Errorf("second request reuses %q, but the anchor never existed", got.Reuse)
	}
}

func TestRunRoundCapsAndRotatesMeasurements(t *testing.T) {
	p := &scriptedPinger{answers: map[string][]ProbeResult{}}
	var targets []Target
	for i := range MaxMeasurements + 3 {
		port := 1000 + i
		targets = append(targets, Target{ID: int64(i + 1), Host: "a.example", Port: port})
		p.answers[fmt.Sprintf("a.example:%d", port)] = probes(5, 3)
	}
	p.answers["a.example:0"] = probes(5, 3)

	measured := func(r Round) []int64 {
		var ids []int64
		for id, o := range r.Results {
			if o.Verdict != OK {
				t.Errorf("line %d: verdict %q, want ok", id, o.Verdict)
			}
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		return ids
	}
	seen := map[int64]int{}
	start := 0
	// The ping takes one slot, leaving 11 for 15 ports.
	for i, want := range [][]int64{
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
		{1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15},
		{8, 9, 10, 11, 12, 13, 14, 15, 1, 2, 3},
	} {
		p.calls = nil
		r := RunRound(context.Background(), p, targets, start)
		if !errors.Is(r.Err, ErrTooManyTargets) {
			t.Errorf("round %d: Err = %v, want ErrTooManyTargets", i, r.Err)
		}
		if len(p.calls) != MaxMeasurements {
			t.Errorf("round %d: made %d measurements, want the cap %d", i, len(p.calls), MaxMeasurements)
		}
		if p.calls[0] != (PingRequest{Host: "a.example"}) {
			t.Errorf("round %d: first measurement %+v, want the host ping every round", i, p.calls[0])
		}
		sort.Slice(want, func(a, b int) bool { return want[a] < want[b] })
		if got := measured(r); !reflect.DeepEqual(got, want) {
			t.Errorf("round %d: measured lines %v, want %v", i, got, want)
		}
		for id := range r.Results {
			seen[id]++
		}
		start = r.Next
	}
	for _, tg := range targets {
		if seen[tg.ID] < 2 {
			t.Errorf("line %d measured %d times in 3 rounds; rotation should reach every line twice", tg.ID, seen[tg.ID])
		}
	}
}

func TestRunRoundCappedDoesNotCondemnTheAddress(t *testing.T) {
	// China cannot ping the host, and every port the round reaches is closed to China, but a
	// port the cap leaves out might still be open: the measured ports are only port-blocked.
	blocked := probes(0, 3)
	p := &scriptedPinger{answers: map[string][]ProbeResult{"a.example:0": blocked}}
	var targets []Target
	for i := range MaxMeasurements + 3 {
		port := 1000 + i
		targets = append(targets, Target{ID: int64(i + 1), Host: "a.example", Port: port})
		p.answers[fmt.Sprintf("a.example:%d", port)] = blocked
	}
	r := RunRound(context.Background(), p, targets, 0)
	if len(r.Results) == 0 {
		t.Fatal("no results")
	}
	for id, o := range r.Results {
		if o.Verdict != PortBlocked {
			t.Errorf("line %d: verdict %q, want port_blocked while some ports went unmeasured", id, o.Verdict)
		}
	}

	// The same host measured in full is judged blocked as a whole.
	r = RunRound(context.Background(), p, targets[:3], 0)
	for id, o := range r.Results {
		if o.Verdict != IPBlocked {
			t.Errorf("full round, line %d: verdict %q, want ip_blocked", id, o.Verdict)
		}
	}
}

func TestCost(t *testing.T) {
	one := []Target{{ID: 1, Host: "a.example", Port: 443}}
	three := append([]Target{{ID: 2, Host: "a.example", Port: 8443}, {ID: 3, Host: "a.example", Port: 9000, IPOnly: true}}, one...)
	var many []Target
	for i := range 40 {
		many = append(many, Target{ID: int64(i), Host: "a.example", Port: 1000 + i})
	}
	for _, tc := range []struct {
		name    string
		targets []Target
		want    int
	}{
		{"no lines", nil, 0},
		{"one tcp line: ping + port", one, 16},
		{"two tcp lines and a udp line on one host: ping + two ports", three, 24},
		{"capped", many, 96},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Cost(tc.targets); got != tc.want {
				t.Errorf("Cost = %d, want %d", got, tc.want)
			}
		})
	}
	if twice := 2 * Cost(many); twice > HourlyLimit {
		t.Errorf("two capped rounds cost %d tests, over the hourly limit %d", twice, HourlyLimit)
	}
}

func TestEffectiveInterval(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured time.Duration
		cost       int
		want       time.Duration
	}{
		{"default with one line is untouched", 30 * time.Minute, 16, 30 * time.Minute},
		{"shortest interval with one line just fits", 10 * time.Minute, 16, 10 * time.Minute},
		{"shortest interval with three lines is stretched", 10 * time.Minute, 32, 20 * time.Minute},
		{"a capped round runs about hourly", 10 * time.Minute, 96, 58 * time.Minute},
		{"nothing to measure", 10 * time.Minute, 0, 10 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveInterval(tc.configured, tc.cost)
			if got != tc.want {
				t.Errorf("EffectiveInterval = %s, want %s", got, tc.want)
			}
			if perHour := float64(tc.cost) * float64(time.Hour) / float64(got); perHour > ScheduledBudget {
				t.Errorf("%.0f tests/hour exceeds the budget of %d", perHour, ScheduledBudget)
			}
		})
	}
}
