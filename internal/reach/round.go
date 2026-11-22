package reach

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	// HourlyLimit is Globalping's allowance for callers without a token, in tests per hour.
	HourlyLimit = 250
	// ScheduledBudget is the share the background loop may spend, leaving the rest for manual checks.
	ScheduledBudget = 100
	// MaxMeasurements caps one round so that two rounds back to back still fit in HourlyLimit.
	MaxMeasurements = 12
	parallelPings   = 4
)

// ErrTooManyTargets marks a round that left some lines unmeasured to stay inside the rate limit.
// Which lines are left out rotates from round to round, so each is still checked in turn.
var ErrTooManyTargets = errors.New("reach: more lines than one round can measure")

// Target is one enabled line and the address its clients dial.
type Target struct {
	ID   int64
	Name string
	Host string
	Port int
	// IPOnly marks a UDP line: Globalping cannot test UDP, so only the address is judged.
	IPOnly bool
}

// Pinger runs one measurement; *Client is the real one.
type Pinger interface {
	Ping(ctx context.Context, req PingRequest) (PingResult, error)
}

// Observation is what one round concluded about one target.
type Observation struct {
	Verdict Verdict
	// China and Control count the probes behind the verdict: the port's for TCP lines, ping's otherwise.
	China   Tally
	Control Tally
}

type Round struct {
	// Results has one entry per target the round measured; a target left out by the cap is absent.
	Results map[int64]Observation
	// Err is why some results are Unknown or absent; a *RateLimitError takes precedence.
	Err error
	// Next is where the following round's rotation starts, for RunRound's start argument.
	Next int
}

type measurementKey struct {
	host string
	port int
}

// plan lists the distinct measurements a round needs: one ping per host, one TCP ping per port.
func plan(targets []Target) []measurementKey {
	var keys []measurementKey
	seen := map[measurementKey]bool{}
	add := func(k measurementKey) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for _, t := range targets {
		host := strings.ToLower(t.Host)
		add(measurementKey{host, 0})
		if !t.IPOnly {
			add(measurementKey{host, t.Port})
		}
	}
	return keys
}

// choose caps a round at MaxMeasurements. Every host's ping is kept, since each port's verdict
// leans on it, and the port measurements that fit are taken in turn starting at start. next is
// where the following round should start, so lines cut this time come first then.
func choose(keys []measurementKey, start int) (chosen []measurementKey, next int, cut bool) {
	if len(keys) <= MaxMeasurements {
		return keys, 0, false
	}
	var pings, ports []measurementKey
	for _, k := range keys {
		if k.port == 0 {
			pings = append(pings, k)
		} else {
			ports = append(ports, k)
		}
	}
	if len(pings) >= MaxMeasurements {
		// So many hosts that their pings alone overflow: rotate through everything.
		pings, ports = nil, keys
	}
	start = max(start, 0) % len(ports)
	room := MaxMeasurements - len(pings)
	chosen = pings
	for i := range room {
		chosen = append(chosen, ports[(start+i)%len(ports)])
	}
	return chosen, (start + room) % len(ports), true
}

// Cost is how many of the hourly tests one round over targets spends.
func Cost(targets []Target) int {
	return min(len(plan(targets)), MaxMeasurements) * ProbesPerMeasurement()
}

type tallies struct{ china, control Tally }

func (t tallies) channel() Channel {
	return Channel{China: t.china.Reach(), Control: t.control.Reach()}
}

// RunRound measures every target once, or as many as MaxMeasurements allows, rotating from
// start (the previous round's Next). The first measurement picks the probes and the rest
// reuse them, so "ping answers but the port does not" compares like with like.
func RunRound(ctx context.Context, p Pinger, targets []Target, start int) Round {
	all := plan(targets)
	keys, next, cut := choose(all, start)
	var roundErr error
	if cut {
		roundErr = ErrTooManyTargets
	}
	planned := map[measurementKey]bool{}
	for _, k := range keys {
		planned[k] = true
	}
	skipped := map[string]bool{}
	for _, k := range all {
		if !planned[k] {
			skipped[k.host] = true
		}
	}

	var (
		mu       sync.Mutex
		measured = map[measurementKey]tallies{}
		limited  *RateLimitError
		firstErr error
	)
	run := func(k measurementKey, reuse string) string {
		res, err := p.Ping(ctx, PingRequest{Host: k.host, Port: k.port, Reuse: reuse})
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			var rl *RateLimitError
			switch {
			case errors.As(err, &rl):
				limited = rl
			case firstErr == nil:
				firstErr = err
			}
			return ""
		}
		var t tallies
		for _, pr := range res.Probes {
			if pr.China {
				t.china.add(pr.Outcome)
			} else {
				t.control.add(pr.Outcome)
			}
		}
		measured[k] = t
		return res.ID
	}
	stopped := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return limited != nil || ctx.Err() != nil
	}

	anchor := ""
	for len(keys) > 0 && anchor == "" && !stopped() {
		anchor = run(keys[0], "")
		keys = keys[1:]
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, parallelPings)
	for _, k := range keys {
		slots <- struct{}{}
		// Once the allowance is spent every further request would only be refused too.
		if stopped() {
			<-slots
			break
		}
		wg.Go(func() {
			defer func() { <-slots }()
			run(k, anchor)
		})
	}
	wg.Wait()

	out := Round{Results: map[int64]Observation{}, Err: roundErr, Next: next}
	switch {
	case limited != nil:
		out.Err = limited
	case firstErr != nil:
		out.Err = firstErr
	case ctx.Err() != nil:
		out.Err = ctx.Err()
	}
	for _, t := range targets {
		host := strings.ToLower(t.Host)
		ev := Evidence{ICMP: measured[measurementKey{host, 0}].channel(), TCP: map[int]Channel{}, Partial: skipped[host]}
		for k, m := range measured {
			if k.host == host && k.port != 0 {
				ev.TCP[k.port] = m.channel()
			}
		}
		key := measurementKey{host, t.Port}
		if t.IPOnly {
			key = measurementKey{host, 0}
		}
		if !planned[key] {
			// Left out by the cap: no news, so the line keeps what the last round said.
			continue
		}
		shown, port := measured[key], key.port
		out.Results[t.ID] = Observation{Verdict: Judge(ev, port), China: shown.china, Control: shown.control}
	}
	return out
}

// EffectiveInterval stretches the configured interval, in whole minutes, until a round of
// the given cost repeated all hour stays inside ScheduledBudget.
func EffectiveInterval(configured time.Duration, cost int) time.Duration {
	floor := time.Duration(cost) * time.Hour / ScheduledBudget
	if rem := floor % time.Minute; rem != 0 {
		floor += time.Minute - rem
	}
	return max(configured, floor)
}
