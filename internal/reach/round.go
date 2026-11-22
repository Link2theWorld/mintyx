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
	Results map[int64]Observation
	// Err is why some results are Unknown; a *RateLimitError takes precedence.
	Err error
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

// Cost is how many of the hourly tests one round over targets spends.
func Cost(targets []Target) int {
	return min(len(plan(targets)), MaxMeasurements) * ProbesPerMeasurement()
}

type tallies struct{ china, control Tally }

func (t tallies) channel() Channel {
	return Channel{China: t.china.Reach(), Control: t.control.Reach()}
}

// RunRound measures every target once. The first measurement picks the probes and the rest
// reuse them, so "ping answers but the port does not" compares like with like.
func RunRound(ctx context.Context, p Pinger, targets []Target) Round {
	keys := plan(targets)
	var roundErr error
	if len(keys) > MaxMeasurements {
		keys, roundErr = keys[:MaxMeasurements], ErrTooManyTargets
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

	out := Round{Results: map[int64]Observation{}, Err: roundErr}
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
		ev := Evidence{ICMP: measured[measurementKey{host, 0}].channel(), TCP: map[int]Channel{}}
		for k, m := range measured {
			if k.host == host && k.port != 0 {
				ev.TCP[k.port] = m.channel()
			}
		}
		shown, port := measured[measurementKey{host, t.Port}], t.Port
		if t.IPOnly {
			shown, port = measured[measurementKey{host, 0}], 0
		}
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
