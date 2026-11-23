package panel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Link2theWorld/mintyx/internal/quota"
)

// Runner periodically records traffic, enforces quotas and expiry, and resyncs the engine.
type Runner struct {
	s        *Server
	src      quota.TrafficSource
	interval time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) NewRunner(src quota.TrafficSource, interval time.Duration) *Runner {
	return &Runner{s: s, src: src, interval: interval}
}

// Tick runs one quota pass. It syncs when blocks changed or an earlier Sync failed.
func (r *Runner) Tick(ctx context.Context) error {
	s := r.s
	s.mu.Lock()
	defer s.mu.Unlock()
	// Finish storing the prior batch before starting a new cycle or draining Xray again.
	if len(s.unstoredTraffic) != 0 {
		if err := s.st.AddTraffic(ctx, s.unstoredTraffic); err != nil {
			return err
		}
		s.unstoredTraffic = nil
	}
	loc, locErr := s.location(ctx)
	if locErr != nil {
		// Reading monthly days in a fallback zone could reset usage a second time; wait for
		// a tick that can read the configured one.
		loc = nil
	}
	res, tickErr := quota.Tick(ctx, s.st, r.src, s.now(), loc)
	s.unstoredTraffic = res.UnstoredTraffic
	for _, c := range res.CycleResets {
		s.auditSystem(ctx, "client.cycle-reset", c.Name, "")
	}
	var syncErr error
	if res.Changed || s.syncPending {
		syncErr = s.syncLocked(ctx)
	}
	return errors.Join(locErr, tickErr, syncErr)
}

// Start runs Tick every interval until Stop or ctx is done. Starting twice is a no-op.
func (r *Runner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
					r.s.log.Warn("panel: quota tick", "err", err)
				}
			}
		}
	}(r.done)
}

// Stop cancels the loop and waits for an in-flight tick to finish.
func (r *Runner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
