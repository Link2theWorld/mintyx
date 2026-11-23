package panel

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

const (
	// settingCoverRecheck holds what the last rechecks of the lines' cover sites found.
	settingCoverRecheck = "cover.recheck"
	// coverRecheckEvery is how often each REALITY line's cover site is checked again.
	coverRecheckEvery = 6 * time.Hour
	// coverRecheckConfirm is how many checks in a row a cover site must fail before it is replaced:
	// replacing one moves every client of the line to a new name, which one network blip must not do.
	coverRecheckConfirm = 2
	coverRecheckTimeout = 10 * time.Minute
)

var errNoNewCover = errors.New("no other usable cover site")

type coverLineState struct {
	// Site is the cover site the failures were counted against; another site starts over.
	Site     string `json:"site"`
	Failures int    `json:"failures,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

type coverRecheckState struct {
	LastRunAt time.Time                `json:"lastRunAt"`
	Lines     map[int64]coverLineState `json:"lines,omitempty"`
}

// managedCover returns the cover site of an enabled REALITY line whose cover the panel looks after:
// one whose target is its server name on port 443, the way the panel sets lines up. A line that
// forwards elsewhere, such as to a web server of its own, was set up by hand and is left alone.
func managedCover(l model.Line) (string, bool) {
	if l.Protocol != model.VLESSReality || !l.Enabled || l.Reality == nil || l.Reality.ServerName == "" {
		return "", false
	}
	return l.Reality.ServerName, l.Reality.Target == l.Reality.ServerName+":443"
}

func (s *Server) loadCoverRecheck(ctx context.Context) (coverRecheckState, error) {
	var st coverRecheckState
	raw, found, err := s.st.GetSetting(ctx, settingCoverRecheck)
	if err != nil || !found {
		return st, err
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		s.log.Warn("panel: stored cover recheck state unreadable, starting over", "err", err)
		return coverRecheckState{}, nil
	}
	return st, nil
}

// coverProblem says why site no longer qualifies as a cover, or "" when it still does or there
// is no telling. Mainland probes have a say only while the reachability check is on.
func (s *Server) coverProblem(ctx context.Context, site string, vet func(context.Context, string) string) string {
	if r := s.covers.Check(ctx, site); !r.OK {
		return r.Problem
	}
	if vet != nil {
		return vet(ctx, site)
	}
	return ""
}

// recheckCovers checks the cover site of every line the panel looks after, and replaces one
// that has failed coverRecheckConfirm checks in a row with a new pick for this server's region.
// Only the line's serverName and target change: its keys and short ID stay, so clients only need
// their subscription refreshed. It never holds s.mu while talking to the network.
func (s *Server) recheckCovers(ctx context.Context) error {
	if s.covers == nil {
		return nil
	}
	lines, err := s.st.ListLines(ctx)
	if err != nil {
		return err
	}
	prev, err := s.loadCoverRecheck(ctx)
	if err != nil {
		return err
	}
	region, _, err := s.st.GetSetting(ctx, settingServerRegion)
	if err != nil {
		return err
	}
	vet := s.coverVetter(ctx)
	next := coverRecheckState{LastRunAt: s.now(), Lines: map[int64]coverLineState{}}
	var errs []error
	for _, l := range lines {
		site, ok := managedCover(l)
		if !ok {
			continue
		}
		cur := prev.Lines[l.ID]
		if cur.Site != site {
			cur = coverLineState{Site: site}
		}
		problem := s.coverProblem(ctx, site, vet)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if problem == "" {
			next.Lines[l.ID] = coverLineState{Site: site}
			continue
		}
		cur.Failures++
		cur.Problem = problem
		if cur.Failures >= coverRecheckConfirm {
			switched, err := s.switchCover(ctx, l.ID, site, region, vet, problem)
			switch {
			case err != nil:
				errs = append(errs, err)
			case switched != "":
				cur = coverLineState{Site: switched}
			}
		}
		next.Lines[l.ID] = cur
	}
	raw, err := json.Marshal(next)
	if err == nil {
		err = s.st.SetSetting(context.WithoutCancel(ctx), settingCoverRecheck, string(raw))
	}
	return errors.Join(append(errs, err)...)
}

// switchCover moves line id from cover site old to a new pick, syncs Xray and records it. It
// returns the new site, or "" when the line changed meanwhile and was left as it is.
func (s *Server) switchCover(ctx context.Context, id int64, old, region string, vet func(context.Context, string) string, why string) (string, error) {
	site := s.covers.Pick(ctx, region, func(ctx context.Context, h string) bool {
		return h != old && (vet == nil || vet(ctx, h) == "")
	})
	if site == "" {
		return "", errNoNewCover
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, err := s.st.GetLine(ctx, id)
	if err != nil {
		return "", err
	}
	if cur, ok := managedCover(l); !ok || cur != old {
		// The admin changed the line while the new site was being picked; theirs stands.
		return "", nil
	}
	before := *l.Reality
	after := before
	after.ServerName, after.Target = site, site+":443"
	l.Reality = &after
	ctx = context.WithoutCancel(ctx)
	if err := s.st.UpdateLine(ctx, &l); err != nil {
		return "", err
	}
	if syncErr := s.syncLocked(ctx); errors.Is(syncErr, ErrConfigRejected) {
		l.Reality = &before
		if err := s.st.UpdateLine(ctx, &l); err != nil {
			return "", errors.Join(syncErr, err)
		}
		_ = s.syncLocked(ctx)
		return "", syncErr
	}
	// Any other sync failure is retried by the runner; the store already has the new site.
	s.auditSystem(ctx, "line.cover-switch", l.Name, old+" → "+site+": "+why)
	return site, nil
}

// CoverRunner rechecks the lines' cover sites every coverRecheckEvery. It wakes far more often,
// so a recheck missed while the panel was down happens soon after it starts again.
type CoverRunner struct {
	s    *Server
	wake time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) NewCoverRunner(wake time.Duration) *CoverRunner {
	return &CoverRunner{s: s, wake: wake}
}

// Tick rechecks the cover sites if a recheck is due; ran reports whether it did.
func (r *CoverRunner) Tick(ctx context.Context) (ran bool, err error) {
	s := r.s
	if s.covers == nil {
		return false, nil
	}
	st, err := s.loadCoverRecheck(ctx)
	if err != nil {
		return false, err
	}
	if !st.LastRunAt.IsZero() && s.now().Sub(st.LastRunAt) < coverRecheckEvery {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, coverRecheckTimeout)
	defer cancel()
	return true, s.recheckCovers(ctx)
}

// Start runs Tick every wake until Stop or ctx is done. Starting twice is a no-op.
func (r *CoverRunner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		t := time.NewTicker(r.wake)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := r.Tick(ctx); err != nil && ctx.Err() == nil {
					r.s.log.Warn("panel: cover recheck", "err", err)
				}
			}
		}
	}(r.done)
}

// Stop cancels the loop and waits for an in-flight recheck to finish.
func (r *CoverRunner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
