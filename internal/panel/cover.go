package panel

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/Link2theWorld/mintyx/internal/probe"
	"github.com/Link2theWorld/mintyx/internal/reach"
)

// settingCoverCache holds what mainland probes said about cover sites, as a reach.CoverCache.
const settingCoverCache = "reach.coverCache"

// coverChecksPerPick caps the fresh mainland checks one cover-site choice may start, so that a
// region whose candidates keep failing cannot keep a request waiting for minutes.
const coverChecksPerPick = 3

// CoverPicker finds REALITY cover sites from this server; *probe.Prober is the real one.
type CoverPicker interface {
	// Pick returns a usable site for region that accept keeps, or "" when there is none.
	// accept of nil keeps every site.
	Pick(ctx context.Context, region string, accept func(context.Context, string) bool) string
	// Check says whether host still qualifies as a cover site, as seen from this server.
	Check(ctx context.Context, host string) probe.Result
}

// noCoverCheck stands in when no mainland checker is configured: no site ever gets a verdict.
type noCoverCheck struct{}

func (noCoverCheck) CheckCover(context.Context, string) (reach.CoverVerdict, error) {
	return reach.CoverVerdict{}, errors.New("panel: no mainland cover-site checker configured")
}

// coverAccept is the filter cover-site choices go through: nil while the reachability check is
// off, since only that setting allows the panel to talk to Globalping. While it is on, a site
// mainland probes turned down is skipped; a site without a verdict (no budget left, the API
// failing) is kept, so the choice falls back to what it would be with the check off.
func (s *Server) coverAccept(ctx context.Context) func(context.Context, string) bool {
	vet := s.coverVetter(ctx)
	if vet == nil {
		return nil
	}
	return func(ctx context.Context, host string) bool { return vet(ctx, host) == "" }
}

// coverVetter is coverAccept saying why: it returns what mainland probes hold against a site,
// "" when nothing or when there is no verdict, and is nil while the reachability check is off.
// One vetter starts at most coverChecksPerPick fresh checks.
func (s *Server) coverVetter(ctx context.Context) func(context.Context, string) string {
	cfg, _, err := s.loadReachConfig(ctx)
	if err != nil || !cfg.Enabled {
		return nil
	}
	var mu sync.Mutex
	checks := 0
	return func(ctx context.Context, host string) string {
		mu.Lock()
		defer mu.Unlock()
		v, known, checked := s.vetCover(ctx, host, checks < coverChecksPerPick)
		if checked {
			checks++
		}
		if !known || v.OK {
			return ""
		}
		return "mainland China probes: " + v.Problem
	}
}

func (s *Server) loadCoverCache(ctx context.Context) (reach.CoverCache, error) {
	var c reach.CoverCache
	raw, found, err := s.st.GetSetting(ctx, settingCoverCache)
	if err != nil || !found {
		return c, err
	}
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		// Losing the cache only costs checks that run again.
		s.log.Warn("panel: stored cover-site cache unreadable, starting over", "err", err)
		return reach.CoverCache{}, nil
	}
	return c, nil
}

// vetCover asks reach.VetCover about host and stores the cache it updates. A rate-limit pause the
// line checks are in holds cover-site checks back too.
func (s *Server) vetCover(ctx context.Context, host string, mayCheck bool) (v reach.CoverVerdict, known, checked bool) {
	s.coverMu.Lock()
	defer s.coverMu.Unlock()
	cache, err := s.loadCoverCache(ctx)
	if err != nil {
		s.log.Warn("panel: load cover-site cache", "err", err)
		return reach.CoverVerdict{}, false, false
	}
	if rec, err := s.loadReachRecord(ctx); err == nil && rec.RetryAt.After(cache.RetryAt) {
		cache.RetryAt = rec.RetryAt
	}
	v, known, checked, err = reach.VetCover(ctx, s.coverCheck, &cache, host, mayCheck, s.now())
	if err != nil {
		s.log.Warn("panel: mainland cover-site check", "host", host, "err", err)
	}
	if checked {
		raw, err := json.Marshal(cache)
		if err == nil {
			err = s.st.SetSetting(context.WithoutCancel(ctx), settingCoverCache, string(raw))
		}
		if err != nil {
			s.log.Warn("panel: save cover-site cache", "err", err)
		}
	}
	return v, known, checked
}
