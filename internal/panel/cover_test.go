package panel

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/reach"
)

// fakePicker offers its sites in order, as the real one does after ranking them.
type fakePicker struct {
	sites []string

	mu       sync.Mutex
	filtered []bool
}

func (p *fakePicker) Pick(ctx context.Context, _ string, accept func(context.Context, string) bool) string {
	p.mu.Lock()
	p.filtered = append(p.filtered, accept != nil)
	p.mu.Unlock()
	for _, s := range p.sites {
		if accept == nil || accept(ctx, s) {
			return s
		}
	}
	return ""
}

type fakeCoverCheck struct {
	mu       sync.Mutex
	verdicts map[string]reach.CoverVerdict
	err      error
	calls    []string
}

func (f *fakeCoverCheck) CheckCover(_ context.Context, host string) (reach.CoverVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, host)
	return f.verdicts[host], f.err
}

func (f *fakeCoverCheck) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newCoverFixture(t *testing.T, sites ...string) (*fixture, *fakePicker, *fakeCoverCheck, *http.Cookie) {
	t.Helper()
	picker := &fakePicker{sites: sites}
	cc := &fakeCoverCheck{verdicts: map[string]reach.CoverVerdict{}}
	f := newFixture(t, func(c *Config) {
		c.Reach = &fakePinger{}
		c.Covers, c.CoverCheck = picker, cc
	})
	return f, picker, cc, f.setup()
}

func (f *fixture) enableReach(on bool) {
	f.t.Helper()
	raw := `{"enabled":false,"intervalMinutes":30,"confirmRounds":2,"smtp":{"port":587,"security":"starttls"}}`
	if on {
		raw = `{"enabled":true,"intervalMinutes":30,"confirmRounds":2,"smtp":{"port":587,"security":"starttls"}}`
	}
	if err := f.st.SetSetting(f.t.Context(), settingReachConfig, raw); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) draftCover(c *http.Cookie) string {
	f.t.Helper()
	w := f.do("POST", "/api/lines/draft", map[string]string{"protocol": "vless-reality", "region": "jp"}, withCookie(c))
	expectStatus(f.t, w, http.StatusOK)
	return decodeBody[map[string]any](f.t, w)["reality"].(map[string]any)["serverName"].(string)
}

func TestCoverSitesAreNotCheckedFromChinaWhileReachIsOff(t *testing.T) {
	f, picker, cc, c := newCoverFixture(t, "a.example", "b.example")
	cc.verdicts["a.example"] = reach.CoverVerdict{Problem: "mainland address"}
	if got := f.draftCover(c); got != "a.example" {
		t.Fatalf("draft cover = %q, want a.example: with the check off nothing is asked of Globalping", got)
	}
	if cc.count() != 0 || picker.filtered[0] {
		t.Fatalf("mainland checks = %d, filtered = %v; want none while the reachability check is off", cc.count(), picker.filtered)
	}
}

func TestCoverSitesTurnedDownFromChinaAreSkipped(t *testing.T) {
	f, _, cc, c := newCoverFixture(t, "a.example", "b.example")
	f.enableReach(true)
	cc.verdicts["a.example"] = reach.CoverVerdict{Problem: "resolves to a mainland China address"}
	cc.verdicts["b.example"] = reach.CoverVerdict{OK: true}

	if got := f.draftCover(c); got != "b.example" {
		t.Fatalf("draft cover = %q, want b.example: a.example was turned down", got)
	}
	if cc.count() != 2 {
		t.Fatalf("mainland checks = %d, want 2", cc.count())
	}
	// The verdicts are cached for days: a second draft asks nothing.
	*f.clock = f.clock.Add(24 * time.Hour)
	if got := f.draftCover(c); got != "b.example" || cc.count() != 2 {
		t.Fatalf("second draft = %q after %d checks, want b.example from the cache", got, cc.count())
	}
}

func TestCoverSiteWithoutAVerdictIsKept(t *testing.T) {
	f, _, cc, c := newCoverFixture(t, "a.example", "b.example")
	f.enableReach(true)
	cc.err = errors.New("globalping: 500")
	if got := f.draftCover(c); got != "a.example" {
		t.Fatalf("draft cover = %q, want a.example: no verdict means choosing as with the check off", got)
	}
}

func TestOneCoverChoiceStartsAFewChecksAtMost(t *testing.T) {
	f, _, cc, c := newCoverFixture(t, "a.example", "b.example", "c.example", "d.example", "e.example")
	f.enableReach(true)
	for _, s := range []string{"a.example", "b.example", "c.example", "d.example", "e.example"} {
		cc.verdicts[s] = reach.CoverVerdict{Problem: "blocked"}
	}
	if got := f.draftCover(c); got != "d.example" || cc.count() != coverChecksPerPick {
		t.Fatalf("draft cover = %q after %d checks; want d.example, unchecked, after %d", got, cc.count(), coverChecksPerPick)
	}
}
