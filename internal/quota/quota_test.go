package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time {
	t := now.Add(d)
	return &t
}

func TestDesired(t *testing.T) {
	tests := []struct {
		name string
		c    model.Client
		want model.DisabledReason
	}{
		{"unlimited stays on", model.Client{UsedDown: 1 << 40}, model.NotDisabled},
		{"under quota", model.Client{QuotaBytes: 100, UsedUp: 40, UsedDown: 59}, model.NotDisabled},
		{"up plus down reaches quota", model.Client{QuotaBytes: 100, UsedUp: 40, UsedDown: 60}, model.DisabledQuota},
		{"expiry in the future", model.Client{ExpiresAt: at(time.Second)}, model.NotDisabled},
		{"expiry reached", model.Client{ExpiresAt: at(0)}, model.DisabledExpired},
		{"expired wins over quota", model.Client{QuotaBytes: 1, UsedUp: 5, ExpiresAt: at(-time.Hour)}, model.DisabledExpired},
		{"manual is never lifted", model.Client{Disabled: model.DisabledManual}, model.DisabledManual},
		{"manual is never replaced", model.Client{Disabled: model.DisabledManual, QuotaBytes: 1, UsedUp: 5}, model.DisabledManual},
		{"quota block lifts after a reset", model.Client{Disabled: model.DisabledQuota, QuotaBytes: 100}, model.NotDisabled},
		{"expiry block lifts after renewal", model.Client{Disabled: model.DisabledExpired, ExpiresAt: at(time.Hour)}, model.NotDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Desired(tt.c, now); got != tt.want {
				t.Fatalf("Desired = %q, want %q", got, tt.want)
			}
		})
	}
}

type fakeStore struct {
	clients map[int64]*model.Client
}

func (f *fakeStore) ListClients(context.Context) ([]model.Client, error) {
	out := make([]model.Client, 0, len(f.clients))
	for _, c := range f.clients {
		out = append(out, *c)
	}
	return out, nil
}

func (f *fakeStore) AddTraffic(_ context.Context, add map[int64]model.Traffic) error {
	for id, tr := range add {
		if c, ok := f.clients[id]; ok {
			c.UsedUp += tr.Up
			c.UsedDown += tr.Down
		}
	}
	return nil
}

func (f *fakeStore) SetClientDisabled(_ context.Context, id int64, r model.DisabledReason) error {
	f.clients[id].Disabled = r
	return nil
}

func (f *fakeStore) StartCycle(_ context.Context, id int64, start time.Time, zero bool) (bool, error) {
	c := f.clients[id]
	if c.CycleStart != nil && !c.CycleStart.Before(start) {
		return false, nil
	}
	c.CycleStart = &start
	if zero {
		c.UsedUp, c.UsedDown = 0, 0
	}
	return true, nil
}

func TestTickCountsTrafficAndBlocksAtQuota(t *testing.T) {
	st := &fakeStore{clients: map[int64]*model.Client{
		1: {ID: 1, QuotaBytes: 1000, UsedDown: 900},
		2: {ID: 2, QuotaBytes: 1000},
	}}
	source := func(context.Context) (map[string]model.Traffic, error) {
		return map[string]model.Traffic{
			"c1":      {Up: 30, Down: 70},
			"c2":      {Up: 1, Down: 2},
			"c999":    {Up: 5},
			"unknown": {Up: 5},
		}, nil
	}

	res, err := Tick(context.Background(), st, source, now, time.UTC)
	changed := res.Changed
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed = false, want true: client 1 crossed its quota and the engine config must be rebuilt")
	}
	if c := st.clients[1]; c.UsedUp != 30 || c.UsedDown != 970 || c.Disabled != model.DisabledQuota {
		t.Fatalf("client 1 = up %d down %d disabled %q, want 30/970/quota", c.UsedUp, c.UsedDown, c.Disabled)
	}
	if c := st.clients[2]; c.UsedUp != 1 || c.UsedDown != 2 || c.Disabled != model.NotDisabled {
		t.Fatalf("client 2 = up %d down %d disabled %q, want 1/2/enabled", c.UsedUp, c.UsedDown, c.Disabled)
	}
}

func TestTickReportsNoChangeWhenNobodyCrosses(t *testing.T) {
	st := &fakeStore{clients: map[int64]*model.Client{
		1: {ID: 1, QuotaBytes: 1000},
		2: {ID: 2, Disabled: model.DisabledManual},
	}}
	source := func(context.Context) (map[string]model.Traffic, error) {
		return map[string]model.Traffic{"c1": {Down: 10}}, nil
	}
	res, err := Tick(context.Background(), st, source, now, time.UTC)
	changed := res.Changed
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("changed = true, want false: an unneeded rebuild restarts the engine and drops connections")
	}
}

func TestTickStillEnforcesExpiryWhenEngineIsDown(t *testing.T) {
	st := &fakeStore{clients: map[int64]*model.Client{1: {ID: 1, ExpiresAt: at(-time.Minute)}}}
	down := errors.New("engine not running")
	source := func(context.Context) (map[string]model.Traffic, error) { return nil, down }

	res, err := Tick(context.Background(), st, source, now, time.UTC)
	changed := res.Changed
	if !errors.Is(err, down) {
		t.Fatalf("err = %v, want the source error surfaced", err)
	}
	if !changed || st.clients[1].Disabled != model.DisabledExpired {
		t.Fatalf("changed=%v disabled=%q, want the expired client blocked despite the stats failure", changed, st.clients[1].Disabled)
	}
}

func TestCycleStartAndNextReset(t *testing.T) {
	seoul, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Fatal(err)
	}
	kst := func(y int, m time.Month, d, h int) time.Time { return time.Date(y, m, d, h, 0, 0, 0, seoul) }
	tests := []struct {
		name      string
		day       int
		now       time.Time
		start     time.Time
		nextReset time.Time
	}{
		{"mid-month", 15, kst(2026, 11, 22, 12), kst(2026, 11, 15, 0), kst(2026, 12, 15, 0)},
		{"before this month's day", 25, kst(2026, 11, 22, 12), kst(2026, 10, 25, 0), kst(2026, 11, 25, 0)},
		{"exactly at midnight", 1, kst(2026, 12, 1, 0), kst(2026, 12, 1, 0), kst(2027, 1, 1, 0)},
		{"one second before", 1, kst(2026, 12, 1, 0).Add(-time.Second), kst(2026, 11, 1, 0), kst(2026, 12, 1, 0)},
		{"31st in February", 31, kst(2027, 2, 10, 9), kst(2027, 1, 31, 0), kst(2027, 2, 28, 0)},
		{"31st after February's end", 31, kst(2027, 3, 5, 9), kst(2027, 2, 28, 0), kst(2027, 3, 31, 0)},
		{"29th in a leap year", 29, kst(2028, 2, 29, 1), kst(2028, 2, 29, 0), kst(2028, 3, 29, 0)},
		{"30th in a 31-day month", 30, kst(2026, 12, 31, 5), kst(2026, 12, 30, 0), kst(2027, 1, 30, 0)},
		{"across the year", 15, kst(2027, 1, 3, 0), kst(2026, 12, 15, 0), kst(2027, 1, 15, 0)},
		// 2026-11-30 20:00 UTC is already 1 December in Seoul.
		{"read in the zone, not UTC", 1, time.Date(2026, 11, 30, 20, 0, 0, 0, time.UTC), kst(2026, 12, 1, 0), kst(2027, 1, 1, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CycleStart(tt.day, tt.now, seoul); !got.Equal(tt.start) {
				t.Errorf("CycleStart = %v, want %v", got, tt.start)
			}
			if got := NextReset(tt.day, tt.now, seoul); !got.Equal(tt.nextReset) {
				t.Errorf("NextReset = %v, want %v", got, tt.nextReset)
			}
		})
	}
}

func TestTickStartsMonthlyCyclesOnce(t *testing.T) {
	last := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	st := &fakeStore{clients: map[int64]*model.Client{
		// Over quota last cycle, so blocked; the new cycle must zero it and lift the block.
		1: {ID: 1, QuotaBytes: 1000, UsedDown: 1500, Disabled: model.DisabledQuota, QuotaResetDay: 1, CycleStart: &last},
		// Cycle set up but never anchored: anchored without losing its usage.
		2: {ID: 2, QuotaBytes: 1000, UsedDown: 300, QuotaResetDay: 1},
		// Not monthly: untouched.
		3: {ID: 3, QuotaBytes: 1000, UsedDown: 1500, Disabled: model.DisabledQuota},
		// A manual block survives the reset, only the usage goes.
		4: {ID: 4, UsedDown: 50, Disabled: model.DisabledManual, QuotaResetDay: 1, CycleStart: &last},
	}}
	novFirst := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	res, err := Tick(context.Background(), st, noTraffic, now, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || len(res.CycleResets) != 2 || res.CycleResets[0].ID+res.CycleResets[1].ID != 5 {
		t.Fatalf("result = %+v, want a change and resets for clients 1 and 4", res)
	}
	c1, c2, c3, c4 := st.clients[1], st.clients[2], st.clients[3], st.clients[4]
	if c1.UsedDown != 0 || c1.Disabled != model.NotDisabled || !c1.CycleStart.Equal(novFirst) {
		t.Errorf("client 1 = %+v, want usage zeroed, unblocked, cycle from 1 November", c1)
	}
	if c2.UsedDown != 300 || !c2.CycleStart.Equal(novFirst) {
		t.Errorf("client 2 = %+v, want usage kept and the cycle anchored", c2)
	}
	if c3.UsedDown != 1500 || c3.Disabled != model.DisabledQuota || c3.CycleStart != nil {
		t.Errorf("client 3 = %+v, want untouched", c3)
	}
	if c4.UsedDown != 0 || c4.Disabled != model.DisabledManual {
		t.Errorf("client 4 = %+v, want usage zeroed and still manually blocked", c4)
	}

	st.clients[1].UsedDown = 400
	res, err = Tick(context.Background(), st, noTraffic, now, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || len(res.CycleResets) != 0 || st.clients[1].UsedDown != 400 {
		t.Fatalf("second tick in the same cycle = %+v, usage %d; want nothing reset", res, st.clients[1].UsedDown)
	}
}

func noTraffic(context.Context) (map[string]model.Traffic, error) { return nil, nil }
