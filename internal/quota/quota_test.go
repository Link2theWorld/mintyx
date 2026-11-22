package quota

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
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

	changed, err := Tick(context.Background(), st, source, now)
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
	changed, err := Tick(context.Background(), st, source, now)
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

	changed, err := Tick(context.Background(), st, source, now)
	if !errors.Is(err, down) {
		t.Fatalf("err = %v, want the source error surfaced", err)
	}
	if !changed || st.clients[1].Disabled != model.DisabledExpired {
		t.Fatalf("changed=%v disabled=%q, want the expired client blocked despite the stats failure", changed, st.clients[1].Disabled)
	}
}
