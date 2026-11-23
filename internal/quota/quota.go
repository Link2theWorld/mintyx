// Package quota adds up each client's traffic and blocks clients past their quota or expiry.
package quota

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

type Store interface {
	ListClients(ctx context.Context) ([]model.Client, error)
	AddTraffic(ctx context.Context, add map[int64]model.Traffic) error
	SetClientDisabled(ctx context.Context, id int64, reason model.DisabledReason) error
	StartCycle(ctx context.Context, id int64, start time.Time, zeroUsage bool) (bool, error)
}

// TrafficSource returns traffic since the previous call, keyed by Client.StatsTag.
type TrafficSource func(ctx context.Context) (map[string]model.Traffic, error)

// Desired is the block state a client should be in at now. A manual block is the admin's and never changes here.
func Desired(c model.Client, now time.Time) model.DisabledReason {
	if c.Disabled == model.DisabledManual {
		return model.DisabledManual
	}
	if c.ExpiresAt != nil && !now.Before(*c.ExpiresAt) {
		return model.DisabledExpired
	}
	if c.QuotaBytes > 0 && c.UsedUp+c.UsedDown >= c.QuotaBytes {
		return model.DisabledQuota
	}
	return model.NotDisabled
}

// dayOfMonth is midnight in loc on day of the month that contains y-m, or on its last day.
func dayOfMonth(y int, m time.Month, day int, loc *time.Location) time.Time {
	first := time.Date(y, m, 1, 0, 0, 0, 0, loc)
	last := first.AddDate(0, 1, -1).Day()
	return time.Date(first.Year(), first.Month(), min(day, last), 0, 0, 0, 0, loc)
}

// CycleStart is when the monthly cycle containing now began: midnight in loc on day (1–31,
// the month's last day when it is shorter) of this month, or of last month if that is still ahead.
func CycleStart(day int, now time.Time, loc *time.Location) time.Time {
	t := now.In(loc)
	start := dayOfMonth(t.Year(), t.Month(), day, loc)
	if start.After(t) {
		start = dayOfMonth(t.Year(), t.Month()-1, day, loc)
	}
	return start
}

// NextReset is when the monthly cycle containing now ends.
func NextReset(day int, now time.Time, loc *time.Location) time.Time {
	start := CycleStart(day, now, loc)
	return dayOfMonth(start.Year(), start.Month()+1, day, loc)
}

// Result reports what a Tick did. Changed means the engine config must be rebuilt.
type Result struct {
	Changed bool
	// CycleResets are the clients whose monthly usage went back to zero, as they were before.
	CycleResets []model.Client
	// UnstoredTraffic is the batch to retry if AddTraffic failed.
	UnstoredTraffic map[int64]model.Traffic
}

// Tick starts due monthly cycles, then records new traffic and reconciles blocks. One batch
// cannot be split at midnight, so it belongs to the cycle in force when it is collected;
// resetting after storing it would erase use after the boundary and invite quota abuse.
// Monthly days are read in loc; a nil loc skips monthly cycles this time. A failing source
// is returned as err only after everything else ran.
func Tick(ctx context.Context, st Store, source TrafficSource, now time.Time, loc *time.Location) (Result, error) {
	var res Result
	refresh := false
	clients, err := st.ListClients(ctx)
	if err != nil {
		return res, err
	}
	for _, c := range clients {
		if c.QuotaResetDay == 0 || loc == nil {
			continue
		}
		start := CycleStart(c.QuotaResetDay, now, loc)
		if c.CycleStart == nil || c.CycleStart.Before(start) {
			// No cycle recorded yet means nothing to end: anchor it without zeroing.
			zero := c.CycleStart != nil
			started, err := st.StartCycle(ctx, c.ID, start, zero)
			if err != nil {
				return res, err
			}
			if started && zero {
				res.CycleResets = append(res.CycleResets, c)
				refresh = true
			}
		}
	}

	traffic, sourceErr := source(ctx)
	if add := ByClientID(traffic); len(add) > 0 {
		if err := st.AddTraffic(ctx, add); err != nil {
			res.UnstoredTraffic = add
			return res, err
		}
		refresh = true
	}
	if refresh {
		// The block pass needs the counters as stored, including this batch and any reset above.
		if clients, err = st.ListClients(ctx); err != nil {
			return res, err
		}
	}
	for _, c := range clients {
		want := Desired(c, now)
		if want == c.Disabled {
			continue
		}
		if err := st.SetClientDisabled(ctx, c.ID, want); err != nil {
			return res, err
		}
		res.Changed = true
	}
	return res, sourceErr
}

// ByClientID turns stats-tag keyed traffic into client-ID keyed traffic, dropping tags that are not clients.
func ByClientID(traffic map[string]model.Traffic) map[int64]model.Traffic {
	out := make(map[int64]model.Traffic, len(traffic))
	for tag, tr := range traffic {
		digits, ok := strings.CutPrefix(tag, "c")
		if !ok {
			continue
		}
		id, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			continue
		}
		out[id] = tr
	}
	return out
}
