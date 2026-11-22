// Package quota adds up each client's traffic and blocks clients past their quota or expiry.
package quota

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
)

type Store interface {
	ListClients(ctx context.Context) ([]model.Client, error)
	AddTraffic(ctx context.Context, add map[int64]model.Traffic) error
	SetClientDisabled(ctx context.Context, id int64, reason model.DisabledReason) error
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

// Tick records new traffic and reconciles blocks. changed means the engine config must be rebuilt.
// A failing source is returned as err only after expiry and quota have still been enforced.
func Tick(ctx context.Context, st Store, source TrafficSource, now time.Time) (changed bool, err error) {
	traffic, sourceErr := source(ctx)
	if add := ByClientID(traffic); len(add) > 0 {
		if err := st.AddTraffic(ctx, add); err != nil {
			return false, err
		}
	}

	clients, err := st.ListClients(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range clients {
		want := Desired(c, now)
		if want == c.Disabled {
			continue
		}
		if err := st.SetClientDisabled(ctx, c.ID, want); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, sourceErr
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
