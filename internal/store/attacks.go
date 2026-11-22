package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
)

const maxAttackSamples = 3

// visibleAttackers excludes the owner's own addresses, which keep a row only to stay excluded.
const visibleAttackers = `trusted = 0 AND hits > 0`

// RecordAttacks adds a drained batch to the tallies. trusted are addresses that just logged in
// with a key: what was recorded about them is dropped, and nothing more is recorded until they
// are pruned for inactivity. at is the current time.
func (s *Store) RecordAttacks(ctx context.Context, hits []model.AttackHit, trusted []string, at time.Time) error {
	if len(hits) == 0 && len(trusted) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	seen := formatTime(at)
	for _, ip := range trusted {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO attackers (ip, first_at, last_at, hits, trusted) VALUES (?, ?, ?, 0, 1)
			 ON CONFLICT (ip) DO UPDATE SET trusted = 1, hits = 0, last_at = excluded.last_at`, ip, seen, seen); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM attacker_kinds WHERE ip = ?`, ip); err != nil {
			return err
		}
	}
	for _, h := range hits {
		first, last := formatTime(h.First), formatTime(h.Last)
		res, err := tx.ExecContext(ctx,
			`INSERT INTO attackers (ip, first_at, last_at, hits) VALUES (?, ?, ?, ?)
			 ON CONFLICT (ip) DO UPDATE SET hits = hits + excluded.hits,
				first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at)
			 WHERE trusted = 0`, h.IP, first, last, h.Count)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			continue
		}

		var stored string
		err = tx.QueryRowContext(ctx, `SELECT samples FROM attacker_kinds WHERE ip = ? AND kind = ?`, h.IP, h.Kind).Scan(&stored)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var samples []model.AttackSample
		if stored != "" {
			// Unreadable evidence is replaced by the new lines rather than failing the batch.
			_ = json.Unmarshal([]byte(stored), &samples)
		}
		samples = append(samples, h.Samples...)
		if len(samples) > maxAttackSamples {
			samples = samples[len(samples)-maxAttackSamples:]
		}
		raw, err := json.Marshal(samples)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO attacker_kinds (ip, kind, hits, first_at, last_at, samples) VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT (ip, kind) DO UPDATE SET hits = hits + excluded.hits,
				first_at = min(first_at, excluded.first_at), last_at = max(last_at, excluded.last_at),
				samples = excluded.samples`, h.IP, h.Kind, h.Count, first, last, string(raw)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO attack_daily (day, kind, hits) VALUES (?, ?, ?)
			 ON CONFLICT (day, kind) DO UPDATE SET hits = hits + excluded.hits`, h.Day, h.Kind, h.Count); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneAttacks forgets sources not seen since before, and daily totals older than beforeDay ("2006-01-02").
func (s *Store) PruneAttacks(ctx context.Context, before time.Time, beforeDay string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM attackers WHERE last_at < ?`, formatTime(before)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM attack_daily WHERE day < ?`, beforeDay); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearAttacks forgets every recorded source, the owner's own addresses included.
func (s *Store) ClearAttacks(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{`DELETE FROM attackers`, `DELETE FROM attack_daily`} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AttackFilter narrows ListAttackers; empty Kind and Country match everything.
type AttackFilter struct {
	Kind    string
	Country string
	Limit   int
	Offset  int
}

const attackerColumns = `ip, first_at, last_at, hits, whois_at, whois_error, country, network, net_range, abuse_email, registry`

func scanAttacker(row interface{ Scan(...any) error }) (model.Attacker, error) {
	var a model.Attacker
	var first, last, whoisAt string
	err := row.Scan(&a.IP, &first, &last, &a.Hits, &whoisAt, &a.LookupError,
		&a.Country, &a.Network, &a.NetRange, &a.AbuseEmail, &a.Registry)
	if err != nil {
		return a, err
	}
	if a.FirstAt, err = parseTime(first); err != nil {
		return a, err
	}
	if a.LastAt, err = parseTime(last); err != nil {
		return a, err
	}
	if whoisAt != "" {
		t, err := parseTime(whoisAt)
		if err != nil {
			return a, err
		}
		a.LookedUpAt = &t
	}
	return a, nil
}

func (s *Store) attackerKinds(ctx context.Context, ip string) ([]model.AttackerKind, error) {
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT kind, hits, first_at, last_at, samples FROM attacker_kinds WHERE ip = ? ORDER BY hits DESC, kind`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AttackerKind
	for rows.Next() {
		var k model.AttackerKind
		var first, last, samples string
		if err := rows.Scan(&k.Kind, &k.Hits, &first, &last, &samples); err != nil {
			return nil, err
		}
		if k.FirstAt, err = parseTime(first); err != nil {
			return nil, err
		}
		if k.LastAt, err = parseTime(last); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(samples), &k.Samples)
		out = append(out, k)
	}
	return out, rows.Err()
}

// ListAttackers returns one page of sources, most recently seen first, and how many match in all.
func (s *Store) ListAttackers(ctx context.Context, f AttackFilter) (list []model.Attacker, total int64, err error) {
	if f.Limit <= 0 || f.Offset < 0 {
		return nil, 0, fmt.Errorf("%w: attack page %d+%d", ErrInvalid, f.Offset, f.Limit)
	}
	where, args := visibleAttackers, []any{}
	if f.Kind != "" {
		where += ` AND EXISTS (SELECT 1 FROM attacker_kinds k WHERE k.ip = attackers.ip AND k.kind = ?)`
		args = append(args, f.Kind)
	}
	if f.Country != "" {
		where += ` AND country = ? AND whois_at != '' AND whois_error = ''`
		args = append(args, f.Country)
	}
	if err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM attackers WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT `+attackerColumns+` FROM attackers WHERE `+where+` ORDER BY last_at DESC, ip LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	for rows.Next() {
		a, err := scanAttacker(rows)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		list = append(list, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, 0, err
	}
	for i := range list {
		if list[i].Kinds, err = s.attackerKinds(ctx, list[i].IP); err != nil {
			return nil, 0, err
		}
	}
	return list, total, nil
}

// GetAttacker returns ErrNotFound for an address with nothing recorded, the owner's own included.
func (s *Store) GetAttacker(ctx context.Context, ip string) (model.Attacker, error) {
	a, err := scanAttacker(s.rdb.QueryRowContext(ctx,
		`SELECT `+attackerColumns+` FROM attackers WHERE ip = ? AND `+visibleAttackers, ip))
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	a.Kinds, err = s.attackerKinds(ctx, ip)
	return a, err
}

// AttackersToLookUp lists the busiest sources whose network is not known yet. A source whose
// lookup failed is offered again only when that failure is older than retryBefore.
func (s *Store) AttackersToLookUp(ctx context.Context, limit int, retryBefore time.Time) ([]string, error) {
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT ip FROM attackers WHERE `+visibleAttackers+`
		 AND (whois_at = '' OR (whois_error != '' AND whois_at < ?)) ORDER BY hits DESC, ip LIMIT ?`,
		formatTime(retryBefore), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// SetAttackerWhois stores a lookup's outcome; a non-empty failure keeps whatever was known before.
func (s *Store) SetAttackerWhois(ctx context.Context, ip string, w model.Whois, failure string, when time.Time) error {
	at := formatTime(when)
	if failure != "" {
		_, err := s.db.ExecContext(ctx, `UPDATE attackers SET whois_at = ?, whois_error = ? WHERE ip = ?`, at, failure, ip)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE attackers SET whois_at = ?, whois_error = '', country = ?, network = ?, net_range = ?, abuse_email = ?, registry = ?
		 WHERE ip = ?`, at, w.Country, w.Network, w.NetRange, w.AbuseEmail, w.Registry, ip)
	return err
}

const (
	attackTopCountries = 12
	attackTopNetworks  = 10
)

// AttackSummary aggregates the visible sources; Daily covers sinceDay ("2006-01-02") onwards.
func (s *Store) AttackSummary(ctx context.Context, sinceDay string) (model.AttackSummary, error) {
	var sum model.AttackSummary
	// One read transaction, so the totals and the breakdowns describe the same moment.
	tx, err := s.rdb.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return sum, err
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(hits), 0),
			COALESCE(SUM(whois_at != '' AND whois_error = ''), 0), COALESCE(SUM(whois_at = ''), 0)
		 FROM attackers WHERE `+visibleAttackers).Scan(&sum.Sources, &sum.Hits, &sum.LookedUp, &sum.Pending)
	if err != nil {
		return sum, err
	}

	each := func(query string, args []any, scan func(*sql.Rows) error) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			if err := scan(rows); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	err = each(`SELECT kind, SUM(hits), COUNT(*) FROM attacker_kinds GROUP BY kind ORDER BY SUM(hits) DESC, kind`, nil,
		func(r *sql.Rows) error {
			var k model.AttackKindTotal
			if err := r.Scan(&k.Kind, &k.Hits, &k.Sources); err != nil {
				return err
			}
			sum.Kinds = append(sum.Kinds, k)
			return nil
		})
	if err != nil {
		return sum, err
	}
	known := ` FROM attackers WHERE ` + visibleAttackers + ` AND whois_at != '' AND whois_error = ''`
	err = each(`SELECT country, COUNT(*), SUM(hits)`+known+` GROUP BY country ORDER BY COUNT(*) DESC, SUM(hits) DESC, country LIMIT ?`,
		[]any{attackTopCountries}, func(r *sql.Rows) error {
			var o model.AttackOrigin
			if err := r.Scan(&o.Country, &o.Sources, &o.Hits); err != nil {
				return err
			}
			sum.Countries = append(sum.Countries, o)
			return nil
		})
	if err != nil {
		return sum, err
	}
	err = each(`SELECT network, country, abuse_email, COUNT(*), SUM(hits)`+known+`
		 GROUP BY network, country, abuse_email ORDER BY SUM(hits) DESC, network LIMIT ?`,
		[]any{attackTopNetworks}, func(r *sql.Rows) error {
			var n model.AttackNetwork
			if err := r.Scan(&n.Network, &n.Country, &n.AbuseEmail, &n.Sources, &n.Hits); err != nil {
				return err
			}
			sum.Networks = append(sum.Networks, n)
			return nil
		})
	if err != nil {
		return sum, err
	}
	err = each(`SELECT day, kind, hits FROM attack_daily WHERE day >= ? ORDER BY day, kind`, []any{sinceDay},
		func(r *sql.Rows) error {
			var d model.AttackDay
			if err := r.Scan(&d.Day, &d.Kind, &d.Hits); err != nil {
				return err
			}
			sum.Daily = append(sum.Daily, d)
			return nil
		})
	return sum, err
}
