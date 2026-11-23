package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

func parseNullableTime(v sql.NullString) (*time.Time, error) {
	if !v.Valid {
		return nil, nil
	}
	t, err := parseTime(v.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) CreateClient(ctx context.Context, c *model.Client) error {
	if !validReason(c.Disabled) {
		return fmt.Errorf("%w: disabled reason %q", ErrInvalid, c.Disabled)
	}
	created := now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO clients (name, secret, sub_token, disabled, quota_bytes, expires_at, quota_reset_day, cycle_start,
		 used_up, used_down, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Name, c.Secret, c.SubToken, string(c.Disabled), c.QuotaBytes, nullableTime(c.ExpiresAt), c.QuotaResetDay,
		nullableTime(c.CycleStart), c.UsedUp, c.UsedDown, formatTime(created))
	if err != nil {
		return mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	c.ID, c.CreatedAt = id, created
	return nil
}

// UpdateClient writes the admin-editable fields only. Usage counters belong to
// AddTraffic/ResetTraffic/StartCycle, Disabled to SetClientDisabled and the cycle anchor to
// StartCycle/UpdateClientWithCycle: the row is read before the update is written, so writing an
// anchor copied from it could overwrite a newer cycle the quota loop started meanwhile.
func (s *Store) UpdateClient(ctx context.Context, c *model.Client) error {
	return s.updateClient(ctx, c, false)
}

// UpdateClientWithCycle is UpdateClient for a change that deliberately reanchors the monthly
// cycle: choosing another reset day, or moving midnight when the time zone changes.
func (s *Store) UpdateClientWithCycle(ctx context.Context, c *model.Client) error {
	return s.updateClient(ctx, c, true)
}

func (s *Store) updateClient(ctx context.Context, c *model.Client, withCycle bool) error {
	set := `name = ?, secret = ?, sub_token = ?, quota_bytes = ?, expires_at = ?, quota_reset_day = ?`
	args := []any{c.Name, c.Secret, c.SubToken, c.QuotaBytes, nullableTime(c.ExpiresAt), c.QuotaResetDay}
	if withCycle {
		set += `, cycle_start = ?`
		args = append(args, nullableTime(c.CycleStart))
	}
	args = append(args, c.ID)
	return expectOneRow(s.db.ExecContext(ctx, `UPDATE clients SET `+set+` WHERE id = ?`, args...))
}

func (s *Store) DeleteClient(ctx context.Context, id int64) error {
	return expectOneRow(s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id))
}

func validReason(r model.DisabledReason) bool {
	switch r {
	case model.NotDisabled, model.DisabledManual, model.DisabledQuota, model.DisabledExpired:
		return true
	}
	return false
}

func (s *Store) SetClientDisabled(ctx context.Context, id int64, reason model.DisabledReason) error {
	if !validReason(reason) {
		return fmt.Errorf("%w: disabled reason %q", ErrInvalid, reason)
	}
	return expectOneRow(s.db.ExecContext(ctx, `UPDATE clients SET disabled = ? WHERE id = ?`, string(reason), id))
}

// AddTraffic increments counters in one transaction; ids of since-deleted clients are skipped.
func (s *Store) AddTraffic(ctx context.Context, deltas map[int64]model.Traffic) error {
	if len(deltas) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `UPDATE clients SET used_up = used_up + ?, used_down = used_down + ? WHERE id = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for id, d := range deltas {
		if _, err := stmt.ExecContext(ctx, d.Up, d.Down, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ResetTraffic(ctx context.Context, id int64) error {
	return expectOneRow(s.db.ExecContext(ctx, `UPDATE clients SET used_up = 0, used_down = 0 WHERE id = ?`, id))
}

// StartCycle moves the client into the monthly cycle that began at start, zeroing its usage
// when zeroUsage is set. It applies only if the stored cycle is older (or unset), so running it
// again for the same cycle, after a restart or a missed tick, does nothing; started reports
// whether it applied.
func (s *Store) StartCycle(ctx context.Context, id int64, start time.Time, zeroUsage bool) (started bool, err error) {
	query := `UPDATE clients SET cycle_start = ? WHERE id = ? AND (cycle_start IS NULL OR cycle_start < ?)`
	if zeroUsage {
		query = `UPDATE clients SET cycle_start = ?, used_up = 0, used_down = 0
		 WHERE id = ? AND (cycle_start IS NULL OR cycle_start < ?)`
	}
	at := formatTime(start)
	res, err := s.db.ExecContext(ctx, query, at, id, at)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

const clientCols = `id, name, secret, sub_token, disabled, quota_bytes, expires_at, quota_reset_day, cycle_start,
	used_up, used_down, created_at`

func scanClient(row interface{ Scan(...any) error }) (model.Client, error) {
	var c model.Client
	var disabled, created string
	var expires, cycle sql.NullString
	if err := row.Scan(&c.ID, &c.Name, &c.Secret, &c.SubToken, &disabled, &c.QuotaBytes, &expires, &c.QuotaResetDay, &cycle,
		&c.UsedUp, &c.UsedDown, &created); err != nil {
		return model.Client{}, err
	}
	c.Disabled = model.DisabledReason(disabled)
	var err error
	if c.CreatedAt, err = parseTime(created); err != nil {
		return model.Client{}, err
	}
	if c.ExpiresAt, err = parseNullableTime(expires); err != nil {
		return model.Client{}, err
	}
	if c.CycleStart, err = parseNullableTime(cycle); err != nil {
		return model.Client{}, err
	}
	return c, nil
}

func (s *Store) getClientWhere(ctx context.Context, where string, arg any) (model.Client, error) {
	c, err := scanClient(s.rdb.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Client{}, ErrNotFound
	}
	return c, err
}

func (s *Store) GetClient(ctx context.Context, id int64) (model.Client, error) {
	return s.getClientWhere(ctx, `id = ?`, id)
}

func (s *Store) GetClientBySubToken(ctx context.Context, token string) (model.Client, error) {
	return s.getClientWhere(ctx, `sub_token = ?`, token)
}

func (s *Store) ListClients(ctx context.Context) ([]model.Client, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+clientCols+` FROM clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
