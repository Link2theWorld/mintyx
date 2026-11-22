package store

import (
	"context"
	"fmt"
	"math"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// AppendAudit fills ID, and At when it is zero.
func (s *Store) AppendAudit(ctx context.Context, e *model.AuditEntry) error {
	if e.At.IsZero() {
		e.At = now()
	} else {
		e.At = e.At.UTC().Round(0)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (at, action, target, detail, remote_ip) VALUES (?, ?, ?, ?, ?)`,
		formatTime(e.At), e.Action, e.Target, e.Detail, e.RemoteIP)
	if err != nil {
		return err
	}
	e.ID, err = res.LastInsertId()
	return err
}

// ListAudit returns up to limit entries newest first, strictly older than beforeID
// (0 starts at the newest). Ordering by id, not At, keeps paging stable under clock skew.
func (s *Store) ListAudit(ctx context.Context, limit int, beforeID int64) ([]model.AuditEntry, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%w: audit limit %d", ErrInvalid, limit)
	}
	if beforeID <= 0 {
		beforeID = math.MaxInt64
	}
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT id, at, action, target, detail, remote_ip FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`,
		beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Action, &e.Target, &e.Detail, &e.RemoteIP); err != nil {
			return nil, err
		}
		if e.At, err = parseTime(at); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
