package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// The params column uses the exits' format: both are parsed share links of another server.

func (s *Store) CreateRemoteLine(ctx context.Context, r *model.RemoteLine) error {
	params, err := encodeExitParams(r.Params)
	if err != nil {
		return err
	}
	created := now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO remote_lines (client_id, name, protocol, params, created_at) VALUES (?, ?, ?, ?, ?)`,
		r.ClientID, r.Name, string(r.Params.Protocol), params, formatTime(created))
	if err != nil {
		return mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	r.ID, r.CreatedAt = id, created
	return nil
}

// UpdateRemoteLine rewrites the name and params of remote line r.ID, which must belong to r.ClientID.
func (s *Store) UpdateRemoteLine(ctx context.Context, r *model.RemoteLine) error {
	params, err := encodeExitParams(r.Params)
	if err != nil {
		return err
	}
	return expectOneRow(s.db.ExecContext(ctx,
		`UPDATE remote_lines SET name = ?, protocol = ?, params = ? WHERE id = ? AND client_id = ?`,
		r.Name, string(r.Params.Protocol), params, r.ID, r.ClientID))
}

func (s *Store) DeleteRemoteLine(ctx context.Context, clientID, id int64) error {
	return expectOneRow(s.db.ExecContext(ctx, `DELETE FROM remote_lines WHERE id = ? AND client_id = ?`, id, clientID))
}

const remoteLineCols = `id, client_id, name, protocol, params, created_at`

func scanRemoteLine(row interface{ Scan(...any) error }) (model.RemoteLine, error) {
	var r model.RemoteLine
	var protocol, params, created string
	if err := row.Scan(&r.ID, &r.ClientID, &r.Name, &protocol, &params, &created); err != nil {
		return model.RemoteLine{}, err
	}
	var err error
	if r.CreatedAt, err = parseTime(created); err != nil {
		return model.RemoteLine{}, err
	}
	if r.Params, err = decodeExitParams(protocol, params); err != nil {
		return model.RemoteLine{}, err
	}
	return r, nil
}

func (s *Store) GetRemoteLine(ctx context.Context, clientID, id int64) (model.RemoteLine, error) {
	r, err := scanRemoteLine(s.rdb.QueryRowContext(ctx,
		`SELECT `+remoteLineCols+` FROM remote_lines WHERE id = ? AND client_id = ?`, id, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return model.RemoteLine{}, ErrNotFound
	}
	return r, err
}

// ListRemoteLines returns the client's remote lines in the order they were added.
func (s *Store) ListRemoteLines(ctx context.Context, clientID int64) ([]model.RemoteLine, error) {
	rows, err := s.rdb.QueryContext(ctx,
		`SELECT `+remoteLineCols+` FROM remote_lines WHERE client_id = ? ORDER BY id`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RemoteLine
	for rows.Next() {
		r, err := scanRemoteLine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
