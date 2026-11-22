package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// The params column holds one of these JSON shapes; explicit tags keep the stored
// format stable if model field names change.
type realityJSON struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	ServerName string `json:"server_name"`
	Target     string `json:"target"`
}

type xhttpJSON struct {
	Path     string `json:"path"`
	Domain   string `json:"domain"`
	Security string `json:"security"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type hysteria2JSON struct {
	Domain       string `json:"domain"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ObfsPassword string `json:"obfs_password"`
}

func encodeParams(l *model.Line) (string, error) {
	set := 0
	for _, p := range []bool{l.Reality != nil, l.XHTTP != nil, l.Hysteria2 != nil} {
		if p {
			set++
		}
	}
	if set != 1 {
		return "", fmt.Errorf("%w: line must carry exactly one params block, has %d", ErrInvalid, set)
	}
	var v any
	switch {
	case l.Protocol == model.VLESSReality && l.Reality != nil:
		r := l.Reality
		v = realityJSON{r.PrivateKey, r.PublicKey, r.ShortID, r.ServerName, r.Target}
	case l.Protocol == model.VLESSXHTTP && l.XHTTP != nil:
		x := l.XHTTP
		v = xhttpJSON{x.Path, x.Domain, string(x.Security), x.CertFile, x.KeyFile}
	case l.Protocol == model.Hysteria2 && l.Hysteria2 != nil:
		h := l.Hysteria2
		v = hysteria2JSON{h.Domain, h.CertFile, h.KeyFile, h.ObfsPassword}
	default:
		return "", fmt.Errorf("%w: params do not match protocol %q", ErrInvalid, l.Protocol)
	}
	b, err := json.Marshal(v)
	return string(b), err
}

func decodeParams(l *model.Line, raw string) error {
	var err error
	switch l.Protocol {
	case model.VLESSReality:
		var r realityJSON
		if err = json.Unmarshal([]byte(raw), &r); err == nil {
			l.Reality = &model.RealityParams{PrivateKey: r.PrivateKey, PublicKey: r.PublicKey, ShortID: r.ShortID, ServerName: r.ServerName, Target: r.Target}
		}
	case model.VLESSXHTTP:
		var x xhttpJSON
		if err = json.Unmarshal([]byte(raw), &x); err == nil {
			l.XHTTP = &model.XHTTPParams{Path: x.Path, Domain: x.Domain, Security: model.XHTTPSecurity(x.Security), CertFile: x.CertFile, KeyFile: x.KeyFile}
		}
	case model.Hysteria2:
		var h hysteria2JSON
		if err = json.Unmarshal([]byte(raw), &h); err == nil {
			l.Hysteria2 = &model.Hysteria2Params{Domain: h.Domain, CertFile: h.CertFile, KeyFile: h.KeyFile, ObfsPassword: h.ObfsPassword}
		}
	default:
		return fmt.Errorf("store: line %d has unknown protocol %q", l.ID, l.Protocol)
	}
	if err != nil {
		return fmt.Errorf("store: line %d params: %w", l.ID, err)
	}
	return nil
}

func (s *Store) CreateLine(ctx context.Context, l *model.Line) error {
	params, err := encodeParams(l)
	if err != nil {
		return err
	}
	created := now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO lines (name, protocol, port, enabled, host, params, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.Name, string(l.Protocol), l.Port, l.Enabled, l.Host, params, formatTime(created))
	if err != nil {
		return mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	l.ID, l.CreatedAt = id, created
	return nil
}

// UpdateLine rewrites every field except ID, CreatedAt and ExitID (see SetRouting).
func (s *Store) UpdateLine(ctx context.Context, l *model.Line) error {
	params, err := encodeParams(l)
	if err != nil {
		return err
	}
	return expectOneRow(s.db.ExecContext(ctx,
		`UPDATE lines SET name = ?, protocol = ?, port = ?, enabled = ?, host = ?, params = ? WHERE id = ?`,
		l.Name, string(l.Protocol), l.Port, l.Enabled, l.Host, params, l.ID))
}

func (s *Store) DeleteLine(ctx context.Context, id int64) error {
	return expectOneRow(s.db.ExecContext(ctx, `DELETE FROM lines WHERE id = ?`, id))
}

// lineCols includes exit_id, which only SetRouting writes; UpdateLine leaves it alone.
const lineCols = `id, name, protocol, port, enabled, host, params, created_at, exit_id`

func scanLine(row interface{ Scan(...any) error }) (model.Line, error) {
	var l model.Line
	var proto, params, created string
	var exitID sql.NullInt64
	if err := row.Scan(&l.ID, &l.Name, &proto, &l.Port, &l.Enabled, &l.Host, &params, &created, &exitID); err != nil {
		return model.Line{}, err
	}
	l.ExitID = exitID.Int64
	l.Protocol = model.Protocol(proto)
	var err error
	if l.CreatedAt, err = parseTime(created); err != nil {
		return model.Line{}, err
	}
	if err := decodeParams(&l, params); err != nil {
		return model.Line{}, err
	}
	return l, nil
}

func (s *Store) GetLine(ctx context.Context, id int64) (model.Line, error) {
	l, err := scanLine(s.rdb.QueryRowContext(ctx, `SELECT `+lineCols+` FROM lines WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Line{}, ErrNotFound
	}
	return l, err
}

func (s *Store) ListLines(ctx context.Context) ([]model.Line, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+lineCols+` FROM lines ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Line
	for rows.Next() {
		l, err := scanLine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
