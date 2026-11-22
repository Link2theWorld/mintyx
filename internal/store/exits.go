package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Link2theWorld/mintyx/internal/model"
)

// exitJSON is the stored params column; explicit tags keep the format stable if the model changes.
type exitJSON struct {
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Secret       string            `json:"secret"`
	Username     string            `json:"username,omitempty"`
	Method       string            `json:"method,omitempty"`
	Flow         string            `json:"flow,omitempty"`
	Encryption   string            `json:"encryption,omitempty"`
	Transport    exitTransportJSON `json:"transport"`
	TLS          *exitTLSJSON      `json:"tls,omitempty"`
	Reality      *exitRealityJSON  `json:"reality,omitempty"`
	ObfsPassword string            `json:"obfs_password,omitempty"`
}

type exitTransportJSON struct {
	Network     string `json:"network,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	Mode        string `json:"mode,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Authority   string `json:"authority,omitempty"`
	MultiMode   bool   `json:"multi_mode,omitempty"`
}

type exitTLSJSON struct {
	ServerName  string   `json:"server_name,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	PinSHA256   string   `json:"pin_sha256,omitempty"`
	VerifyName  string   `json:"verify_name,omitempty"`
}

type exitRealityJSON struct {
	ServerName    string `json:"server_name"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	PublicKey     string `json:"public_key"`
	ShortID       string `json:"short_id,omitempty"`
	SpiderX       string `json:"spider_x,omitempty"`
	MLDSA65Verify string `json:"mldsa65_verify,omitempty"`
}

func encodeExitParams(p model.ExitParams) (string, error) {
	if !p.Protocol.Valid() {
		return "", fmt.Errorf("%w: exit protocol %q", ErrInvalid, p.Protocol)
	}
	t := p.Transport
	j := exitJSON{
		Host: p.Host, Port: p.Port, Secret: p.Secret, Username: p.Username, Method: p.Method, Flow: p.Flow,
		Encryption: p.Encryption, ObfsPassword: p.ObfsPassword,
		Transport: exitTransportJSON{Network: string(t.Network), Path: t.Path, Host: t.Host, Mode: t.Mode,
			ServiceName: t.ServiceName, Authority: t.Authority, MultiMode: t.MultiMode},
	}
	if p.TLS != nil {
		j.TLS = &exitTLSJSON{ServerName: p.TLS.ServerName, Fingerprint: p.TLS.Fingerprint, ALPN: slices.Clone(p.TLS.ALPN),
			PinSHA256: p.TLS.PinSHA256, VerifyName: p.TLS.VerifyName}
	}
	if r := p.Reality; r != nil {
		j.Reality = &exitRealityJSON{ServerName: r.ServerName, Fingerprint: r.Fingerprint, PublicKey: r.PublicKey,
			ShortID: r.ShortID, SpiderX: r.SpiderX, MLDSA65Verify: r.MLDSA65Verify}
	}
	b, err := json.Marshal(j)
	return string(b), err
}

func decodeExitParams(protocol, raw string) (model.ExitParams, error) {
	var j exitJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return model.ExitParams{}, fmt.Errorf("store: exit params: %w", err)
	}
	t := j.Transport
	p := model.ExitParams{
		Protocol: model.ExitProtocol(protocol), Host: j.Host, Port: j.Port, Secret: j.Secret, Username: j.Username,
		Method: j.Method, Flow: j.Flow, Encryption: j.Encryption, ObfsPassword: j.ObfsPassword,
		Transport: model.ExitTransport{Network: model.ExitNetwork(t.Network), Path: t.Path, Host: t.Host, Mode: t.Mode,
			ServiceName: t.ServiceName, Authority: t.Authority, MultiMode: t.MultiMode},
	}
	if j.TLS != nil {
		p.TLS = &model.ExitTLS{ServerName: j.TLS.ServerName, Fingerprint: j.TLS.Fingerprint, ALPN: j.TLS.ALPN,
			PinSHA256: j.TLS.PinSHA256, VerifyName: j.TLS.VerifyName}
	}
	if r := j.Reality; r != nil {
		p.Reality = &model.ExitReality{ServerName: r.ServerName, Fingerprint: r.Fingerprint, PublicKey: r.PublicKey,
			ShortID: r.ShortID, SpiderX: r.SpiderX, MLDSA65Verify: r.MLDSA65Verify}
	}
	return p, nil
}

func nullableID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *Store) CreateExit(ctx context.Context, e *model.Exit) error {
	params, err := encodeExitParams(e.Params)
	if err != nil {
		return err
	}
	created := now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO exits (name, region, protocol, params, next_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		e.Name, e.Region, string(e.Params.Protocol), params, nullableID(e.NextID), formatTime(created))
	if err != nil {
		return mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	e.ID, e.CreatedAt = id, created
	return nil
}

// UpdateExit rewrites name, region and params. NextID belongs to SetRouting.
func (s *Store) UpdateExit(ctx context.Context, e *model.Exit) error {
	params, err := encodeExitParams(e.Params)
	if err != nil {
		return err
	}
	return expectOneRow(s.db.ExecContext(ctx,
		`UPDATE exits SET name = ?, region = ?, protocol = ?, params = ? WHERE id = ?`,
		e.Name, e.Region, string(e.Params.Protocol), params, e.ID))
}

// DeleteExit removes the exit; lines and exits that pointed at it go straight out instead.
func (s *Store) DeleteExit(ctx context.Context, id int64) error {
	return expectOneRow(s.db.ExecContext(ctx, `DELETE FROM exits WHERE id = ?`, id))
}

const exitCols = `id, name, region, protocol, params, next_id, created_at`

func scanExit(row interface{ Scan(...any) error }) (model.Exit, error) {
	var e model.Exit
	var protocol, params, created string
	var next sql.NullInt64
	if err := row.Scan(&e.ID, &e.Name, &e.Region, &protocol, &params, &next, &created); err != nil {
		return model.Exit{}, err
	}
	e.NextID = next.Int64
	var err error
	if e.CreatedAt, err = parseTime(created); err != nil {
		return model.Exit{}, err
	}
	if e.Params, err = decodeExitParams(protocol, params); err != nil {
		return model.Exit{}, err
	}
	return e, nil
}

func (s *Store) GetExit(ctx context.Context, id int64) (model.Exit, error) {
	e, err := scanExit(s.rdb.QueryRowContext(ctx, `SELECT `+exitCols+` FROM exits WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Exit{}, ErrNotFound
	}
	return e, err
}

func (s *Store) ListExits(ctx context.Context) ([]model.Exit, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+exitCols+` FROM exits ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Exit
	for rows.Next() {
		e, err := scanExit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetRouting changes where lines and exits send their traffic, all in one transaction: lineExit
// maps a line to its first exit and exitNext an exit to its next one, 0 meaning the internet.
// An unknown line or exit id fails the whole change with ErrNotFound.
func (s *Store) SetRouting(ctx context.Context, lineExit, exitNext map[int64]int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, k := range sortedKeys(lineExit) {
		if err := expectOneRow(tx.ExecContext(ctx, `UPDATE lines SET exit_id = ? WHERE id = ?`, nullableID(lineExit[k]), k)); err != nil {
			return err
		}
	}
	for _, k := range sortedKeys(exitNext) {
		if err := expectOneRow(tx.ExecContext(ctx, `UPDATE exits SET next_id = ? WHERE id = ?`, nullableID(exitNext[k]), k)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func sortedKeys(m map[int64]int64) []int64 {
	keys := make([]int64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
