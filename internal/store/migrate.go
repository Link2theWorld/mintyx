package store

import (
	"context"
	"fmt"
)

// migrations are append-only: entry i moves the schema from version i to i+1.
var migrations = []string{
	`
CREATE TABLE lines (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL,
	protocol   TEXT    NOT NULL,
	port       INTEGER NOT NULL UNIQUE,
	enabled    INTEGER NOT NULL,
	host       TEXT    NOT NULL,
	params     TEXT    NOT NULL,
	created_at TEXT    NOT NULL
);
CREATE TABLE clients (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT    NOT NULL UNIQUE,
	secret      TEXT    NOT NULL UNIQUE,
	sub_token   TEXT    NOT NULL UNIQUE,
	disabled    TEXT    NOT NULL DEFAULT '',
	quota_bytes INTEGER NOT NULL DEFAULT 0,
	expires_at  TEXT,
	used_up     INTEGER NOT NULL DEFAULT 0,
	used_down   INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT    NOT NULL
);
CREATE TABLE audit_log (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	at        TEXT NOT NULL,
	action    TEXT NOT NULL,
	target    TEXT NOT NULL,
	detail    TEXT NOT NULL,
	remote_ip TEXT NOT NULL
);
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`,
	`
CREATE TABLE attackers (
	ip          TEXT PRIMARY KEY,
	first_at    TEXT    NOT NULL,
	last_at     TEXT    NOT NULL,
	hits        INTEGER NOT NULL,
	trusted     INTEGER NOT NULL DEFAULT 0,
	whois_at    TEXT    NOT NULL DEFAULT '',
	whois_error TEXT    NOT NULL DEFAULT '',
	country     TEXT    NOT NULL DEFAULT '',
	network     TEXT    NOT NULL DEFAULT '',
	net_range   TEXT    NOT NULL DEFAULT '',
	abuse_email TEXT    NOT NULL DEFAULT '',
	registry    TEXT    NOT NULL DEFAULT ''
) WITHOUT ROWID;
CREATE INDEX attackers_last_at ON attackers (last_at);
CREATE TABLE attacker_kinds (
	ip       TEXT    NOT NULL REFERENCES attackers (ip) ON DELETE CASCADE,
	kind     TEXT    NOT NULL,
	hits     INTEGER NOT NULL,
	first_at TEXT    NOT NULL,
	last_at  TEXT    NOT NULL,
	samples  TEXT    NOT NULL,
	PRIMARY KEY (ip, kind)
) WITHOUT ROWID;
CREATE TABLE attack_daily (
	day  TEXT    NOT NULL,
	kind TEXT    NOT NULL,
	hits INTEGER NOT NULL,
	PRIMARY KEY (day, kind)
) WITHOUT ROWID;
`,
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: create schema_version: %w", err)
	}
	for {
		done, err := s.migrateOne(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// migrateOne applies the next pending migration, re-reading the version inside
// the write transaction so two processes opening the same file cannot both apply it.
func (s *Store) migrateOne(ctx context.Context) (done bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("store: migrate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var version, rows int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0), COUNT(*) FROM schema_version`).Scan(&version, &rows); err != nil {
		return false, fmt.Errorf("store: read schema version: %w", err)
	}
	switch {
	case version > len(migrations):
		return false, fmt.Errorf("%w: database at %d, build knows %d", ErrSchemaTooNew, version, len(migrations))
	case version == len(migrations):
		return true, nil
	}
	if _, err := tx.ExecContext(ctx, migrations[version]); err != nil {
		return false, fmt.Errorf("store: migration %d: %w", version+1, err)
	}
	if rows == 0 {
		_, err = tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, version+1)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, version+1)
	}
	if err != nil {
		return false, fmt.Errorf("store: record schema version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: commit migration %d: %w", version+1, err)
	}
	return false, nil
}
