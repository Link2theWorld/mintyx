// Package store persists lines, clients, the audit log and settings in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
	ErrInvalid  = errors.New("store: invalid value")
	// ErrSchemaTooNew means a newer build migrated this database; migrations are forward-only.
	ErrSchemaTooNew = errors.New("store: database schema is newer than this build")
)

// ConflictError reports which unique field collided, e.g. "port", "name", "secret", "sub_token".
type ConflictError struct {
	Field string
}

func (e *ConflictError) Error() string     { return "store: conflict on " + e.Field }
func (e *ConflictError) Is(err error) bool { return err == ErrConflict }

const busyTimeoutMillis = 5000

// Store keeps one writer connection so in-process writes queue in database/sql
// rather than spinning in SQLite's busy handler; WAL lets the reader pool run alongside.
type Store struct {
	db  *sql.DB
	rdb *sql.DB
}

func Open(path string) (*Store, error) {
	if strings.ContainsRune(path, '?') {
		return nil, fmt.Errorf("%w: database path %q contains '?'", ErrInvalid, path)
	}
	base := fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path, busyTimeoutMillis)
	// _txlock=immediate takes the write lock at BEGIN, so another process's writer
	// makes us wait out the busy timeout instead of failing a read-to-write upgrade.
	db, err := sql.Open("sqlite", base+"&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	if s.rdb, err = sql.Open("sqlite", base+"&_pragma=query_only(1)"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) Close() error { return errors.Join(s.rdb.Close(), s.db.Close()) }

// timeLayout is fixed-width so stored timestamps sort lexically and keep nanoseconds.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func formatTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func parseTime(s string) (time.Time, error) {
	t, err := time.ParseInLocation(timeLayout, s, time.UTC)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: bad timestamp %q: %w", s, err)
	}
	return t, nil
}

func now() time.Time { return time.Now().UTC().Round(0) }

// mapErr turns unique-constraint failures into ConflictError naming the column.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY) {
		field := "unknown"
		// Message form: "UNIQUE constraint failed: table.column (...)".
		if i := strings.LastIndex(se.Error(), "failed: "); i >= 0 {
			rest := strings.Fields(se.Error()[i+len("failed: "):])
			if len(rest) > 0 {
				col := strings.TrimSuffix(rest[0], ",")
				if j := strings.IndexByte(col, '.'); j >= 0 {
					col = col[j+1:]
				}
				field = col
			}
		}
		return &ConflictError{Field: field}
	}
	if errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY || se.Code() == sqlite3.SQLITE_CONSTRAINT_CHECK) {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return err
}

func expectOneRow(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
