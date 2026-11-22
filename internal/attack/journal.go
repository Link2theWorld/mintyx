package attack

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ErrNoJournal means this host has no systemd journal to read sshd's messages from.
var ErrNoJournal = errors.New("attack: no systemd journal on this host")

const (
	journalTimeout = 30 * time.Second
	maxJournalLine = 1 << 20
)

type journalRecord struct {
	Cursor string `json:"__CURSOR"`
	Micros string `json:"__REALTIME_TIMESTAMP"`
	// MESSAGE is a string, or an array of bytes when it is not valid UTF-8; those are skipped.
	Message json.RawMessage `json:"MESSAGE"`
}

// parseJournal reads `journalctl -o json` output, calling fn per message, and returns the last cursor seen.
func parseJournal(r io.Reader, fn func(at time.Time, msg string)) (cursor string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxJournalLine)
	for sc.Scan() {
		var rec journalRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if rec.Cursor != "" {
			cursor = rec.Cursor
		}
		var msg string
		micros, terr := strconv.ParseInt(rec.Micros, 10, 64)
		if terr != nil || json.Unmarshal(rec.Message, &msg) != nil {
			continue
		}
		fn(time.UnixMicro(micros).UTC(), msg)
	}
	return cursor, sc.Err()
}

// ReadSSHJournal feeds fn every sshd message logged after cursor, or within the last backlog when
// cursor is empty, and returns the cursor to continue from (the one given when nothing was new).
func ReadSSHJournal(ctx context.Context, cursor string, backlog time.Duration, fn func(at time.Time, msg string)) (string, error) {
	if runtime.GOOS != "linux" {
		return cursor, ErrNoJournal
	}
	bin, err := exec.LookPath("journalctl")
	if err != nil {
		return cursor, ErrNoJournal
	}
	// OpenSSH 9.8 moved the per-connection messages from sshd to sshd-session.
	args := []string{"--no-pager", "--quiet", "-o", "json", "--output-fields=MESSAGE", "-t", "sshd", "-t", "sshd-session"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, fmt.Sprintf("--since=-%ds", int(backlog.Seconds())))
	}
	ctx, cancel := context.WithTimeout(ctx, journalTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return cursor, err
	}
	if err := cmd.Start(); err != nil {
		return cursor, err
	}
	next, parseErr := parseJournal(out, fn)
	if next == "" {
		next = cursor
	}
	if err := cmd.Wait(); err != nil {
		return cursor, fmt.Errorf("attack: journalctl: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return next, parseErr
}
