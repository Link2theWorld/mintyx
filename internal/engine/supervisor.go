package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// ErrAlreadyStarted is returned by Start when the supervisor is already running Xray.
var ErrAlreadyStarted = errors.New("engine: supervisor already started")

// SupervisorOptions tunes the supervisor; zero values take the defaults below.
type SupervisorOptions struct {
	// StopTimeout is how long Stop waits after SIGTERM before SIGKILL. Default 5s.
	StopTimeout time.Duration
	// BackoffMin and BackoffMax bound the delay before restarting a crashed process. Default 500ms and 30s.
	BackoffMin time.Duration
	BackoffMax time.Duration
	// LogLines is how many stdout/stderr lines Logs keeps. Default 500.
	LogLines int
	// Env, when non-nil, replaces the child's environment.
	Env []string
	// OnLine, when set, is shown every line Xray prints and says whether Logs should keep it.
	// It runs on the goroutine copying Xray's output, so it must not block.
	OnLine func(line string) (keep bool)
}

// Status is a snapshot of the supervised process.
type Status struct {
	Running   bool
	PID       int
	StartedAt time.Time
	// LastExit is the error text of the most recent exit or failed start; empty if none yet.
	LastExit string
	// Restarts counts automatic restarts after unexpected exits; Apply does not count.
	Restarts int
}

// Supervisor owns the Xray child process: it restarts it after crashes until Stop is called.
type Supervisor struct {
	bin, configPath string
	opt             SupervisorOptions
	logs            *ringLog

	// ctl serialises Start, Stop and Apply so the loop's lifetime is well defined for each.
	ctl     sync.Mutex
	stop    chan struct{}
	restart chan chan error
	done    chan struct{}

	mu     sync.Mutex
	status Status
}

// NewSupervisor runs binPath as `run -c configPath`. It does not start anything until Start.
func NewSupervisor(binPath, configPath string, opt SupervisorOptions) *Supervisor {
	if opt.StopTimeout <= 0 {
		opt.StopTimeout = 5 * time.Second
	}
	if opt.BackoffMin <= 0 {
		opt.BackoffMin = 500 * time.Millisecond
	}
	if opt.BackoffMax < opt.BackoffMin {
		opt.BackoffMax = max(30*time.Second, opt.BackoffMin)
	}
	if opt.LogLines <= 0 {
		opt.LogLines = 500
	}
	return &Supervisor{bin: binPath, configPath: configPath, opt: opt, logs: newRingLog(opt.LogLines)}
}

// Start launches Xray and the restart loop. It returns the error if the first launch fails.
func (s *Supervisor) Start() error {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	if s.done != nil {
		return ErrAlreadyStarted
	}
	p, err := s.spawn()
	if err != nil {
		return err
	}
	s.stop = make(chan struct{})
	s.restart = make(chan chan error)
	s.done = make(chan struct{})
	go s.loop(p, s.stop, s.restart, s.done)
	return nil
}

// Stop terminates Xray (SIGTERM, then SIGKILL after StopTimeout) and ends the restart loop. Safe to call when stopped.
func (s *Supervisor) Stop() {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	if s.done == nil {
		return
	}
	close(s.stop)
	<-s.done
	s.stop, s.restart, s.done = nil, nil, nil
}

// Apply atomically replaces the config file and, if Xray is supervised, restarts it on the new config.
func (s *Supervisor) Apply(config []byte) error {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	if err := writeFileAtomic(s.configPath, config); err != nil {
		return err
	}
	if s.done == nil {
		return nil
	}
	reply := make(chan error)
	s.restart <- reply
	return <-reply
}

// Status returns a snapshot of the process state.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// Logs returns the most recent output lines, oldest first.
func (s *Supervisor) Logs() []string { return s.logs.lines() }

type proc struct {
	cmd     *exec.Cmd
	started time.Time
	exited  chan struct{}
	err     error // valid once exited is closed
}

func (s *Supervisor) spawn() (*proc, error) {
	cmd := exec.Command(s.bin, "run", "-c", s.configPath)
	cmd.Env = s.opt.Env
	cmd.Stdout = s.logs.writer(s.opt.OnLine)
	cmd.Stderr = s.logs.writer(s.opt.OnLine)
	// Bounds Wait if a grandchild inherited the pipes and keeps them open.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		s.recordExit(fmt.Sprintf("start: %v", err))
		return nil, fmt.Errorf("start %s: %w", s.bin, err)
	}
	p := &proc{cmd: cmd, started: time.Now(), exited: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.exited)
	}()
	s.mu.Lock()
	s.status.Running = true
	s.status.PID = cmd.Process.Pid
	s.status.StartedAt = p.started
	s.mu.Unlock()
	s.logs.add(fmt.Sprintf("[supervisor] started pid %d", cmd.Process.Pid))
	return p, nil
}

func (s *Supervisor) recordExit(text string) {
	s.mu.Lock()
	s.status.Running = false
	s.status.PID = 0
	s.status.LastExit = text
	s.mu.Unlock()
}

func exitText(err error) string {
	if err == nil {
		return "exited with status 0"
	}
	return err.Error()
}

// terminate signals p and waits for it to be reaped, so no zombie remains.
func (s *Supervisor) terminate(p *proc) {
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = p.cmd.Process.Kill()
	}
	timer := time.NewTimer(s.opt.StopTimeout)
	defer timer.Stop()
	select {
	case <-p.exited:
	case <-timer.C:
		s.logs.add(fmt.Sprintf("[supervisor] pid %d ignored SIGTERM for %s, killing", p.cmd.Process.Pid, s.opt.StopTimeout))
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
	s.recordExit(exitText(p.err))
}

func (s *Supervisor) loop(p *proc, stop <-chan struct{}, restart <-chan chan error, done chan<- struct{}) {
	defer close(done)
	backoff := s.opt.BackoffMin
	var retry <-chan time.Time
	var retryTimer *time.Timer
	cancelRetry := func() {
		if retryTimer != nil {
			retryTimer.Stop()
			retryTimer, retry = nil, nil
		}
	}
	scheduleRetry := func() {
		s.logs.add(fmt.Sprintf("[supervisor] restarting in %s", backoff))
		retryTimer = time.NewTimer(backoff)
		retry = retryTimer.C
		backoff = min(backoff*2, s.opt.BackoffMax)
	}
	for {
		var exited <-chan struct{}
		if p != nil {
			exited = p.exited
		}
		select {
		case <-stop:
			cancelRetry()
			if p != nil {
				s.terminate(p)
			}
			s.logs.add("[supervisor] stopped")
			return
		case reply := <-restart:
			cancelRetry()
			if p != nil {
				s.terminate(p)
			}
			backoff = s.opt.BackoffMin
			var err error
			p, err = s.spawn()
			if err != nil {
				scheduleRetry()
			}
			reply <- err
		case <-exited:
			text := exitText(p.err)
			s.recordExit(text)
			s.logs.add(fmt.Sprintf("[supervisor] pid %d exited unexpectedly: %s", p.cmd.Process.Pid, text))
			if time.Since(p.started) >= s.opt.BackoffMax {
				backoff = s.opt.BackoffMin
			}
			p = nil
			scheduleRetry()
		case <-retry:
			retryTimer, retry = nil, nil
			var err error
			p, err = s.spawn()
			if err != nil {
				s.logs.add(fmt.Sprintf("[supervisor] %v", err))
				scheduleRetry()
				continue
			}
			s.mu.Lock()
			s.status.Restarts++
			s.mu.Unlock()
		}
	}
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ringLog keeps the last N output lines across all writers.
type ringLog struct {
	mu   sync.Mutex
	buf  []string
	next int
	full bool
}

func newRingLog(n int) *ringLog { return &ringLog{buf: make([]string, n)} }

func (r *ringLog) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = line
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *ringLog) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]string(nil), r.buf[:r.next]...)
	}
	return append(append([]string(nil), r.buf[r.next:]...), r.buf[:r.next]...)
}

// writer returns an io.Writer that splits one stream into lines; each stream needs its own for partial lines.
func (r *ringLog) writer(onLine func(string) bool) *lineWriter {
	return &lineWriter{ring: r, onLine: onLine}
}

type lineWriter struct {
	ring    *ringLog
	onLine  func(string) bool
	partial []byte
}

func (w *lineWriter) emit(line string) {
	if w.onLine == nil || w.onLine(line) {
		w.ring.add(line)
	}
}

const maxLogLine = 4096

func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.partial = append(w.partial, p...)
			if len(w.partial) > maxLogLine {
				w.emit(string(w.partial))
				w.partial = w.partial[:0]
			}
			break
		}
		line := append(w.partial, p[:i]...)
		w.emit(string(bytes.TrimRight(line, "\r")))
		w.partial = w.partial[:0]
		p = p[i+1:]
	}
	return n, nil
}
