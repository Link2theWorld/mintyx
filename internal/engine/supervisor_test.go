package engine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func newFakeSupervisor(t *testing.T, mode string, opt SupervisorOptions) (*Supervisor, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt.Env = append(os.Environ(), fakeModeEnv+"="+mode, fakeMarkerEnv+"="+filepath.Join(dir, "marker"))
	if opt.BackoffMin == 0 {
		opt.BackoffMin = 10 * time.Millisecond
		opt.BackoffMax = 40 * time.Millisecond
	}
	if opt.StopTimeout == 0 {
		opt.StopTimeout = 2 * time.Second
	}
	s := NewSupervisor(os.Args[0], cfg, opt)
	t.Cleanup(s.Stop)
	return s, cfg
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func logsContain(s *Supervisor, substr string) bool {
	return slices.ContainsFunc(s.Logs(), func(l string) bool { return strings.Contains(l, substr) })
}

func processGone(pid int) bool {
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}

func TestSupervisorRestartsAfterCrash(t *testing.T) {
	s, _ := newFakeSupervisor(t, "crash-once", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "restart after crash", func() bool { st := s.Status(); return st.Restarts == 1 && st.Running })

	st := s.Status()
	if st.LastExit != "exit status 3" {
		t.Errorf("LastExit = %q, want %q", st.LastExit, "exit status 3")
	}
	if st.PID == 0 || st.StartedAt.IsZero() {
		t.Errorf("running status lacks pid/start time: %+v", st)
	}
	time.Sleep(100 * time.Millisecond)
	if got := s.Status(); got.Restarts != 1 || got.PID != st.PID {
		t.Errorf("healthy process was restarted again: %+v then %+v", st, got)
	}
}

func TestSupervisorStopEndsProcessWithoutRestart(t *testing.T) {
	before := runtime.NumGoroutine()
	s, _ := newFakeSupervisor(t, "serve", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "child output", func() bool { return logsContain(s, "config: first") })
	pid := s.Status().PID

	s.Stop()
	st := s.Status()
	if st.Running || st.PID != 0 {
		t.Errorf("status after Stop = %+v, want not running", st)
	}
	if st.LastExit != "exited with status 0" {
		t.Errorf("LastExit = %q, want graceful exit", st.LastExit)
	}
	if !processGone(pid) {
		t.Errorf("pid %d still exists (or is an unreaped zombie) after Stop", pid)
	}
	time.Sleep(100 * time.Millisecond)
	if got := s.Status(); got.Running || got.Restarts != 0 {
		t.Errorf("process came back after Stop: %+v", got)
	}
	waitFor(t, "supervisor goroutines to exit", func() bool { return runtime.NumGoroutine() <= before })
}

func TestSupervisorStopKillsProcessIgnoringSIGTERM(t *testing.T) {
	s, _ := newFakeSupervisor(t, "ignore-term", SupervisorOptions{StopTimeout: 100 * time.Millisecond})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "child output", func() bool { return logsContain(s, "fake stderr pid") })
	pid := s.Status().PID

	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("Stop did not return: SIGKILL fallback missing")
	}
	if got := s.Status().LastExit; got != "signal: killed" {
		t.Errorf("LastExit = %q, want %q", got, "signal: killed")
	}
	if !processGone(pid) {
		t.Errorf("pid %d survived Stop", pid)
	}
}

func TestSupervisorStopInterruptsCrashLoop(t *testing.T) {
	s, _ := newFakeSupervisor(t, "always-crash", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "several restarts", func() bool { return s.Status().Restarts >= 3 })
	if got := s.Status().LastExit; got != "exit status 4" {
		t.Errorf("LastExit = %q, want %q", got, "exit status 4")
	}
	s.Stop()
	n := s.Status().Restarts
	time.Sleep(150 * time.Millisecond)
	if got := s.Status(); got.Restarts != n || got.Running {
		t.Errorf("restarts continued after Stop: %d then %+v", n, got)
	}
}

func TestSupervisorApplyWritesConfigAndRestarts(t *testing.T) {
	s, cfg := newFakeSupervisor(t, "serve", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first config", func() bool { return logsContain(s, "config: first") })
	oldPID := s.Status().PID

	if err := s.Apply([]byte("second")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cfg)
	if err != nil || string(data) != "second" {
		t.Fatalf("config on disk = %q, %v; want %q", data, err, "second")
	}
	st := s.Status()
	if !st.Running || st.PID == oldPID || st.PID == 0 {
		t.Errorf("after Apply status = %+v, want a new running pid (old %d)", st, oldPID)
	}
	if st.Restarts != 0 {
		t.Errorf("Apply counted as a crash restart: %d", st.Restarts)
	}
	if !processGone(oldPID) {
		t.Errorf("old pid %d still exists after Apply", oldPID)
	}
	waitFor(t, "new config read by new process", func() bool { return logsContain(s, "config: second") })
	entries, _ := os.ReadDir(filepath.Dir(cfg))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file %s left behind", e.Name())
		}
	}
}

func TestSupervisorApplyWhenStoppedOnlyWrites(t *testing.T) {
	s, cfg := newFakeSupervisor(t, "serve", SupervisorOptions{})
	if err := s.Apply([]byte("written")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(cfg); string(data) != "written" {
		t.Errorf("config on disk = %q, want %q", data, "written")
	}
	if st := s.Status(); st.Running {
		t.Errorf("Apply on a stopped supervisor started xray: %+v", st)
	}
}

func TestSupervisorStartTwiceAndStartFailure(t *testing.T) {
	s, _ := newFakeSupervisor(t, "serve", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second Start = %v, want ErrAlreadyStarted", err)
	}

	missing := NewSupervisor(filepath.Join(t.TempDir(), "no-such-xray"), "cfg.json", SupervisorOptions{})
	err := missing.Start()
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Start with missing binary = %v, want ErrNotExist", err)
	}
	if st := missing.Status(); st.Running || !strings.Contains(st.LastExit, "no such file") {
		t.Errorf("status after failed start = %+v", st)
	}
	missing.Stop()
}

func TestSupervisorConcurrentUse(t *testing.T) {
	s, _ := newFakeSupervisor(t, "serve", SupervisorOptions{})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.Apply([]byte{byte('a' + i)}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = s.Status()
				_ = s.Logs()
			}
		}()
	}
	wg.Wait()
	if !s.Status().Running {
		t.Error("not running after concurrent applies")
	}
}

func TestRingLogKeepsLastLinesAcrossPartialWrites(t *testing.T) {
	r := newRingLog(3)
	w := r.writer(nil)
	for _, chunk := range []string{"one\ntw", "o\r\nthree\n", "four\nfive"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"two", "three", "four"}
	if got := r.lines(); !slices.Equal(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}
