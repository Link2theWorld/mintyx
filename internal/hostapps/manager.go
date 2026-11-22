package hostapps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Actions a caller may ask for.
const (
	ActionInstall = "install"
	ActionRemove  = "remove"
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
)

// Service states; ServiceNone is an app without a service, or one that is not installed.
const (
	ServiceNone    = ""
	ServiceRunning = "running"
	ServiceStopped = "stopped"
	ServiceFailed  = "failed"
)

// Job states.
const (
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
)

// Reasons the host cannot be managed, as returned by Manager.Unsupported.
const (
	ReasonOS      = "os"
	ReasonRoot    = "root"
	ReasonSystemd = "systemd"
	ReasonApt     = "apt"
)

var (
	ErrUnknownApp  = errors.New("hostapps: no such app")
	ErrUnknownVerb = errors.New("hostapps: no such action")
	ErrBusy        = errors.New("hostapps: another job is still running")
	ErrUnsupported = errors.New("hostapps: this server cannot be managed")
	// ErrState means the action does not fit the app as it is now, e.g. removing what is not installed.
	ErrState = errors.New("hostapps: the app is not in a state that allows this")
)

// PortError reports a port the service would need that something else already holds.
type PortError struct{ Port int }

func (e *PortError) Error() string {
	return "hostapps: port " + strconv.Itoa(e.Port) + " is already in use"
}

// Exec runs one command and returns its combined output.
type Exec func(ctx context.Context, name string, args ...string) ([]byte, error)

type Options struct {
	// Exec replaces real command execution; nil runs the commands on this host.
	Exec Exec
	// Unsupported says why this host cannot be managed, "" when it can; nil inspects the real host.
	Unsupported func() string
	// PortFree says whether a TCP port can still be bound; nil tries to bind it.
	PortFree func(port int) bool
	Now      func() time.Time
}

// State is one catalog entry as found on this host.
type State struct {
	App       App
	Installed bool
	Version   string
	Service   string
}

// Job is the one install/remove/service action in flight, or the last one that finished.
type Job struct {
	App       string
	Action    string
	State     string
	StartedAt time.Time
	EndedAt   time.Time
	// Error names the step that failed; the commands' own output is in Log.
	Error string
	Log   []string
}

const (
	jobTimeout  = 15 * time.Minute
	maxLogLines = 200
	maxLineLen  = 400
)

// Manager runs at most one job at a time: apt holds a system-wide lock anyway.
type Manager struct {
	exec        Exec
	unsupported func() string
	portFree    func(int) bool
	now         func() time.Time

	mu   sync.Mutex
	job  *Job
	idle chan struct{}
}

func New(opts Options) *Manager {
	m := &Manager{exec: opts.Exec, unsupported: opts.Unsupported, portFree: opts.PortFree, now: opts.Now}
	if m.exec == nil {
		m.exec = runCommand
	}
	if m.unsupported == nil {
		m.unsupported = sync.OnceValue(inspectHost)
	}
	if m.portFree == nil {
		m.portFree = canBind
	}
	if m.now == nil {
		m.now = time.Now
	}
	return m
}

// Unsupported is "" when apps can be managed here, otherwise one of the Reason constants.
func (m *Manager) Unsupported() string { return m.unsupported() }

// List reports every catalog entry. On an unsupported host nothing is inspected.
func (m *Manager) List(ctx context.Context) []State {
	supported := m.Unsupported() == ""
	out := make([]State, 0, len(Catalog))
	for _, a := range Catalog {
		st := State{App: a}
		if supported {
			st = m.inspect(ctx, a)
		}
		out = append(out, st)
	}
	return out
}

// Job returns a copy of the running or most recently finished job, nil when there was none.
func (m *Manager) Job() *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job == nil {
		return nil
	}
	j := *m.job
	j.Log = append([]string(nil), m.job.Log...)
	return &j
}

// Wait blocks until no job is running.
func (m *Manager) Wait() {
	m.mu.Lock()
	idle := m.idle
	m.mu.Unlock()
	if idle != nil {
		<-idle
	}
}

func (m *Manager) inspect(ctx context.Context, a App) State {
	st := State{App: a}
	// Only what is on disk counts: a package removed with its config left behind reports
	// "config-files", and one held back with apt-mark is still "installed".
	out, err := m.exec(ctx, "dpkg-query", "-W", "-f=${db:Status-Status}\n${Version}", "--", a.Packages[0])
	status, version, _ := strings.Cut(string(out), "\n")
	if err != nil || strings.TrimSpace(status) != "installed" {
		return st
	}
	st.Installed = true
	st.Version = strings.TrimSpace(version)
	if len(a.Units) > 0 {
		// is-active exits non-zero for anything but "active"; the word it prints is the answer.
		out, _ := m.exec(ctx, "systemctl", "is-active", a.Units[0])
		switch strings.TrimSpace(string(out)) {
		case "active", "activating", "reloading":
			st.Service = ServiceRunning
		case "failed":
			st.Service = ServiceFailed
		default:
			st.Service = ServiceStopped
		}
	}
	return st
}

type step struct {
	argv []string
	// optional steps only prepare the ground; their failure is logged and the job goes on.
	optional bool
}

var aptLockWait = []string{"-o", "DPkg::Lock::Timeout=120"}

func apt(args ...string) []string {
	return append(append([]string{"apt-get"}, aptLockWait...), args...)
}

func plan(a App, action string) []step {
	enable := append([]string{"systemctl", "enable", "--now"}, a.Units...)
	disable := append([]string{"systemctl", "disable", "--now"}, a.Units...)
	switch action {
	case ActionInstall:
		steps := []step{
			// Finishes an install that an earlier panel restart cut short, which would block apt.
			{argv: []string{"dpkg", "--configure", "-a"}, optional: true},
			// One broken third-party source should not stop an install the existing lists can serve.
			{argv: apt("update"), optional: true},
			// --no-remove: apt may not take a conflicting package away to make room, e.g. a
			// running Docker CE for docker.io. The install fails and says so instead.
			{argv: apt(append([]string{"install", "--no-remove", "-y"}, a.Packages...)...)},
		}
		if len(a.Units) > 0 {
			steps = append(steps, step{argv: enable})
		}
		return steps
	case ActionRemove:
		var steps []step
		if len(a.Units) > 0 {
			steps = append(steps, step{argv: disable, optional: true})
		}
		return append(steps, step{argv: apt(append(append([]string{"remove", "-y"}, a.Packages...), a.RemoveToo...)...)})
	case ActionStart:
		return []step{{argv: enable}}
	case ActionStop:
		return []step{{argv: disable}}
	case ActionRestart:
		return []step{{argv: []string{"systemctl", "restart", a.Units[0]}}}
	}
	return nil
}

// Begin starts an action in the background and returns once it is accepted. done, when not nil,
// is called with the finished job.
func (m *Manager) Begin(ctx context.Context, appID, action string, done func(Job)) error {
	a, ok := find(appID)
	if !ok {
		return ErrUnknownApp
	}
	switch action {
	case ActionInstall, ActionRemove, ActionStart, ActionStop, ActionRestart:
	default:
		return ErrUnknownVerb
	}
	if m.Unsupported() != "" {
		return ErrUnsupported
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.job != nil && m.job.State == JobRunning {
		return ErrBusy
	}
	st := m.inspect(ctx, a)
	switch action {
	case ActionInstall:
		if st.Installed {
			return ErrState
		}
		for _, p := range a.Ports {
			if !m.portFree(p) {
				return &PortError{Port: p}
			}
		}
	case ActionRemove:
		if !st.Installed {
			return ErrState
		}
	default:
		if !st.Installed || len(a.Units) == 0 {
			return ErrState
		}
	}

	job := &Job{App: a.ID, Action: action, State: JobRunning, StartedAt: m.now()}
	idle := make(chan struct{})
	m.job, m.idle = job, idle
	go m.run(job, plan(a, action), idle, done)
	return nil
}

// run is detached from the request that started it: closing the browser tab must not kill apt.
func (m *Manager) run(job *Job, steps []step, idle chan struct{}, done func(Job)) {
	ctx, cancel := context.WithTimeout(context.Background(), jobTimeout)
	defer cancel()
	failed := ""
	for _, s := range steps {
		out, err := m.exec(ctx, s.argv[0], s.argv[1:]...)
		m.mu.Lock()
		job.Log = appendLog(job.Log, "$ "+strings.Join(s.argv, " "))
		for line := range strings.Lines(string(out)) {
			// dpkg redraws its progress with carriage returns; only what ends up on screen is kept.
			line = strings.TrimRight(line, "\r\n")
			if i := strings.LastIndexByte(line, '\r'); i >= 0 {
				line = line[i+1:]
			}
			if strings.TrimSpace(line) != "" {
				job.Log = appendLog(job.Log, line)
			}
		}
		if err != nil {
			job.Log = appendLog(job.Log, "! "+err.Error())
		}
		m.mu.Unlock()
		if err != nil && !s.optional {
			failed = fmt.Sprintf("%s: %v", commandName(s.argv), err)
			break
		}
	}

	m.mu.Lock()
	job.EndedAt = m.now()
	job.State = JobDone
	if failed != "" {
		job.State, job.Error = JobFailed, failed
	}
	final := *job
	final.Log = append([]string(nil), job.Log...)
	m.mu.Unlock()
	if done != nil {
		done(final)
	}
	close(idle)
}

// commandName is the command and its verb without options, e.g. "apt-get install".
func commandName(argv []string) string {
	for _, a := range argv[1:] {
		if !strings.HasPrefix(a, "-") && !strings.Contains(a, "=") {
			return argv[0] + " " + a
		}
	}
	return argv[0]
}

func appendLog(log []string, line string) []string {
	if len(line) > maxLineLen {
		line = line[:maxLineLen] + "…"
	}
	log = append(log, line)
	if len(log) > maxLogLines {
		log = log[len(log)-maxLogLines:]
	}
	return log
}

// A service's PATH often lacks the sbin directories dpkg's maintainer scripts expect.
const commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	// Resolve against the PATH the command itself will get, not the service's.
	path, err := lookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(),
		"PATH="+commandPath,
		// Package scripts must never wait for an answer nobody can give.
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=a",
		"LC_ALL=C",
	)
	return cmd.CombinedOutput()
}

func lookPath(name string) (string, error) {
	for dir := range strings.SplitSeq(commandPath, ":") {
		p := dir + "/" + name
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", exec.ErrNotFound
}

func inspectHost() string {
	if runtime.GOOS != "linux" {
		return ReasonOS
	}
	if os.Geteuid() != 0 {
		return ReasonRoot
	}
	if fi, err := os.Stat("/run/systemd/system"); err != nil || !fi.IsDir() {
		return ReasonSystemd
	}
	for _, bin := range []string{"apt-get", "dpkg-query", "systemctl"} {
		if _, err := lookPath(bin); err != nil {
			if bin == "systemctl" {
				return ReasonSystemd
			}
			return ReasonApt
		}
	}
	return ""
}

func canBind(port int) bool {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}
