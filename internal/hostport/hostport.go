// Package hostport finds the programs listening on a TCP port of this host and stops them, so
// a line can take a port that something else was holding.
package hostport

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Process is one program listening on the port.
type Process struct {
	PID int
	// Name is the command name, as in /proc/<pid>/comm.
	Name string
	// Unit is the systemd system service the process runs in, "" when it runs in none.
	Unit string
}

// Stopped is one thing FreeTCP stopped: a systemd service (stopped and disabled) or a lone process.
type Stopped struct {
	Unit string
	PID  int
	Name string
}

func (s Stopped) String() string {
	if s.Unit != "" {
		return s.Unit
	}
	return fmt.Sprintf("%s (pid %d)", s.Name, s.PID)
}

// RefusedError reports a holder FreeTCP will not stop.
type RefusedError struct {
	Port   int
	Holder Process
	Reason string
}

func (e *RefusedError) Error() string {
	name := e.Holder.Name
	if e.Holder.Unit != "" {
		name = e.Holder.Unit
	}
	return fmt.Sprintf("port %d/tcp is held by %s (pid %d), which the panel will not stop: %s", e.Port, name, e.Holder.PID, e.Reason)
}

// ErrUnseen means the port is in use but no process could be found holding it, e.g. because
// the panel cannot look into other users' processes.
var ErrUnseen = errors.New("hostport: the port is in use by a process the panel cannot see")

// ErrStillHeld means the port was still in use after everything holding it was stopped.
var ErrStillHeld = errors.New("hostport: the port is still in use")

type Options struct {
	// Listeners lists the processes listening on a TCP port. It returns ErrUnseen when the port
	// is in use but its holder cannot be found. nil reads /proc.
	Listeners func(ctx context.Context, port int) ([]Process, error)
	// Exec runs systemctl; nil runs it on this host.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Signal sends sig to pid; nil signals the real process.
	Signal func(pid int, sig syscall.Signal) error
	// Self is the panel's own process. It, and every process in its systemd unit, is never
	// touched. nil reads this process.
	Self *Process
	// Grace is how long a stopped holder has to let go of the port before it is killed, and
	// again after that; 0 means 5 seconds. Poll is how often the port is looked at meanwhile.
	Grace time.Duration
	Poll  time.Duration
}

// Freer stops the programs that hold a TCP port the panel needs.
type Freer struct {
	listeners func(context.Context, int) ([]Process, error)
	exec      func(context.Context, string, ...string) ([]byte, error)
	signal    func(int, syscall.Signal) error
	self      Process
	grace     time.Duration
	poll      time.Duration
}

func New(opts Options) *Freer {
	f := &Freer{listeners: opts.Listeners, exec: opts.Exec, signal: opts.Signal, grace: opts.Grace, poll: opts.Poll}
	if f.listeners == nil {
		f.listeners = ProcListeners("/proc")
	}
	if f.exec == nil {
		f.exec = runCommand
	}
	if f.signal == nil {
		f.signal = signalProcess
	}
	if opts.Self != nil {
		f.self = *opts.Self
	} else {
		f.self = Process{PID: os.Getpid(), Unit: readUnit("/proc", "self")}
	}
	if f.grace <= 0 {
		f.grace = 5 * time.Second
	}
	if f.poll <= 0 {
		f.poll = 200 * time.Millisecond
	}
	return f
}

// mine says whether p is the panel itself, part of the panel's systemd service (its Xray is),
// or one of the keep processes.
func (f *Freer) mine(p Process, keep []int) bool {
	return p.PID == f.self.PID || slices.Contains(keep, p.PID) || (f.self.Unit != "" && p.Unit == f.self.Unit)
}

// protected says why p must not be stopped, "" when it may be.
func protected(p Process) string {
	switch {
	case p.PID <= 1:
		// systemd itself, holding the socket for a .socket unit; killing it is out of the question.
		return "it is systemd listening for a socket unit"
	case p.Name == "sshd" || p.Unit == "ssh.service" || p.Unit == "sshd.service":
		return "stopping SSH would lock you out of the server"
	}
	return ""
}

// FreeTCP stops whatever listens on port except the panel and the keep processes (its Xray). A
// process in a systemd service has the service stopped and disabled, so it does not come back
// at the next boot; any other process is sent SIGTERM, then SIGKILL if it does not let go.
// It returns what it stopped, also when it fails part way.
func (f *Freer) FreeTCP(ctx context.Context, port int, keep []int) ([]Stopped, error) {
	holders, err := f.listeners(ctx, port)
	if err != nil {
		return nil, err
	}
	var others []Process
	for _, p := range holders {
		if !f.mine(p, keep) {
			others = append(others, p)
		}
	}
	// Refuse before stopping anything, so a refusal leaves the host as it was.
	for _, p := range others {
		if why := protected(p); why != "" {
			return nil, &RefusedError{Port: port, Holder: p, Reason: why}
		}
	}

	var stopped []Stopped
	var signalled []int
	units := map[string]bool{}
	for _, p := range others {
		if p.Unit != "" {
			if units[p.Unit] {
				continue
			}
			units[p.Unit] = true
			if out, err := f.exec(ctx, "systemctl", "disable", "--now", p.Unit); err != nil {
				return stopped, fmt.Errorf("hostport: systemctl disable --now %s: %w: %s", p.Unit, err, strings.TrimSpace(string(out)))
			}
			stopped = append(stopped, Stopped{Unit: p.Unit, Name: p.Name})
			continue
		}
		if err := f.signal(p.PID, syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return stopped, fmt.Errorf("hostport: stop %s (pid %d): %w", p.Name, p.PID, err)
		}
		signalled = append(signalled, p.PID)
		stopped = append(stopped, Stopped{PID: p.PID, Name: p.Name})
	}
	if len(stopped) == 0 {
		return nil, nil
	}
	if f.waitFree(ctx, port, keep) {
		return stopped, nil
	}
	for _, pid := range signalled {
		_ = f.signal(pid, syscall.SIGKILL)
	}
	if len(signalled) > 0 && f.waitFree(ctx, port, keep) {
		return stopped, nil
	}
	return stopped, fmt.Errorf("%w: port %d/tcp after stopping %s", ErrStillHeld, port, joinStopped(stopped))
}

// waitFree polls until nobody but the panel holds port, or the grace period ends.
func (f *Freer) waitFree(ctx context.Context, port int, keep []int) bool {
	deadline := time.Now().Add(f.grace)
	for {
		holders, err := f.listeners(ctx, port)
		if err == nil && !slices.ContainsFunc(holders, func(p Process) bool { return !f.mine(p, keep) }) {
			return true
		}
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(f.poll):
		}
	}
}

func joinStopped(s []Stopped) string {
	names := make([]string, len(s))
	for i, x := range s {
		names[i] = x.String()
	}
	return strings.Join(names, ", ")
}

// ProcListeners reads listening sockets from root/net/tcp and tcp6 and finds their owners
// through root/<pid>/fd. Where root has no such files (not Linux), nothing listens.
func ProcListeners(root string) func(ctx context.Context, port int) ([]Process, error) {
	return func(ctx context.Context, port int) ([]Process, error) {
		sockets := map[string]bool{}
		for _, name := range []string{"net/tcp", "net/tcp6"} {
			data, err := os.ReadFile(filepath.Join(root, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for _, inode := range listeningInodes(string(data), port) {
				sockets["socket:["+inode+"]"] = true
			}
		}
		if len(sockets) == 0 {
			return nil, nil
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		var out []Process
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid <= 0 {
				continue
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			dir := filepath.Join(root, e.Name())
			// A process that is gone, or that belongs to someone the panel may not look at, is skipped.
			fds, err := os.ReadDir(filepath.Join(dir, "fd"))
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
				if err != nil || !sockets[target] {
					continue
				}
				comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
				out = append(out, Process{PID: pid, Name: strings.TrimSpace(string(comm)), Unit: readUnit(root, e.Name())})
				break
			}
		}
		if len(out) == 0 {
			return nil, ErrUnseen
		}
		return out, nil
	}
}

// listeningInodes picks the sockets in LISTEN state on port from a /proc/net/tcp table.
func listeningInodes(table string, port int) []string {
	const listen = "0A"
	var out []string
	for line := range strings.Lines(table) {
		f := strings.Fields(line)
		if len(f) < 10 || f[3] != listen {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		p, err := strconv.ParseUint(f[1][i+1:], 16, 16)
		if err != nil || int(p) != port || f[9] == "0" {
			continue
		}
		out = append(out, f[9])
	}
	return out
}

func readUnit(root, pid string) string {
	data, err := os.ReadFile(filepath.Join(root, pid, "cgroup"))
	if err != nil {
		return ""
	}
	return UnitFromCgroup(string(data))
}

// UnitFromCgroup finds the systemd system service in a /proc/<pid>/cgroup file, "" when the
// process is in none (a login session, a container scope, a user's own service manager).
func UnitFromCgroup(cgroup string) string {
	for line := range strings.Lines(cgroup) {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) != 3 {
			continue
		}
		// The unified hierarchy (cgroup v2) is "0::"; under v1 systemd keeps its own "name=systemd".
		if !(parts[0] == "0" && parts[1] == "") && parts[1] != "name=systemd" {
			continue
		}
		path := parts[2]
		if strings.Contains(path, "/user@") {
			// A unit of someone's user manager; systemctl without --user cannot stop it.
			return ""
		}
		segs := strings.Split(path, "/")
		for i := len(segs) - 1; i >= 0; i-- {
			if strings.HasSuffix(segs[i], ".service") {
				return segs[i]
			}
		}
		return ""
	}
	return ""
}

// A service's PATH often lacks the sbin directories.
const commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	for dir := range strings.SplitSeq(commandPath, ":") {
		p := dir + "/" + name
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			cmd := exec.CommandContext(ctx, p, args...)
			cmd.Env = append(os.Environ(), "PATH="+commandPath, "LC_ALL=C")
			return cmd.CombinedOutput()
		}
	}
	return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
}

func signalProcess(pid int, sig syscall.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}
