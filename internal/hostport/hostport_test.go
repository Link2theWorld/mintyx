package hostport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeHost holds a port the way the kernel does: a process holds it until it is stopped.
type fakeHost struct {
	mu      sync.Mutex
	holders []Process
	// ignoreTerm lists pids that only SIGKILL gets rid of.
	ignoreTerm []int
	// stubborn keeps the port held whatever happens.
	stubborn bool
	calls    []string
	signals  []string
}

func (h *fakeHost) listeners(context.Context, int) ([]Process, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.holders), nil
}

func (h *fakeHost) drop(keep func(Process) bool) {
	if h.stubborn {
		return
	}
	h.holders = slices.DeleteFunc(h.holders, func(p Process) bool { return !keep(p) })
}

func (h *fakeHost) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, strings.Join(append([]string{name}, args...), " "))
	unit := args[len(args)-1]
	h.drop(func(p Process) bool { return p.Unit != unit })
	return nil, nil
}

func (h *fakeHost) signal(pid int, sig syscall.Signal) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.signals = append(h.signals, sig.String()+" "+strconv.Itoa(pid))
	if sig == syscall.SIGTERM && slices.Contains(h.ignoreTerm, pid) {
		return nil
	}
	h.drop(func(p Process) bool { return p.PID != pid })
	return nil
}

func (h *fakeHost) freer() *Freer {
	return New(Options{
		Listeners: h.listeners, Exec: h.exec, Signal: h.signal,
		Self:  &Process{PID: 100, Name: "mintyx", Unit: "mintyx.service"},
		Grace: 20 * time.Millisecond, Poll: time.Millisecond,
	})
}

func names(s []Stopped) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.String()
	}
	return out
}

func TestFreeTCPStopsAndDisablesAService(t *testing.T) {
	h := &fakeHost{holders: []Process{
		{PID: 2001, Name: "nginx", Unit: "nginx.service"},
		{PID: 2002, Name: "nginx", Unit: "nginx.service"},
	}}
	stopped, err := h.freer().FreeTCP(t.Context(), 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(stopped); !slices.Equal(got, []string{"nginx.service"}) {
		t.Errorf("stopped = %v, want nginx.service once", got)
	}
	if !slices.Equal(h.calls, []string{"systemctl disable --now nginx.service"}) {
		t.Errorf("commands = %v", h.calls)
	}
	if len(h.signals) != 0 {
		t.Errorf("a service's processes were signalled directly: %v", h.signals)
	}
}

func TestFreeTCPTerminatesALoneProcess(t *testing.T) {
	h := &fakeHost{holders: []Process{{PID: 3001, Name: "python3"}}}
	stopped, err := h.freer().FreeTCP(t.Context(), 443, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(stopped); !slices.Equal(got, []string{"python3 (pid 3001)"}) {
		t.Errorf("stopped = %v", got)
	}
	if !slices.Equal(h.signals, []string{"terminated 3001"}) {
		t.Errorf("signals = %v, want one SIGTERM", h.signals)
	}
}

func TestFreeTCPKillsWhatIgnoresSIGTERM(t *testing.T) {
	h := &fakeHost{holders: []Process{{PID: 3001, Name: "stubborn"}}, ignoreTerm: []int{3001}}
	if _, err := h.freer().FreeTCP(t.Context(), 443, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.signals, []string{"terminated 3001", "killed 3001"}) {
		t.Errorf("signals = %v, want SIGTERM then SIGKILL", h.signals)
	}
}

func TestFreeTCPLeavesThePanelAndItsXrayAlone(t *testing.T) {
	h := &fakeHost{holders: []Process{
		{PID: 100, Name: "mintyx", Unit: "mintyx.service"},
		{PID: 101, Name: "xray", Unit: "mintyx.service"},
		{PID: 4001, Name: "xray"}, // the panel's Xray when the panel runs outside systemd
	}}
	stopped, err := h.freer().FreeTCP(t.Context(), 443, []int{4001})
	if err != nil || stopped != nil {
		t.Fatalf("FreeTCP = %v, %v; want nothing stopped", stopped, err)
	}
	if len(h.calls)+len(h.signals) != 0 {
		t.Errorf("the panel's own processes were touched: %v %v", h.calls, h.signals)
	}
}

func TestFreeTCPRefusesSSHAndSystemd(t *testing.T) {
	for _, p := range []Process{
		{PID: 700, Name: "sshd", Unit: "ssh.service"},
		{PID: 1, Name: "systemd"},
	} {
		h := &fakeHost{holders: []Process{{PID: 2001, Name: "nginx", Unit: "nginx.service"}, p}}
		stopped, err := h.freer().FreeTCP(t.Context(), 443, nil)
		var re *RefusedError
		if !errors.As(err, &re) || re.Holder.PID != p.PID {
			t.Fatalf("%s: err = %v, want a refusal naming it", p.Name, err)
		}
		// Nothing is stopped when the port cannot be freed anyway.
		if stopped != nil || len(h.calls)+len(h.signals) != 0 {
			t.Errorf("%s: stopped %v, ran %v %v", p.Name, stopped, h.calls, h.signals)
		}
	}
}

func TestFreeTCPReportsAPortStillHeld(t *testing.T) {
	h := &fakeHost{holders: []Process{{PID: 2001, Name: "nginx", Unit: "nginx.service"}}, stubborn: true}
	stopped, err := h.freer().FreeTCP(t.Context(), 443, nil)
	if !errors.Is(err, ErrStillHeld) {
		t.Fatalf("err = %v, want ErrStillHeld", err)
	}
	if got := names(stopped); !slices.Equal(got, []string{"nginx.service"}) {
		t.Errorf("stopped = %v, want what was stopped even so", got)
	}
}

func TestFreeTCPWithNothingThere(t *testing.T) {
	h := &fakeHost{}
	if stopped, err := h.freer().FreeTCP(t.Context(), 443, nil); err != nil || stopped != nil {
		t.Fatalf("FreeTCP = %v, %v", stopped, err)
	}
}

func TestUnitFromCgroup(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"0::/system.slice/nginx.service\n", "nginx.service"},
		{"0::/system.slice/getty@tty1.service\n", "getty@tty1.service"},
		{"0::/system.slice/docker-0123abcd.scope\n", ""},
		{"0::/user.slice/user-0.slice/session-3.scope\n", ""},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/web.service\n", ""},
		{"0::/init.scope\n", ""},
		// cgroup v1: only systemd's own hierarchy says which unit it is.
		{"12:pids:/system.slice/caddy.service\n1:name=systemd:/system.slice/caddy.service\n0::/\n", "caddy.service"},
		{"", ""},
	} {
		if got := UnitFromCgroup(tc.in); got != tc.want {
			t.Errorf("UnitFromCgroup(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

const tcpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5551 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F98 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5552 1 0000000000000000 100 0 0 10 0
   2: 0A000001:01BB 0A000002:C350 01 00000000:00000000 00:00000000 00000000     0        0 5553 1 0000000000000000 100 0 0 10 0
`

const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5554 1 0000000000000000 100 0 0 10 0
`

func TestProcListeners(t *testing.T) {
	root := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, target string) {
		t.Helper()
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	write("net/tcp", tcpTable)
	write("net/tcp6", tcp6Table)
	// nginx listens on 443 over IPv4, caddy over IPv6; 8088 and the established connection don't count.
	write("2001/comm", "nginx\n")
	write("2001/cgroup", "0::/system.slice/nginx.service\n")
	link("2001/fd/6", "socket:[5551]")
	link("2001/fd/7", "/dev/null")
	write("2002/comm", "caddy\n")
	write("2002/cgroup", "0::/user.slice/user-0.slice/session-1.scope\n")
	link("2002/fd/3", "socket:[5554]")
	write("100/comm", "mintyx\n")
	link("100/fd/9", "socket:[5552]")
	write("3000/comm", "curl\n")
	link("3000/fd/3", "socket:[5553]")

	got, err := ProcListeners(root)(t.Context(), 443)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b Process) int { return a.PID - b.PID })
	want := []Process{{PID: 2001, Name: "nginx", Unit: "nginx.service"}, {PID: 2002, Name: "caddy"}}
	if !slices.Equal(got, want) {
		t.Errorf("listeners on 443 = %+v, want %+v", got, want)
	}

	if got, err := ProcListeners(root)(t.Context(), 2053); err != nil || got != nil {
		t.Errorf("listeners on a free port = %+v, %v; want none", got, err)
	}
	// Bound, but no process the panel can see owns it.
	if _, err := ProcListeners(root)(t.Context(), 8088); err != nil {
		t.Errorf("8088 is held by pid 100: %v", err)
	}
	write("net/tcp", tcpTable+"   3: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5560 1 0000000000000000 100 0 0 10 0\n")
	if _, err := ProcListeners(root)(t.Context(), 80); !errors.Is(err, ErrUnseen) {
		t.Errorf("port held by an unseen process: err = %v, want ErrUnseen", err)
	}
	// Not Linux: no /proc, nothing to find.
	if got, err := ProcListeners(filepath.Join(root, "missing"))(t.Context(), 443); err != nil || got != nil {
		t.Errorf("without /proc = %+v, %v", got, err)
	}
}
