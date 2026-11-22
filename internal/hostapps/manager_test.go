package hostapps

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeHost answers the commands the manager runs from a small model of a Debian box.
type fakeHost struct {
	mu        sync.Mutex
	installed map[string]string   // package -> version
	leftover  map[string]bool     // package removed, config files still there
	deps      map[string][]string // package -> what apt installs with it, and removes it with
	active    map[string]bool     // unit -> running
	fail      map[string]error    // "apt-get install" -> error
	ran       []string
	gate      chan struct{} // when set, apt-get install waits for it
}

func newFakeHost() *fakeHost {
	return &fakeHost{installed: map[string]string{}, active: map[string]bool{}, fail: map[string]error{}}
}

func (h *fakeHost) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	h.mu.Lock()
	gate := h.gate
	h.mu.Unlock()
	if gate != nil && name == "apt-get" && slices.Contains(args, "install") {
		<-gate
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	switch name {
	case "dpkg-query":
		if !slices.Contains(args, "-f=${db:Status-Status}\n${Version}") {
			return nil, errors.New("unexpected dpkg-query format")
		}
		pkg := args[len(args)-1]
		if h.leftover[pkg] {
			return []byte("config-files\n1.0-1"), nil
		}
		v, ok := h.installed[pkg]
		if !ok {
			return []byte("dpkg-query: no packages found"), errors.New("exit status 1")
		}
		return []byte("installed\n" + v), nil
	case "systemctl":
		if args[0] == "is-active" {
			if h.active[args[1]] {
				return []byte("active\n"), nil
			}
			return []byte("inactive\n"), errors.New("exit status 3")
		}
	}
	h.ran = append(h.ran, line)
	if err := h.fail[commandName(append([]string{name}, args...))]; err != nil {
		return []byte("(Reading database ... 5%\r(Reading database ... 100%\rE: something broke\r\n"), err
	}
	switch {
	case name == "apt-get" && slices.Contains(args, "install"):
		for _, p := range args[slices.Index(args, "-y")+1:] {
			h.installed[p] = "1.0-1"
			for _, d := range h.deps[p] {
				h.installed[d] = "1.0-1"
			}
		}
	case name == "apt-get" && slices.Contains(args, "remove"):
		for _, p := range args[slices.Index(args, "-y")+1:] {
			delete(h.installed, p)
			// apt takes away whatever depends on a package it removes, never what it depends on.
			for dependent, needs := range h.deps {
				if slices.Contains(needs, p) {
					delete(h.installed, dependent)
				}
			}
		}
	case name == "systemctl" && (args[0] == "enable" || args[0] == "disable"):
		for _, u := range args[2:] {
			h.active[u] = args[0] == "enable"
		}
	}
	return nil, nil
}

func (h *fakeHost) commands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.ran)
}

func newManager(h *fakeHost, busyPorts ...int) *Manager {
	return New(Options{
		Exec:        h.exec,
		Unsupported: func() string { return "" },
		PortFree:    func(p int) bool { return !slices.Contains(busyPorts, p) },
	})
}

func stateOf(t *testing.T, m *Manager, id string) State {
	t.Helper()
	for _, s := range m.List(context.Background()) {
		if s.App.ID == id {
			return s
		}
	}
	t.Fatalf("no %s in the list", id)
	return State{}
}

func TestInstallThenRemove(t *testing.T) {
	h := newFakeHost()
	m := newManager(h)
	ctx := context.Background()

	var finished Job
	if err := m.Begin(ctx, "docker", ActionInstall, func(j Job) { finished = j }); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if finished.State != JobDone || finished.App != "docker" || finished.Action != ActionInstall {
		t.Fatalf("finished job = %+v", finished)
	}
	want := []string{
		"dpkg --configure -a",
		"apt-get -o DPkg::Lock::Timeout=120 update",
		"apt-get -o DPkg::Lock::Timeout=120 install --no-remove -y docker.io",
		"systemctl enable --now docker.service docker.socket",
	}
	if got := h.commands(); !slices.Equal(got, want) {
		t.Fatalf("install ran\n%q\nwant\n%q", got, want)
	}
	if s := stateOf(t, m, "docker"); !s.Installed || s.Version != "1.0-1" || s.Service != ServiceRunning {
		t.Fatalf("after install: %+v", s)
	}

	if err := m.Begin(ctx, "docker", ActionStop, nil); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if s := stateOf(t, m, "docker"); s.Service != ServiceStopped {
		t.Fatalf("after stop: %+v", s)
	}

	if err := m.Begin(ctx, "docker", ActionRemove, nil); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if s := stateOf(t, m, "docker"); s.Installed || s.Service != ServiceNone {
		t.Fatalf("after remove: %+v", s)
	}
}

// Before Debian 13 and Ubuntu 24.04 "nginx" is an empty package that only depends on the real
// ones. Removing it alone left the server installed while the page said it was gone.
func TestRemoveTakesTheProgramBehindAMetapackage(t *testing.T) {
	h := newFakeHost()
	h.deps = map[string][]string{"nginx": {"nginx-core", "nginx-common"}, "nginx-core": {"nginx-common"}}
	m := newManager(h)
	ctx := context.Background()
	if err := m.Begin(ctx, "nginx", ActionInstall, nil); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if len(h.installed) != 3 {
		t.Fatalf("after install: %v, want nginx, nginx-core and nginx-common", h.installed)
	}
	if err := m.Begin(ctx, "nginx", ActionRemove, nil); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if j := m.Job(); j.State != JobDone {
		t.Fatalf("remove job = %+v", j)
	}
	if len(h.installed) != 0 {
		t.Fatalf("after remove these are still installed: %v", h.installed)
	}
}

func TestRemovedWithConfigLeftIsNotInstalled(t *testing.T) {
	h := newFakeHost()
	h.leftover = map[string]bool{"nginx": true}
	m := newManager(h)
	if s := stateOf(t, m, "nginx"); s.Installed || s.Version != "" {
		t.Fatalf("nginx with only its config left: %+v", s)
	}
	if err := m.Begin(context.Background(), "nginx", ActionInstall, nil); err != nil {
		t.Fatalf("install over leftover config: %v", err)
	}
	m.Wait()
}

func TestBeginRefusals(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	h.installed["htop"] = "3.4"
	m := newManager(h, 80)

	for _, tc := range []struct {
		name, app, action string
		want              error
	}{
		{"unknown app", "rm -rf /", ActionInstall, ErrUnknownApp},
		{"unknown action", "nginx", "purge", ErrUnknownVerb},
		{"already installed", "htop", ActionInstall, ErrState},
		{"remove what is absent", "nginx", ActionRemove, ErrState},
		{"start what is absent", "nginx", ActionStart, ErrState},
		{"start a plain tool", "htop", ActionStart, ErrState},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.Begin(ctx, tc.app, tc.action, nil); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	var pe *PortError
	if err := m.Begin(ctx, "nginx", ActionInstall, nil); !errors.As(err, &pe) || pe.Port != 80 {
		t.Fatalf("install on a taken port: err = %v", err)
	}
	if ran := h.commands(); len(ran) != 0 {
		t.Fatalf("a refused action still ran %q", ran)
	}
}

func TestOneJobAtATime(t *testing.T) {
	h := newFakeHost()
	h.gate = make(chan struct{})
	m := newManager(h)
	ctx := context.Background()
	if err := m.Begin(ctx, "htop", ActionInstall, nil); err != nil {
		t.Fatal(err)
	}
	if err := m.Begin(ctx, "iperf3", ActionInstall, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second job: err = %v, want ErrBusy", err)
	}
	if j := m.Job(); j == nil || j.State != JobRunning || j.App != "htop" {
		t.Fatalf("job while running = %+v", j)
	}
	close(h.gate)
	m.Wait()
	if err := m.Begin(ctx, "iperf3", ActionInstall, nil); err != nil {
		t.Fatal(err)
	}
	m.Wait()
}

func TestFailedInstallKeepsTheOutput(t *testing.T) {
	h := newFakeHost()
	// A failing `apt-get update` alone must not stop the install.
	h.fail["apt-get update"] = errors.New("exit status 100")
	h.fail["apt-get install"] = errors.New("exit status 100")
	m := newManager(h)
	var finished Job
	if err := m.Begin(context.Background(), "vnstat", ActionInstall, func(j Job) { finished = j }); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if finished.State != JobFailed || finished.Error != "apt-get install: exit status 100" {
		t.Fatalf("finished job = %+v", finished)
	}
	if !slices.Contains(finished.Log, "E: something broke") {
		t.Fatalf("log lost the command output: %q", finished.Log)
	}
	if ran := h.commands(); slices.ContainsFunc(ran, func(c string) bool { return strings.HasPrefix(c, "systemctl enable") }) {
		t.Fatalf("service was enabled after a failed install: %q", ran)
	}
	if s := stateOf(t, m, "vnstat"); s.Installed {
		t.Fatalf("vnstat reported installed: %+v", s)
	}
}

func TestUnsupportedHostRunsNothing(t *testing.T) {
	h := newFakeHost()
	m := New(Options{Exec: h.exec, Unsupported: func() string { return ReasonRoot }})
	if got := m.List(context.Background()); len(got) != len(Catalog) {
		t.Fatalf("list has %d entries, want the whole catalog (%d)", len(got), len(Catalog))
	}
	if err := m.Begin(context.Background(), "htop", ActionInstall, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if ran := h.commands(); len(ran) != 0 {
		t.Fatalf("commands ran on an unsupported host: %q", ran)
	}
}

func TestCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range Catalog {
		if a.ID == "" || seen[a.ID] || len(a.Packages) == 0 {
			t.Errorf("bad catalog entry %+v", a)
		}
		seen[a.ID] = true
		// These strings become arguments of commands run as root.
		for _, s := range slices.Concat(a.Packages, a.RemoveToo, a.Units) {
			if strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\n;&|$`'\"\\/") {
				t.Errorf("%s: unsafe package or unit name %q", a.ID, s)
			}
		}
	}
}
