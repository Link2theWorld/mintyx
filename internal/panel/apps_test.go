package panel

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Link2theWorld/mintyx/internal/hostapps"
)

// fakeApt remembers which packages are installed and can be told to fail an install.
type fakeApt struct {
	mu          sync.Mutex
	installed   map[string]bool
	failInstall bool
}

func (a *fakeApt) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case name == "dpkg-query":
		if a.installed[args[len(args)-1]] {
			return []byte("installed\n2.4-1"), nil
		}
		return nil, errors.New("exit status 1")
	case name == "systemctl" && args[0] == "is-active":
		return []byte("active\n"), nil
	case name == "apt-get" && slices.Contains(args, "install"):
		if a.failInstall {
			return []byte("E: Unable to locate package\n"), errors.New("exit status 100")
		}
		a.installed[args[len(args)-1]] = true
	}
	return nil, nil
}

type appsBody struct {
	Supported bool       `json:"supported"`
	Reason    string     `json:"reason"`
	Apps      []appDTO   `json:"apps"`
	Job       *appJobDTO `json:"job"`
}

func appsFixture(t *testing.T, apt *fakeApt, busyPorts ...int) (*fixture, *hostapps.Manager, *http.Cookie) {
	t.Helper()
	m := hostapps.New(hostapps.Options{
		Exec:        apt.exec,
		Unsupported: func() string { return "" },
		PortFree:    func(p int) bool { return !slices.Contains(busyPorts, p) },
	})
	f := newFixture(t, func(c *Config) { c.Apps = m })
	return f, m, f.setup()
}

func appByID(t *testing.T, b appsBody, id string) appDTO {
	t.Helper()
	for _, a := range b.Apps {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("no %s in %+v", id, b.Apps)
	return appDTO{}
}

func auditActions(t *testing.T, f *fixture) []string {
	t.Helper()
	entries, err := f.st.ListAudit(context.Background(), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "app.") {
			out = append(out, e.Action+" "+e.Target)
		}
	}
	return out
}

func TestAppsInstall(t *testing.T) {
	f, m, c := appsFixture(t, &fakeApt{installed: map[string]bool{}})

	before := decodeBody[appsBody](t, f.do("GET", "/api/apps", nil, withCookie(c)))
	if !before.Supported || before.Job != nil || len(before.Apps) != len(hostapps.Catalog) {
		t.Fatalf("before: %+v", before)
	}
	if a := appByID(t, before, "nginx"); a.Installed || !a.Service || !slices.Equal(a.Ports, []int{80}) {
		t.Fatalf("nginx before install: %+v", a)
	}

	expectStatus(t, f.do("POST", "/api/apps/nginx/install", nil, withCookie(c)), http.StatusAccepted)
	m.Wait()

	after := decodeBody[appsBody](t, f.do("GET", "/api/apps", nil, withCookie(c)))
	if a := appByID(t, after, "nginx"); !a.Installed || a.Version != "2.4-1" || a.Status != hostapps.ServiceRunning {
		t.Fatalf("nginx after install: %+v", a)
	}
	if j := after.Job; j == nil || j.State != hostapps.JobDone || j.App != "nginx" || j.EndedAt == nil {
		t.Fatalf("job after install: %+v", j)
	}
	if got := auditActions(t, f); !slices.Equal(got, []string{"app.install nginx"}) {
		t.Fatalf("audit = %q", got)
	}
}

func TestAppsFailedInstallIsAudited(t *testing.T) {
	f, m, c := appsFixture(t, &fakeApt{installed: map[string]bool{}, failInstall: true})
	expectStatus(t, f.do("POST", "/api/apps/htop/install", nil, withCookie(c)), http.StatusAccepted)
	m.Wait()
	body := decodeBody[appsBody](t, f.do("GET", "/api/apps", nil, withCookie(c)))
	if j := body.Job; j == nil || j.State != hostapps.JobFailed || !slices.Contains(j.Log, "E: Unable to locate package") {
		t.Fatalf("job = %+v", j)
	}
	if got := auditActions(t, f); !slices.Equal(got, []string{"app.install.fail htop", "app.install htop"}) {
		t.Fatalf("audit = %q", got)
	}
}

func TestAppsRefusals(t *testing.T) {
	f, _, c := appsFixture(t, &fakeApt{installed: map[string]bool{"htop": true}}, 80)
	for _, tc := range []struct {
		name, path string
		status     int
		code       string
		field      string
	}{
		{"unknown app", "/api/apps/sl/install", http.StatusNotFound, codeNotFound, ""},
		{"unknown action", "/api/apps/nginx/purge", http.StatusNotFound, codeNotFound, ""},
		{"port taken", "/api/apps/nginx/install", http.StatusConflict, codeConflict, "port"},
		{"already installed", "/api/apps/htop/install", http.StatusConflict, codeConflict, "state"},
		{"not installed", "/api/apps/vnstat/remove", http.StatusConflict, codeConflict, "state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectError(t, f.do("POST", tc.path, nil, withCookie(c)), tc.status, tc.code, tc.field)
		})
	}
	expectError(t, f.do("POST", "/api/apps/htop/remove", nil), http.StatusUnauthorized, codeUnauthorized, "")
	expectError(t, f.do("GET", "/api/apps", nil), http.StatusUnauthorized, codeUnauthorized, "")
	if got := auditActions(t, f); len(got) != 0 {
		t.Fatalf("refused actions were audited: %q", got)
	}
}

func TestAppsUnsupportedHost(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	body := decodeBody[appsBody](t, f.do("GET", "/api/apps", nil, withCookie(c)))
	if body.Supported || body.Reason != hostapps.ReasonOS || len(body.Apps) != len(hostapps.Catalog) {
		t.Fatalf("body = %+v", body)
	}
	expectError(t, f.do("POST", "/api/apps/htop/install", nil, withCookie(c)), http.StatusConflict, codeConflict, "host")
}
