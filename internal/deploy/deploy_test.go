package deploy

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/deploy/deploytest"
)

var fakePanelBinary = []byte("\x7fELF pretend panel build")

func fakePayload(arch string) ([]byte, error) { return fakePanelBinary, nil }

type stepLog struct{ events []string }

func (l *stepLog) report(step StepID, status StepStatus, _ string) {
	l.events = append(l.events, string(step)+":"+string(status))
}

// The whole story against a real panel: fresh server in, working share link out, and a second
// run that recognises the server instead of touching its account.
func TestDeployEndToEnd(t *testing.T) {
	v := deploytest.New(t)
	v.Firewall = "ufw"
	kh := testKnownHosts(t)
	target := vpsTarget(v)
	target.Host = "localhost"
	c, err := Dial(testContext(t), target, Options{KnownHosts: kh})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var log stepLog
	res, err := c.Deploy(testContext(t), Request{Region: "jp", PanelBinary: fakePayload, Report: log.report})
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	wantEvents := []string{
		"inspect:running", "inspect:done", "panel:running", "panel:done", "xray:running", "xray:done",
		"service:running", "service:done", "setup:running", "setup:done", "line:running", "line:done",
		"firewall:running", "firewall:done",
	}
	if !slices.Equal(log.events, wantEvents) {
		t.Fatalf("progress = %v\nwant %v", log.events, wantEvents)
	}

	u, err := url.Parse(res.Link)
	if err != nil {
		t.Fatalf("link %q: %v", res.Link, err)
	}
	if u.Scheme != "vless" || u.Hostname() != "localhost" || u.Port() != fmt.Sprint(res.Port) || u.Query().Get("security") != "reality" {
		t.Fatalf("link = %q, want vless://…@localhost:%d with security=reality", res.Link, res.Port)
	}
	if u.Query().Get("sni") != "www.campus.example" || u.Query().Get("pbk") == "" {
		t.Fatalf("link = %q, want the draft's cover site as sni and a public key", res.Link)
	}
	if res.Port != 443 || res.Arch != "amd64" || res.AlreadyDeployed {
		t.Fatalf("result = %+v, want port 443 on amd64, not already deployed", res)
	}
	if res.AdminUser != AdminUser || len(res.AdminPassword) != 24 {
		t.Fatalf("admin = %q with a %d-character password, want %q and 24", res.AdminUser, len(res.AdminPassword), AdminUser)
	}

	if got, _ := v.File(PanelBinaryPath); !bytes.Equal(got, fakePanelBinary) {
		t.Fatalf("installed panel binary = %q, want the payload", got)
	}
	if unit, _ := v.File(UnitPath); !strings.Contains(string(unit), "ExecStart=/usr/local/bin/mintyx -data /var/lib/mintyx -listen 127.0.0.1:8088 -xray /usr/local/lib/mintyx/xray\n") {
		t.Fatalf("unit file does not start the panel on loopback:\n%s", unit)
	}
	if v.XrayVersion() != XrayVersion {
		t.Fatalf("installed Xray %q, want %q", v.XrayVersion(), XrayVersion)
	}
	if got := v.OpenedPorts(); !slices.Equal(got, []string{"443/tcp"}) {
		t.Fatalf("firewall opened %v, want only the line's port 443/tcp", got)
	}

	// The password in the result must be the one the panel really has.
	p := c.panel()
	defer p.close()
	if err := p.do(testContext(t), http.MethodPost, "/api/login", map[string]string{"username": res.AdminUser, "password": res.AdminPassword}, nil); err != nil {
		t.Fatalf("login with the returned password: %v", err)
	}
	var settings struct{ PublicHost string }
	if err := p.do(testContext(t), http.MethodGet, "/api/settings", nil, &settings); err != nil || settings.PublicHost != "localhost" {
		t.Fatalf("publicHost = %q (err %v), want the address the user typed", settings.PublicHost, err)
	}

	t.Run("second run reports already deployed and changes nothing", func(t *testing.T) {
		var log stepLog
		again, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload, Report: log.report})
		if err != nil {
			t.Fatalf("Deploy: %v", err)
		}
		if !again.AlreadyDeployed || again.AdminPassword != "" || again.Link != "" {
			t.Fatalf("result = %+v, want only AlreadyDeployed", again)
		}
		wantTail := []string{"service:done", "setup:skipped", "line:skipped", "firewall:skipped"}
		if n := len(log.events); n < 4 || !slices.Equal(log.events[n-4:], wantTail) {
			t.Fatalf("progress = %v, want it to end with %v", log.events, wantTail)
		}
		if v.Uploads() != 1 {
			t.Fatalf("the panel binary was uploaded %d times, want once", v.Uploads())
		}
		if got := v.OpenedPorts(); len(got) != 1 {
			t.Fatalf("firewall rules after the second run: %v, want still one", got)
		}
	})
}

func TestDeployStopsEarlyOnAnUnsuitableServer(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*deploytest.VPS)
		reason string
	}{
		{"not Linux", func(v *deploytest.VPS) { v.OS = "FreeBSD" }, "it runs FreeBSD, not Linux"},
		{"32-bit ARM", func(v *deploytest.VPS) { v.Machine = "armv7l" }, "its CPU is armv7l; only x86_64 and arm64 are supported"},
		{"no systemd", func(v *deploytest.VPS) { v.Systemd = false }, "it does not use systemd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := deploytest.New(t)
			tt.setup(v)
			c := dialVPS(t, v, testKnownHosts(t))
			_, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload})
			var unsupported *UnsupportedError
			if !errors.As(err, &unsupported) || unsupported.Reason != tt.reason {
				t.Fatalf("err = %v, want UnsupportedError %q", err, tt.reason)
			}
			if names := v.RanNames(); !slices.Equal(names, []string{"inspect"}) {
				t.Fatalf("scripts run = %v, want only inspect", names)
			}
		})
	}
}

func TestDeployPicksThePayloadForTheServerCPU(t *testing.T) {
	v := deploytest.New(t)
	v.Machine = "aarch64"
	c := dialVPS(t, v, testKnownHosts(t))
	var asked []string
	res, err := c.Deploy(testContext(t), Request{PanelBinary: func(arch string) ([]byte, error) {
		asked = append(asked, arch)
		return fakePanelBinary, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(asked, []string{"arm64"}) || res.Arch != "arm64" {
		t.Fatalf("payload asked for %v, result arch %q; want arm64", asked, res.Arch)
	}
	for _, r := range v.Ran() {
		if r.Name == "xray-install" && r.Vars["ASSET"] != "Xray-linux-arm64-v8a.zip" {
			t.Fatalf("Xray asset = %q, want the arm64 one", r.Vars["ASSET"])
		}
	}
}

// A build without the payload must say so before it has changed anything on the server.
func TestDeployWithoutPayloadChangesNothing(t *testing.T) {
	v := deploytest.New(t)
	c := dialVPS(t, v, testKnownHosts(t))
	var log stepLog
	_, err := c.Deploy(testContext(t), Request{Report: log.report, PanelBinary: func(string) ([]byte, error) { return nil, ErrNoPayload }})
	if !errors.Is(err, ErrNoPayload) {
		t.Fatalf("err = %v, want ErrNoPayload", err)
	}
	if names := v.RanNames(); !slices.Equal(names, []string{"inspect"}) {
		t.Fatalf("scripts run = %v, want only inspect", names)
	}
	if want := []string{"inspect:running", "inspect:failed"}; !slices.Equal(log.events, want) {
		t.Fatalf("progress = %v, want %v", log.events, want)
	}
}

// Once setup has run the password exists only in the result; an error in a later step must not lose it.
func TestDeployKeepsThePasswordWhenALaterStepFails(t *testing.T) {
	v := deploytest.New(t)
	v.CoverSite = ""
	c := dialVPS(t, v, testKnownHosts(t))
	res, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload})
	if !errors.Is(err, ErrNoCoverSite) {
		t.Fatalf("err = %v, want ErrNoCoverSite", err)
	}
	if res == nil || len(res.AdminPassword) != 24 {
		t.Fatalf("result = %+v, want the admin password that was already set", res)
	}
}

// A retry after a failure past the setup step must finish the job with the password it set,
// not mistake its own panel for someone else's and skip the line and firewall.
func TestDeployRetryFinishesWithTheEarlierPassword(t *testing.T) {
	v := deploytest.New(t)
	v.Firewall = "ufw"
	v.CoverSite = ""
	c := dialVPS(t, v, testKnownHosts(t))
	first, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload})
	if !errors.Is(err, ErrNoCoverSite) || first == nil || first.AdminPassword == "" {
		t.Fatalf("first run: %+v, %v; want ErrNoCoverSite with a password", first, err)
	}

	v.Set(func(v *deploytest.VPS) { v.CoverSite = "www.campus.example" })
	var log stepLog
	res, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload, AdminPassword: first.AdminPassword, Report: log.report})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if res.AlreadyDeployed || res.AdminPassword != first.AdminPassword || !strings.HasPrefix(res.Link, "vless://") {
		t.Fatalf("retry result = %+v, want the same password and a link", res)
	}
	if !slices.Contains(log.events, "firewall:done") || len(v.OpenedPorts()) != 1 {
		t.Fatalf("retry progress %v, opened ports %v; want the firewall step done once", log.events, v.OpenedPorts())
	}

	// Running it once more reuses the line and client instead of adding new ones.
	again, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload, AdminPassword: first.AdminPassword})
	if err != nil || again.Link != res.Link {
		t.Fatalf("third run = %+v, %v; want the same link %q", again, err, res.Link)
	}
}

func TestDeployGivesUpWhenThePanelNeverAnswers(t *testing.T) {
	v := deploytest.New(t)
	// Nothing answers on any forwarded address, as if the service crashed on start.
	v.SSH.Forward(nil)
	c := dialVPS(t, v, testKnownHosts(t))
	_, err := c.Deploy(testContext(t), Request{PanelBinary: fakePayload, PanelWait: 300 * time.Millisecond})
	if !errors.Is(err, ErrPanelNotAnswering) {
		t.Fatalf("err = %v, want ErrPanelNotAnswering", err)
	}
	if !strings.Contains(err.Error(), "(fake journal)") {
		t.Fatalf("err = %v, want the service log in it", err)
	}
}

func TestDeployRejectsUnknownRegion(t *testing.T) {
	v := deploytest.New(t)
	c := dialVPS(t, v, testKnownHosts(t))
	if _, err := c.Deploy(testContext(t), Request{Region: "mars", PanelBinary: fakePayload}); err == nil || err.Error() != `unknown region "mars"` {
		t.Fatalf("err = %v, want unknown region", err)
	}
	if len(v.Ran()) != 0 {
		t.Fatalf("scripts ran for an invalid request: %v", v.RanNames())
	}
}
