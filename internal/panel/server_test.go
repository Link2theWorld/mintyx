package panel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func TestRoutingAPIVersusSPA(t *testing.T) {
	f := newFixture(t, nil)
	for _, tc := range []struct {
		name, method, path string
		status             int
		ctype, body        string
	}{
		{"unknown api route", "GET", "/api/x", 404, "application/json; charset=utf-8", `"code":"not_found"`},
		{"unknown nested api route", "GET", "/api/lines/1/x", 404, "application/json; charset=utf-8", `"code":"not_found"`},
		{"spa route", "GET", "/clients", 200, "text/html; charset=utf-8", "<title>Mintyx</title>"},
		{"spa nested route", "GET", "/lines/3/edit", 200, "text/html; charset=utf-8", "<title>Mintyx</title>"},
		{"root", "GET", "/", 200, "text/html; charset=utf-8", "<title>Mintyx</title>"},
		{"asset", "GET", "/assets/app.js", 200, "text/javascript; charset=utf-8", "console.log"},
		{"missing asset is not html", "GET", "/assets/gone.js", 404, "text/plain; charset=utf-8", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do(tc.method, tc.path, nil)
			expectStatus(t, w, tc.status)
			if ct := w.Header().Get("Content-Type"); ct != tc.ctype {
				t.Errorf("content-type = %q, want %q", ct, tc.ctype)
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Errorf("body %q lacks %q", w.Body, tc.body)
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	f := newFixture(t, nil)
	for _, path := range []string{"/api/session", "/clients", "/sub/nope"} {
		w := f.do("GET", path, nil)
		h := w.Header()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" ||
			!strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") ||
			!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: missing security headers: %v", path, h)
		}
		apiLike := !strings.HasPrefix(path, "/clients")
		if got := h.Get("Cache-Control") == "no-store"; got != apiLike {
			t.Errorf("%s: Cache-Control = %q", path, h.Get("Cache-Control"))
		}
	}
}

func TestBodyLimit(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	huge := `{"name":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	expectError(t, f.do("POST", "/api/clients", huge, withCookie(c)), http.StatusBadRequest, codeInvalid, "")
}

func TestAuditEntries(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("POST", "/api/lines", realityLine("tokyo", 443), withCookie(c)), http.StatusCreated)
	const typed = "my-secret-guess-123"
	f.do("POST", "/api/login", map[string]string{"username": testUser, "password": typed})
	expectStatus(t, f.do("PUT", "/api/password", map[string]string{"current": testPassword, "new": "fresh password 456"}, withCookie(c)), http.StatusNoContent)

	w := f.do("GET", "/api/audit?limit=10", nil, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	got := decodeBody[struct{ Entries []auditDTO }](t, w)
	var actions []string
	for _, e := range got.Entries {
		actions = append(actions, e.Action+":"+e.Target)
		if e.RemoteIP != "198.51.100.7" {
			t.Errorf("%s remoteIp = %q", e.Action, e.RemoteIP)
		}
	}
	want := "password.change:admin login.fail:admin line.create:tokyo setup:admin"
	if strings.Join(actions, " ") != want {
		t.Fatalf("audit (newest first) = %v, want %s", actions, want)
	}
	for _, secret := range []string{typed, testPassword, "fresh password 456", "PRIVATEKEY"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("audit leaks %q: %s", secret, w.Body)
		}
	}

	page := decodeBody[struct{ Entries []auditDTO }](t, f.do("GET", "/api/audit?limit=2&before="+itoa(got.Entries[1].ID), nil, withCookie(c)))
	if len(page.Entries) != 2 || page.Entries[0].Action != "line.create" {
		t.Fatalf("second page = %+v", page.Entries)
	}
	expectError(t, f.do("GET", "/api/audit?limit=0", nil, withCookie(c)), http.StatusBadRequest, codeInvalid, "limit")
}

func TestSettingsValidation(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	for _, tc := range []struct {
		body  map[string]string
		field string
	}{
		{map[string]string{"publicHost": "https://vpn.example.com"}, "publicHost"},
		{map[string]string{"subscriptionBaseUrl": "ftp://x"}, "subscriptionBaseUrl"},
		{map[string]string{"subscriptionBaseUrl": "https://x.example.com/?a=b"}, "subscriptionBaseUrl"},
	} {
		expectError(t, f.do("PUT", "/api/settings", tc.body, withCookie(c)), http.StatusBadRequest, codeInvalid, tc.field)
	}
	expectStatus(t, f.do("PUT", "/api/settings", map[string]string{"publicHost": "2001:db8::1"}, withCookie(c)), http.StatusOK)
	got := decodeBody[settingsDTO](t, f.do("GET", "/api/settings", nil, withCookie(c)))
	if got.PublicHost != "2001:db8::1" || got.SubscriptionBaseURL != "" {
		t.Fatalf("settings = %+v", got)
	}
}

func TestEngineAndStatus(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("GET", "/api/engine", nil, withCookie(c))
	if got := strings.TrimSpace(w.Body.String()); got != `{"binaryFound":true,"lastExit":"","pid":42,"restarts":0,"running":true,"startedAt":null,"version":"25.1.1"}` {
		t.Fatalf("engine = %s", got)
	}
	expectStatus(t, f.do("POST", "/api/engine/restart", nil, withCookie(c)), http.StatusNoContent)
	if f.eng.restarts != 1 {
		t.Fatalf("restarts = %d", f.eng.restarts)
	}
	if got := strings.TrimSpace(f.do("GET", "/api/engine/logs", nil, withCookie(c)).Body.String()); got != `{"lines":[]}` {
		t.Fatalf("logs = %s", got)
	}

	f.createClient(c, "a", 0)
	b := f.createClient(c, "b", 0)
	f.do("POST", "/api/clients/"+itoa(b.ID)+"/disable", nil, withCookie(c))
	if err := f.st.AddTraffic(t.Context(), map[int64]model.Traffic{b.ID: {Up: 3, Down: 4}}); err != nil {
		t.Fatal(err)
	}
	st := decodeBody[map[string]any](t, f.do("GET", "/api/status", nil, withCookie(c)))
	if st["clientCount"] != 2.0 || st["activeClientCount"] != 1.0 || st["totalUp"] != 3.0 || st["totalDown"] != 4.0 || st["lineCount"] != 0.0 {
		t.Fatalf("status = %v", st)
	}
}

func noTraffic(context.Context) (map[string]model.Traffic, error) { return nil, nil }

func TestRunnerSyncsOnlyOnChange(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	cl := f.createClient(c, "phone", 100)
	base := f.eng.syncCount()

	r := f.srv.NewRunner(noTraffic, time.Minute)
	if err := r.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.eng.syncCount(); n != base {
		t.Fatalf("idle tick synced (%d -> %d)", base, n)
	}

	over := f.srv.NewRunner(func(context.Context) (map[string]model.Traffic, error) {
		return map[string]model.Traffic{model.Client{ID: cl.ID}.StatsTag(): {Up: 80, Down: 30}}, nil
	}, time.Minute)
	if err := over.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.eng.syncCount(); n != base+1 {
		t.Fatalf("quota-crossing tick: syncs %d -> %d, want one", base, n)
	}
	if got, _ := f.st.GetClient(t.Context(), cl.ID); got.Disabled != model.DisabledQuota || got.UsedUp != 80 {
		t.Fatalf("client after tick = %+v", got)
	}
}

func TestRunnerRetriesFailedSync(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	f.eng.failSync(errors.New("down"))
	f.do("POST", "/api/clients", map[string]any{"name": "phone"}, withCookie(c))
	f.eng.failSync(nil)
	base := f.eng.syncCount()

	r := f.srv.NewRunner(noTraffic, time.Minute)
	if err := r.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := f.eng.syncCount(); n != base+1 {
		t.Fatalf("syncs %d -> %d, want exactly one retry", base, n)
	}
}

func TestRunnerStartStop(t *testing.T) {
	f := newFixture(t, nil)
	ticked := make(chan struct{}, 1)
	r := f.srv.NewRunner(func(context.Context) (map[string]model.Traffic, error) {
		select {
		case ticked <- struct{}{}:
		default:
		}
		return nil, nil
	}, time.Millisecond)
	r.Start(t.Context())
	select {
	case <-ticked:
	case <-time.After(5 * time.Second):
		t.Fatal("runner never ticked")
	}
	r.Stop()
	r.Stop()
}
