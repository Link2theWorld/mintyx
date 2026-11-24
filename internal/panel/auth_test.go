package panel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSetupOnlyOnceAndLogsIn(t *testing.T) {
	f := newFixture(t, nil)

	w := f.do("GET", "/api/session", nil)
	expectStatus(t, w, http.StatusOK)
	if got := w.Body.String(); strings.TrimSpace(got) != `{"needsSetup":true,"username":null}` {
		t.Fatalf("session before setup = %s", got)
	}

	c := f.setup()
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure {
		t.Fatalf("cookie attrs HttpOnly=%v SameSite=%v Secure=%v; want true, Strict, false on plain HTTP", c.HttpOnly, c.SameSite, c.Secure)
	}
	w = f.do("GET", "/api/session", nil, withCookie(c))
	if got := strings.TrimSpace(w.Body.String()); got != `{"needsSetup":false,"username":"admin"}` {
		t.Fatalf("session after setup = %s", got)
	}

	w = f.do("POST", "/api/setup", map[string]string{"username": "other", "password": "another long password"})
	expectError(t, w, http.StatusConflict, codeConflict, "")
}

func TestSetupRejectsShortPassword(t *testing.T) {
	f := newFixture(t, nil)
	w := f.do("POST", "/api/setup", map[string]string{"username": "admin", "password": "123456789"})
	expectError(t, w, http.StatusBadRequest, codeInvalid, "password")
}

func TestSecureCookieBehindTrustedTLSProxy(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.TrustProxy = true })
	w := f.do("POST", "/api/setup", map[string]string{"username": testUser, "password": testPassword},
		withHeader("X-Forwarded-Proto", "https"))
	if c := sessionCookieOf(t, w); !c.Secure {
		t.Fatal("cookie lacks Secure although the proxy reports HTTPS")
	}
}

func TestAuthRequired(t *testing.T) {
	f := newFixture(t, nil)
	f.setup()
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/lines"},
		{"GET", "/api/clients"},
		{"POST", "/api/clients"},
		{"GET", "/api/audit"},
		{"PUT", "/api/settings"},
		{"POST", "/api/engine/restart"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := f.do(tc.method, tc.path, map[string]any{"name": "x"})
			expectError(t, w, http.StatusUnauthorized, codeUnauthorized, "")
		})
	}
	w := f.do("GET", "/api/lines", nil, withCookie(&http.Cookie{Name: sessionCookie, Value: "forged"}))
	expectError(t, w, http.StatusUnauthorized, codeUnauthorized, "")
}

func TestCSRFRules(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	body := map[string]any{"name": "phone", "quotaBytes": 0}
	for _, tc := range []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"missing X-Mintyx", []reqOpt{noMintyx()}, http.StatusForbidden},
		{"wrong X-Mintyx", []reqOpt{withHeader("X-Mintyx", "yes")}, http.StatusForbidden},
		{"cross-origin", []reqOpt{withHeader("Origin", "https://evil.test")}, http.StatusForbidden},
		{"same host other port", []reqOpt{withHeader("Origin", "http://panel.test:8080")}, http.StatusForbidden},
		{"null origin", []reqOpt{withHeader("Origin", "null")}, http.StatusForbidden},
		{"same origin", []reqOpt{withHeader("Origin", "http://panel.test")}, http.StatusCreated},
		{"no origin", nil, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body["name"] = "phone " + tc.name
			w := f.do("POST", "/api/clients", body, append([]reqOpt{withCookie(c)}, tc.opts...)...)
			if tc.want == http.StatusForbidden {
				expectError(t, w, tc.want, codeForbidden, "")
				return
			}
			expectStatus(t, w, tc.want)
		})
	}
	// Login is a state change too: a cross-site form must not be able to log the browser in.
	w := f.do("POST", "/api/login", map[string]string{"username": testUser, "password": testPassword}, noMintyx())
	expectError(t, w, http.StatusForbidden, codeForbidden, "")
}

func TestCSRFOriginIncludesScheme(t *testing.T) {
	for _, tc := range []struct {
		name, origin, host    string
		tls, proxy, forwarded bool
		want                  int
	}{
		{"http from https", "https://panel.test", "panel.test", false, false, false, http.StatusForbidden},
		{"https from http", "http://panel.test", "panel.test", true, false, false, http.StatusForbidden},
		{"https default port", "https://panel.test:443", "panel.test", true, false, false, http.StatusCreated},
		{"http default port", "http://panel.test:80", "panel.test", false, false, false, http.StatusCreated},
		{"trusted proxy https", "https://panel.test", "panel.test", false, true, true, http.StatusCreated},
		{"trusted proxy rejects http", "http://panel.test", "panel.test", false, true, true, http.StatusForbidden},
		{"untrusted forwarded https", "https://panel.test", "panel.test", false, false, true, http.StatusForbidden},
		{"different port", "https://panel.test:8443", "panel.test", true, false, false, http.StatusForbidden},
		{"missing origin", "", "panel.test", true, false, false, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(c *Config) { c.TrustProxy = tc.proxy })
			cookie := f.setup()
			w := f.do("POST", "/api/clients", map[string]any{"name": tc.name}, withCookie(cookie),
				withHeader("Origin", tc.origin), func(r *http.Request) {
					r.Host = tc.host
					if tc.tls {
						r.TLS = &tls.ConnectionState{}
					}
					if tc.forwarded {
						r.Header.Set("X-Forwarded-Proto", "https")
					}
				})
			expectStatus(t, w, tc.want)
		})
	}
}

func TestLoginThrottlingPerIP(t *testing.T) {
	f := newFixture(t, nil)
	f.setup()
	attacker := fromAddr("203.0.113.9:5555")
	wrong := map[string]string{"username": testUser, "password": "wrong password!"}
	right := map[string]string{"username": testUser, "password": testPassword}

	for i := range loginMaxFailures {
		w := f.do("POST", "/api/login", wrong, attacker)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, w.Code)
		}
	}
	// Locked out: even the right password is refused without being checked.
	w := f.do("POST", "/api/login", right, attacker)
	expectError(t, w, http.StatusTooManyRequests, codeRateLimited, "")
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}

	w = f.do("POST", "/api/login", right, fromAddr("198.51.100.20:1"))
	expectStatus(t, w, http.StatusNoContent)

	*f.clock = f.clock.Add(loginLockout + time.Second)
	w = f.do("POST", "/api/login", right, attacker)
	expectStatus(t, w, http.StatusNoContent)
}

func TestLoginLimiterFloodCannotGrowMemoryOrBypassThrottle(t *testing.T) {
	l := newLoginLimiter()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < limiterSweepAt+1000; i++ {
		l.fail(fmt.Sprintf("2001:db8::%x", i), now)
	}
	if got := len(l.m); got > limiterSweepAt {
		t.Fatalf("limiter tracks %d addresses after a flood, want at most %d", got, limiterSweepAt)
	}
	if d := l.blocked("2001:db8::ffff", now); d <= 0 {
		t.Fatal("an untracked flood address bypasses the throttle")
	}
}

func TestLoginLimiterFloodDoesNotLockOutATrackedAddress(t *testing.T) {
	l := newLoginLimiter()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	const victim = "198.51.100.7"
	l.fail(victim, now)
	for i := 0; i < limiterSweepAt+1000; i++ {
		l.fail(fmt.Sprintf("2001:db8::%x", i), now)
	}
	if d := l.blocked("2001:db8::ffff", now); d <= 0 {
		t.Fatal("the shared flood bucket is not locked")
	}
	if d := l.blocked(victim, now); d != 0 {
		t.Fatalf("an individually tracked address inherited the flood lockout: %v", d)
	}
}

func TestLoginWrongUsername(t *testing.T) {
	f := newFixture(t, nil)
	f.setup()
	w := f.do("POST", "/api/login", map[string]string{"username": "root", "password": testPassword})
	expectError(t, w, http.StatusUnauthorized, codeUnauthorized, "")
}

func TestForwardedForOnlyWhenTrusted(t *testing.T) {
	for _, tc := range []struct {
		name  string
		trust bool
		want  string
	}{
		{"untrusted ignores header", false, "198.51.100.7"},
		{"trusted takes rightmost entry", true, "192.0.2.50"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, func(c *Config) { c.TrustProxy = tc.trust })
			f.setup()
			f.do("POST", "/api/login", map[string]string{"username": testUser, "password": "nope nope nope"},
				withHeader("X-Forwarded-For", "10.9.9.9, 192.0.2.50"))
			entries, err := f.st.ListAudit(t.Context(), 1, 0)
			if err != nil {
				t.Fatal(err)
			}
			if entries[0].Action != "login.fail" || entries[0].RemoteIP != tc.want {
				t.Fatalf("audit = %+v, want login.fail from %s", entries[0], tc.want)
			}
		})
	}
}

func TestPasswordChangeInvalidatesOtherSessions(t *testing.T) {
	f := newFixture(t, nil)
	a := f.setup()
	w := f.do("POST", "/api/login", map[string]string{"username": testUser, "password": testPassword})
	b := sessionCookieOf(t, w)

	w = f.do("PUT", "/api/password", map[string]string{"current": "not the password", "new": "a brand new password"}, withCookie(a))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "current")

	w = f.do("PUT", "/api/password", map[string]string{"current": testPassword, "new": "short"}, withCookie(a))
	expectError(t, w, http.StatusBadRequest, codeInvalid, "new")

	w = f.do("PUT", "/api/password", map[string]string{"current": testPassword, "new": "a brand new password"}, withCookie(a))
	expectStatus(t, w, http.StatusNoContent)

	expectStatus(t, f.do("GET", "/api/lines", nil, withCookie(a)), http.StatusOK)
	expectError(t, f.do("GET", "/api/lines", nil, withCookie(b)), http.StatusUnauthorized, codeUnauthorized, "")

	w = f.do("POST", "/api/login", map[string]string{"username": testUser, "password": testPassword})
	expectStatus(t, w, http.StatusUnauthorized)
	w = f.do("POST", "/api/login", map[string]string{"username": testUser, "password": "a brand new password"})
	expectStatus(t, w, http.StatusNoContent)
}

func TestLogoutEndsSession(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	expectStatus(t, f.do("POST", "/api/logout", nil, withCookie(c)), http.StatusNoContent)
	expectStatus(t, f.do("GET", "/api/lines", nil, withCookie(c)), http.StatusUnauthorized)
}

func TestSessionExpires(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	*f.clock = f.clock.Add(sessionTTL)
	expectStatus(t, f.do("GET", "/api/lines", nil, withCookie(c)), http.StatusUnauthorized)
}

// The reset runs in another process (`mintyx reset-password`), so it reaches the running
// panel only through the database; sessions opened with the old password must still end.
func TestResetAdminPasswordEndsSessionsOfTheRunningPanel(t *testing.T) {
	f := newFixture(t, nil)
	a := f.setup()
	expectStatus(t, f.do("GET", "/api/lines", nil, withCookie(a)), http.StatusOK)

	user, password, err := ResetAdminPassword(context.Background(), f.st)
	if err != nil {
		t.Fatal(err)
	}
	if user != testUser || validatePassword("new", password) != nil || password == testPassword {
		t.Fatalf("reset gave %q / %q, want the admin account and a usable new password", user, password)
	}

	expectError(t, f.do("GET", "/api/lines", nil, withCookie(a)), http.StatusUnauthorized, codeUnauthorized, "")
	if got := strings.TrimSpace(f.do("GET", "/api/session", nil, withCookie(a)).Body.String()); got != `{"needsSetup":false,"username":null}` {
		t.Fatalf("session with the old cookie = %s, want signed out", got)
	}
	w := f.do("POST", "/api/login", map[string]string{"username": testUser, "password": testPassword})
	expectStatus(t, w, http.StatusUnauthorized)
	w = f.do("POST", "/api/login", map[string]string{"username": testUser, "password": password})
	expectStatus(t, w, http.StatusNoContent)
	expectStatus(t, f.do("GET", "/api/lines", nil, withCookie(sessionCookieOf(t, w))), http.StatusOK)

	entries, err := f.st.ListAudit(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "password.reset" && e.Target == testUser {
			found = true
		}
		if strings.Contains(e.Detail, password) {
			t.Fatalf("the new password ended up in the audit log: %+v", e)
		}
	}
	if !found {
		t.Fatalf("audit = %+v, want a password.reset entry", entries)
	}
}

func TestResetAdminPasswordNeedsAnAdmin(t *testing.T) {
	f := newFixture(t, nil)
	if _, _, err := ResetAdminPassword(context.Background(), f.st); !errors.Is(err, ErrNoAdmin) {
		t.Fatalf("reset before setup = %v, want ErrNoAdmin", err)
	}
	w := f.do("GET", "/api/session", nil)
	if got := strings.TrimSpace(w.Body.String()); got != `{"needsSetup":true,"username":null}` {
		t.Fatalf("session after a refused reset = %s, want setup still open", got)
	}
}
