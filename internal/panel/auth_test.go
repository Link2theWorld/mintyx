package panel

import (
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
