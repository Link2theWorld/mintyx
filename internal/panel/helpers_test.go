package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ysuhao/mintyx-next/internal/hostapps"
	"github.com/ysuhao/mintyx-next/internal/store"
)

type fakeEngine struct {
	mu       sync.Mutex
	syncs    int
	syncErr  error
	restarts int
}

func (e *fakeEngine) Sync(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.syncs++
	return e.syncErr
}

func (e *fakeEngine) Restart(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.restarts++
	return nil
}

func (e *fakeEngine) Status(context.Context) EngineStatus {
	return EngineStatus{Running: true, PID: 42, Version: "25.1.1", BinaryFound: true}
}

func (e *fakeEngine) Logs() []string { return nil }

func (e *fakeEngine) syncCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.syncs
}

func (e *fakeEngine) failSync(err error) {
	e.mu.Lock()
	e.syncErr = err
	e.mu.Unlock()
}

// fakeKeys is deterministic so tests can tell which key pair a line carries.
type fakeKeys struct {
	mu sync.Mutex
	n  int
}

func (k *fakeKeys) next() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.n++
	return k.n
}

func (k *fakeKeys) NewUUID() string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", k.next())
}

func (k *fakeKeys) NewRealityKeyPair() (string, string, error) {
	n := k.next()
	return fmt.Sprintf("PRIVATEKEY%d", n), fmt.Sprintf("pub%d", n), nil
}

func (k *fakeKeys) NewShortID() string  { return fmt.Sprintf("%016x", k.next()) }
func (k *fakeKeys) NewPassword() string { return fmt.Sprintf("pw%d", k.next()) }

type fixture struct {
	t     *testing.T
	srv   *Server
	st    *store.Store
	eng   *fakeEngine
	clock *time.Time
}

const (
	testHost     = "panel.test"
	testUser     = "admin"
	testPassword = "correct horse battery"
)

var testStatic = fstest.MapFS{
	"index.html":    {Data: []byte("<!doctype html><title>Mintyx</title>")},
	"assets/app.js": {Data: []byte("console.log(1)")},
}

func newFixture(t *testing.T, mod func(*Config)) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	eng := &fakeEngine{}
	cfg := Config{Store: st, Engine: eng, Keys: &fakeKeys{}, Static: testStatic, ReservedPorts: []int{2096},
		// No test may reach the real package manager.
		Apps: hostapps.New(hostapps.Options{Unsupported: func() string { return hostapps.ReasonOS }}),
		CoverSite: func(_ context.Context, region string) string {
			if region == "" {
				return "www.campus.example"
			}
			return "www." + region + ".example"
		}}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv.bcryptCost = bcrypt.MinCost
	clock := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	f := &fixture{t: t, srv: srv, st: st, eng: eng, clock: &clock}
	srv.now = func() time.Time { return *f.clock }
	return f
}

type reqOpt func(*http.Request)

func withCookie(c *http.Cookie) reqOpt { return func(r *http.Request) { r.AddCookie(c) } }
func withHeader(k, v string) reqOpt    { return func(r *http.Request) { r.Header.Set(k, v) } }
func fromAddr(a string) reqOpt         { return func(r *http.Request) { r.RemoteAddr = a } }
func noMintyx() reqOpt                 { return func(r *http.Request) { r.Header.Del("X-Mintyx") } }

func (f *fixture) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	f.t.Helper()
	var buf bytes.Buffer
	switch b := body.(type) {
	case nil:
	case string:
		buf.WriteString(b)
	default:
		if err := json.NewEncoder(&buf).Encode(b); err != nil {
			f.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	r.Host = testHost
	r.RemoteAddr = "198.51.100.7:40000"
	r.Header.Set("X-Mintyx", "1")
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, r)
	return w
}

func sessionCookieOf(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in response (status %d, body %s)", w.Code, w.Body)
	return nil
}

// setup creates the admin and returns its session cookie.
func (f *fixture) setup() *http.Cookie {
	f.t.Helper()
	w := f.do("POST", "/api/setup", map[string]string{"username": testUser, "password": testPassword})
	if w.Code != http.StatusNoContent {
		f.t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	return sessionCookieOf(f.t, w)
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body)
	}
}

func expectError(t *testing.T, w *httptest.ResponseRecorder, status int, code, field string) {
	t.Helper()
	expectStatus(t, w, status)
	var b errorBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("error body %q: %v", w.Body, err)
	}
	if b.Error.Code != code || b.Error.Field != field {
		t.Fatalf("error = {code %q, field %q}, want {%q, %q}; message %q", b.Error.Code, b.Error.Field, code, field, b.Error.Message)
	}
}

func decodeBody[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body, err)
	}
	return v
}

func realityLine(name string, port int) map[string]any {
	return map[string]any{
		"name": name, "protocol": "vless-reality", "port": port, "enabled": true,
		"reality": map[string]any{"shortId": "abcd", "serverName": "www.example.com", "target": "www.example.com:443"},
	}
}

func (f *fixture) createClient(c *http.Cookie, name string, quota int64) clientDTO {
	f.t.Helper()
	w := f.do("POST", "/api/clients", map[string]any{"name": name, "quotaBytes": quota, "expiresAt": nil}, withCookie(c))
	expectStatus(f.t, w, http.StatusCreated)
	return decodeBody[clientDTO](f.t, w)
}
