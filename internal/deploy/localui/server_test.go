package localui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/deploy"
	"github.com/ysuhao/mintyx-next/internal/deploy/deploytest"
)

type fixture struct {
	t   *testing.T
	srv *Server
	hs  *httptest.Server
	kh  *deploy.KnownHosts
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	kh := deploy.OpenKnownHosts(filepath.Join(t.TempDir(), "known_hosts.json"))
	hs := httptest.NewUnstartedServer(nil)
	srv, err := New(Config{
		KnownHosts:   kh,
		KeyDir:       filepath.Join(t.TempDir(), ".ssh"),
		PanelBinary:  func(string) ([]byte, error) { return []byte("pretend panel"), nil },
		PayloadArchs: []string{"amd64", "arm64"},
	}, hs.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	hs.Config.Handler = srv
	hs.Start()
	t.Cleanup(func() { srv.Close(); hs.Close() })
	return &fixture{t: t, srv: srv, hs: hs, kh: kh}
}

type reqOpt func(*http.Request)

func noToken() reqOpt            { return func(r *http.Request) { r.Header.Del(TokenHeader) } }
func token(v string) reqOpt      { return func(r *http.Request) { r.Header.Set(TokenHeader, v) } }
func hostHeader(v string) reqOpt { return func(r *http.Request) { r.Host = v } }
func origin(v string) reqOpt     { return func(r *http.Request) { r.Header.Set("Origin", v) } }

func (f *fixture) do(method, path string, body any, opts ...reqOpt) *http.Response {
	f.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			f.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, f.hs.URL+path, &buf)
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set(TokenHeader, f.srv.token)
	for _, o := range opts {
		o(req)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func decodeBody[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	var v T
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode %q: %v", data, err)
	}
	return v
}

func expectError(t *testing.T, resp *http.Response, status int, code string) apiError {
	t.Helper()
	body := decodeBody[map[string]apiError](t, resp)
	if resp.StatusCode != status || body["error"].Code != code {
		t.Fatalf("got %d %+v, want %d with code %q", resp.StatusCode, body["error"], status, code)
	}
	return body["error"]
}

func TestGuard(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name   string
		method string
		path   string
		opts   []reqOpt
		status int
		code   string
	}{
		{"API without the token", "GET", "/api/state", []reqOpt{noToken()}, 401, "unauthorized"},
		{"API with a wrong token", "GET", "/api/state", []reqOpt{token("guess")}, 403, "forbidden"},
		{"mutation without the token", "POST", "/api/disconnect", []reqOpt{noToken()}, 401, "unauthorized"},
		{"foreign Host, as in DNS rebinding", "GET", "/api/state", []reqOpt{hostHeader("evil.example:80")}, 403, "forbidden"},
		{"localhost is not the address served", "GET", "/api/state", []reqOpt{hostHeader("localhost:1")}, 403, "forbidden"},
		{"page under a foreign Host", "GET", "/", []reqOpt{hostHeader("evil.example"), noToken()}, 403, "forbidden"},
		{"request from another site that somehow has the token", "POST", "/api/disconnect", []reqOpt{origin("https://evil.example")}, 403, "forbidden"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := f.do(tt.method, tt.path, nil, tt.opts...)
			expectError(t, resp, tt.status, tt.code)
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
				t.Fatalf("Access-Control-Allow-Origin = %q, want no CORS at all", got)
			}
		})
	}

	t.Run("the right token and Host get through", func(t *testing.T) {
		resp := f.do("GET", "/api/state", nil, origin(f.hs.URL))
		st := decodeBody[stateDTO](t, resp)
		if resp.StatusCode != 200 || st.Connection != nil || !slices.Equal(st.Payload, []string{"amd64", "arm64"}) {
			t.Fatalf("status %d, state %+v; want 200, no connection, both payloads", resp.StatusCode, st)
		}
	})

	t.Run("a preflight gets no permission", func(t *testing.T) {
		resp := f.do("OPTIONS", "/api/connect", nil, noToken(), origin("https://evil.example"))
		if resp.StatusCode != 401 || resp.Header.Get("Access-Control-Allow-Headers") != "" {
			t.Fatalf("OPTIONS = %d with Allow-Headers %q, want 401 and none", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Headers"))
		}
	})
}

func TestURLCarriesTheTokenInTheFragment(t *testing.T) {
	f := newFixture(t)
	u, err := url.Parse(f.srv.URL())
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != f.hs.Listener.Addr().String() || u.Fragment != "t="+f.srv.token || u.RawQuery != "" || len(f.srv.token) != 43 {
		t.Fatalf("URL = %q, want http://<listener>/#t=<43-character token>", f.srv.URL())
	}
}

var urlPattern = regexp.MustCompile(`(?i)(https?:)?//[a-z0-9][^\s"'<>)]*`)

// The page must work offline and must not make the browser contact anyone: the only
// addresses in it are the owner's three guides, and those are plain links the user clicks.
func TestPageIsSelfContained(t *testing.T) {
	f := newFixture(t)
	resp := f.do("GET", "/", nil, noToken())
	data, _ := io.ReadAll(resp.Body)
	page := string(data)
	if resp.StatusCode != 200 {
		t.Fatalf("GET / = %d", resp.StatusCode)
	}

	csp := resp.Header.Get("Content-Security-Policy")
	nonce := regexp.MustCompile(`script-src 'nonce-([A-Za-z0-9+/]+)'`).FindStringSubmatch(csp)
	if nonce == nil || !strings.HasPrefix(csp, "default-src 'none';") || !strings.Contains(csp, "connect-src 'self'") {
		t.Fatalf("CSP = %q, want default-src 'none', a script nonce and connect-src 'self'", csp)
	}
	if !strings.Contains(page, `<script nonce="`+nonce[1]+`">`) || strings.Contains(page, noncePattern) {
		t.Fatal("the page's script does not carry the nonce from the CSP header")
	}

	var urls []string
	for _, u := range urlPattern.FindAllString(page, -1) {
		if !slices.Contains(urls, u) {
			urls = append(urls, u)
		}
	}
	slices.Sort(urls)
	want := []string{"https://fand.dev/go/mintyx-clients", "https://fand.dev/go/mintyx-security", "https://fand.dev/go/mintyx-ssh-key"}
	if !slices.Equal(urls, want) {
		t.Fatalf("addresses in the page = %q\nwant only %q", urls, want)
	}
	for _, u := range want {
		if n := strings.Count(page, u); n != 1 {
			t.Errorf("%s appears %d times, want it defined in one place", u, n)
		}
	}
	for _, loader := range []string{"<link", "<script src", "<img src=\"http", "<iframe", "@import", "url(", "@font-face", "sendBeacon", "new WebSocket", "EventSource("} {
		if strings.Contains(page, loader) {
			t.Errorf("the page contains %q, which loads or contacts something", loader)
		}
	}
	if strings.Contains(page, f.srv.token) {
		t.Fatal("the token is baked into the page; it must only travel in the URL fragment")
	}
}

func connectBody(v *deploytest.VPS) map[string]any {
	return map[string]any{"host": "127.0.0.1", "port": v.SSH.Port(), "user": deploytest.User, "password": deploytest.Password}
}

func (f *fixture) waitForDeploy() *jobState {
	f.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		st := decodeBody[stateDTO](f.t, f.do("GET", "/api/state", nil))
		if st.Deploy != nil && !st.Deploy.Running {
			return st.Deploy
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatal("deploy did not finish")
	return nil
}

func TestConnectErrorsHaveDistinctCodes(t *testing.T) {
	f := newFixture(t)
	v := deploytest.New(t)

	wrong := connectBody(v)
	wrong["password"] = "nope"
	expectError(t, f.do("POST", "/api/connect", wrong), 401, "auth")

	expectError(t, f.do("POST", "/api/connect", map[string]any{"host": "", "password": "x"}), 400, "invalid")
	expectError(t, f.do("POST", "/api/deploy", map[string]any{"region": "jp"}), 409, "not_connected")

	v.Set(func(v *deploytest.VPS) { v.SudoPassword = "" })
	expectError(t, f.do("POST", "/api/connect", connectBody(v)), 403, "needs_root")
	v.Set(func(v *deploytest.VPS) { v.SudoPassword = deploytest.Password })

	known := v.SSH.HostKeyFingerprint()
	v.SSH.RotateHostKey()
	e := expectError(t, f.do("POST", "/api/connect", connectBody(v)), 409, "host_key_changed")
	if e.Known != known || e.Presented != v.SSH.HostKeyFingerprint() {
		t.Fatalf("fingerprints = known %q presented %q, want %q and %q", e.Known, e.Presented, known, v.SSH.HostKeyFingerprint())
	}

	if resp := f.do("POST", "/api/forget-host", connectBody(v)); resp.StatusCode != 204 {
		t.Fatalf("forget-host = %d, want 204", resp.StatusCode)
	}
	resp := f.do("POST", "/api/connect", connectBody(v))
	conn := decodeBody[connectionDTO](t, resp)
	if resp.StatusCode != 200 || !conn.FirstSeen || conn.Fingerprint != v.SSH.HostKeyFingerprint() || conn.Root {
		t.Fatalf("connect after forgetting = %d %+v, want 200, first seen, the new fingerprint, not root", resp.StatusCode, conn)
	}
}

// The browser's whole journey over HTTP: connect, deploy, save the password, open the panel, key login.
func TestFlowThroughTheAPI(t *testing.T) {
	f := newFixture(t)
	v := deploytest.New(t)

	if resp := f.do("POST", "/api/connect", connectBody(v)); resp.StatusCode != 200 {
		t.Fatalf("connect = %d", resp.StatusCode)
	}
	if resp := f.do("POST", "/api/deploy", map[string]any{"region": "unsure", "clientName": "我的设备"}); resp.StatusCode != 202 {
		t.Fatalf("deploy = %d", resp.StatusCode)
	}
	job := f.waitForDeploy()
	if job.Error != nil || job.Result == nil {
		t.Fatalf("job = %+v, error %+v", job, job.Error)
	}
	res := job.Result
	if !strings.HasPrefix(res.Link, "vless://") || !strings.Contains(res.Link, "@127.0.0.1:443?") || !strings.Contains(res.Link, "security=reality") {
		t.Fatalf("link = %q, want a vless REALITY link to 127.0.0.1:443", res.Link)
	}
	if !strings.HasPrefix(res.QRSVG, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 `) || strings.Count(res.QRSVG, "h1v1h-1z") < 400 {
		t.Fatalf("QR code is not a drawn SVG: %.80q…", res.QRSVG)
	}
	if len(res.AdminPassword) != 24 || res.AdminUser != "admin" {
		t.Fatalf("admin = %q / %d-character password", res.AdminUser, len(res.AdminPassword))
	}
	for _, s := range job.Steps {
		if s.Status != deploy.StatusDone {
			t.Fatalf("step %s is %q, want done; steps %+v", s.ID, s.Status, job.Steps)
		}
	}

	t.Run("the password is forgotten once the user has saved it", func(t *testing.T) {
		if resp := f.do("POST", "/api/password-saved", nil); resp.StatusCode != 204 {
			t.Fatalf("password-saved = %d", resp.StatusCode)
		}
		st := decodeBody[stateDTO](t, f.do("GET", "/api/state", nil))
		if st.Deploy.Result.AdminPassword != "" || st.Deploy.Result.Link != res.Link {
			t.Fatalf("after saving: password %q, link %q; want no password and the same link", st.Deploy.Result.AdminPassword, st.Deploy.Result.Link)
		}
	})

	t.Run("open panel starts a tunnel to the server's loopback", func(t *testing.T) {
		out := decodeBody[map[string]string](t, f.do("POST", "/api/tunnel", nil))
		resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second}).Get(out["url"] + "api/session")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if want := `{"needsSetup":false,"username":null}`; strings.TrimSpace(string(body)) != want {
			t.Fatalf("panel through the tunnel answered %q, want %q", body, want)
		}
		again := decodeBody[map[string]string](t, f.do("POST", "/api/tunnel", nil))
		if again["url"] != out["url"] {
			t.Fatalf("a second click opened another tunnel: %q then %q", out["url"], again["url"])
		}
	})

	t.Run("key login turns passwords off", func(t *testing.T) {
		out := decodeBody[keyLoginDTO](t, f.do("POST", "/api/key-login", nil))
		if out.Outcome != "done" || !out.PasswordOff || filepath.Base(out.KeyPath) != "mintyx_127.0.0.1_ed25519" {
			t.Fatalf("key login = %+v, want done with passwords off", out)
		}
		if !v.SSH.PasswordDisabled() {
			t.Fatal("the server still accepts passwords")
		}
	})

	t.Run("disconnect drops everything", func(t *testing.T) {
		f.do("POST", "/api/disconnect", nil)
		st := decodeBody[stateDTO](t, f.do("GET", "/api/state", nil))
		if st.Connection != nil || st.Deploy != nil || st.TunnelURL != "" || st.KeyLogin != nil {
			t.Fatalf("state after disconnect = %+v, want empty", st)
		}
	})
}

func TestKeyLoginOutcomesReachThePage(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*deploytest.VPS)
		outcome string
		hasKey  bool
	}{
		{"key never worked", func(v *deploytest.VPS) { v.IgnoreAuthorizedKeys = true }, "never-worked", false},
		{"rolled back", func(v *deploytest.VPS) { v.BreakKeysWithPasswords = true }, "rolled-back", true},
		{"another config keeps passwords", func(v *deploytest.VPS) { v.OtherConfigKeepsPasswords = true }, "still-on", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			v := deploytest.New(t)
			tt.setup(v)
			if resp := f.do("POST", "/api/connect", connectBody(v)); resp.StatusCode != 200 {
				t.Fatalf("connect = %d", resp.StatusCode)
			}
			out := decodeBody[keyLoginDTO](t, f.do("POST", "/api/key-login", nil))
			if out.Outcome != tt.outcome || out.PasswordOff || (out.KeyPath != "") != tt.hasKey {
				t.Fatalf("key login = %+v, want outcome %q, passwords still on, key saved: %v", out, tt.outcome, tt.hasKey)
			}
			if v.SSH.PasswordDisabled() {
				t.Fatal("password login is off although the outcome says it is not")
			}
		})
	}
}

// A deploy that set the password and then failed must keep it through the retry,
// and the page must not be able to drop it by disconnecting.
func TestRetryKeepsTheUnsavedPassword(t *testing.T) {
	f := newFixture(t)
	v := deploytest.New(t)
	v.CoverSite = ""
	if resp := f.do("POST", "/api/connect", connectBody(v)); resp.StatusCode != 200 {
		t.Fatalf("connect = %d", resp.StatusCode)
	}
	f.do("POST", "/api/deploy", map[string]any{"region": "unsure"})
	first := f.waitForDeploy()
	if first.Error == nil || first.Result == nil || len(first.Result.AdminPassword) != 24 {
		t.Fatalf("first run = %+v / %+v, want an error with the password", first.Error, first.Result)
	}
	password := first.Result.AdminPassword

	if resp := f.do("POST", "/api/disconnect", nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("disconnect with an unsaved password = %d, want 409", resp.StatusCode)
	}

	v.Set(func(v *deploytest.VPS) { v.CoverSite = "www.campus.example" })
	f.do("POST", "/api/deploy", map[string]any{"region": "unsure"})
	retry := f.waitForDeploy()
	if retry.Error != nil || retry.Result == nil {
		t.Fatalf("retry = %+v / %+v", retry.Error, retry.Result)
	}
	if retry.Result.AlreadyDeployed || retry.Result.AdminPassword != password || !strings.HasPrefix(retry.Result.Link, "vless://") {
		t.Fatalf("retry result = %+v, want the first password and a link", retry.Result)
	}

	f.do("POST", "/api/password-saved", nil)
	if resp := f.do("POST", "/api/disconnect", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disconnect after saving = %d, want 204", resp.StatusCode)
	}
}
