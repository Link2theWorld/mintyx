// Package localui is the page the deployer shows in the user's own browser, and the
// loopback-only API behind it.
package localui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "embed"

	"github.com/ysuhao/mintyx-next/internal/deploy"
)

//go:embed page.html
var pageHTML []byte

const (
	// TokenHeader carries the per-run secret; a page from another site cannot read it or set it.
	TokenHeader  = "X-Mintyx-Deploy"
	noncePattern = "__NONCE__"
	maxBody      = 64 << 10

	connectTimeout  = 40 * time.Second
	deployTimeout   = 20 * time.Minute
	keyLoginTimeout = 2 * time.Minute
)

type Config struct {
	KnownHosts *deploy.KnownHosts
	// KeyDir is where key login saves the new private key, normally ~/.ssh.
	KeyDir string
	// PanelBinary supplies the panel build for the server's CPU.
	PanelBinary func(arch string) ([]byte, error)
	// PayloadArchs lists the CPUs PanelBinary can serve, so the page can warn before connecting.
	PayloadArchs []string
	Logger       *slog.Logger
}

type Server struct {
	cfg   Config
	host  string
	token string
	log   *slog.Logger

	mu       sync.Mutex
	client   *deploy.Client
	conn     *connectionDTO
	job      *jobState
	cancel   context.CancelFunc
	tunnel   *deploy.Forwarder
	keyLogin *keyLoginDTO
	// busy is set while a connect or key-login request is in flight.
	busy bool
	// unsavedPassword is the panel password a deploy set on unsavedAddr and the user has not yet
	// confirmed saving. It outlives a failed run so a retry can finish with it, and while it is
	// held the page may not drop the connection or move to another server.
	unsavedPassword, unsavedAddr string
}

// New builds the handler for a listener on addr ("127.0.0.1:port"); requests for any other Host are refused.
func New(cfg Config, addr string) (*Server, error) {
	if cfg.KnownHosts == nil || cfg.PanelBinary == nil || cfg.KeyDir == "" {
		return nil, errors.New("localui: KnownHosts, PanelBinary and KeyDir are required")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, host: addr, token: base64.RawURLEncoding.EncodeToString(raw[:]), log: cfg.Logger}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// URL is what the user's browser opens. The token sits in the fragment, which browsers
// never send to a server and never put in a Referer.
func (s *Server) URL() string { return "http://" + s.host + "/#t=" + s.token }

// Close drops the SSH connection and with it every credential held in memory.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.disconnectLocked()
	s.unsavedPassword, s.unsavedAddr = "", ""
}

var errPasswordUnsaved = apiError{Code: "password_unsaved", Message: "save the panel password shown on the page first"}

// holdsPasswordForOtherThan reports whether an unsaved password would be lost by leaving for addr ("" for none).
func (s *Server) holdsPasswordForOtherThan(addr string) bool {
	return s.unsavedPassword != "" && s.unsavedAddr != addr
}

func (s *Server) disconnectLocked() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.tunnel != nil {
		s.tunnel.Close()
		s.tunnel = nil
	}
	if s.client != nil {
		_ = s.client.Close()
		s.client = nil
	}
	s.conn, s.job, s.keyLogin = nil, nil, nil
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
	// Known and Presented are the two fingerprints of a host_key_changed error.
	Known     string   `json:"known,omitempty"`
	Presented string   `json:"presented,omitempty"`
	Files     []string `json:"files,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, e apiError) {
	writeJSON(w, status, map[string]apiError{"error": e})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")

	// A DNS-rebinding page reaches this port under its own host name; only the literal address is served.
	if r.Host != s.host {
		writeErr(w, http.StatusForbidden, apiError{Code: "forbidden", Message: "this address is not served"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		s.servePage(w, r)
		return
	}
	token := r.Header.Get(TokenHeader)
	if token == "" {
		writeErr(w, http.StatusUnauthorized, apiError{Code: "unauthorized", Message: "missing " + TokenHeader + " header"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
		writeErr(w, http.StatusForbidden, apiError{Code: "forbidden", Message: "wrong token"})
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != "http://"+s.host {
		writeErr(w, http.StatusForbidden, apiError{Code: "forbidden", Message: "cross-origin request"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	switch r.Method + " " + r.URL.Path {
	case "GET /api/state":
		s.getState(w, r)
	case "POST /api/connect":
		s.postConnect(w, r)
	case "POST /api/forget-host":
		s.postForgetHost(w, r)
	case "POST /api/disconnect":
		s.mu.Lock()
		if s.holdsPasswordForOtherThan("") {
			s.mu.Unlock()
			writeErr(w, http.StatusConflict, errPasswordUnsaved)
			return
		}
		s.disconnectLocked()
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	case "POST /api/deploy":
		s.postDeploy(w, r)
	case "POST /api/password-saved":
		s.postPasswordSaved(w, r)
	case "POST /api/tunnel":
		s.postTunnel(w, r)
	case "POST /api/key-login":
		s.postKeyLogin(w, r)
	default:
		writeErr(w, http.StatusNotFound, apiError{Code: "not_found", Message: "no such endpoint"})
	}
}

func (s *Server) servePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	nonce := base64.RawStdEncoding.EncodeToString(raw[:])
	// Nothing may load from anywhere else: no CDN, no fonts, no analytics.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+
		"'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(bytes.ReplaceAll(pageHTML, []byte(noncePattern), []byte(nonce)))
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	data, err := io.ReadAll(r.Body)
	if err == nil && len(bytes.TrimSpace(data)) > 0 {
		err = json.Unmarshal(data, v)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, apiError{Code: "invalid", Message: "malformed request body"})
		return false
	}
	return true
}

type connectionDTO struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	Root        bool   `json:"root"`
	Fingerprint string `json:"fingerprint"`
	FirstSeen   bool   `json:"firstSeen"`
	// PasswordLogin is false when the user connected with a key and gave no password.
	PasswordLogin bool `json:"passwordLogin"`
}

type stepDTO struct {
	ID     deploy.StepID     `json:"id"`
	Status deploy.StepStatus `json:"status"`
	Detail string            `json:"detail"`
}

type resultDTO struct {
	AlreadyDeployed bool   `json:"alreadyDeployed"`
	Arch            string `json:"arch"`
	AdminUser       string `json:"adminUser"`
	// AdminPassword is served until the user confirms having saved it, then wiped from memory.
	AdminPassword string `json:"adminPassword"`
	Link          string `json:"link"`
	QRSVG         string `json:"qrSvg"`
	LineName      string `json:"lineName"`
	Port          int    `json:"port"`
	Firewall      string `json:"firewall"`
}

type jobState struct {
	Running bool       `json:"running"`
	Steps   []stepDTO  `json:"steps"`
	Error   *apiError  `json:"error"`
	Result  *resultDTO `json:"result"`
}

type keyLoginDTO struct {
	// Outcome is "done", "never-worked", "rolled-back", "still-on" or "error".
	Outcome     string   `json:"outcome"`
	KeyPath     string   `json:"keyPath"`
	PasswordOff bool     `json:"passwordOff"`
	Message     string   `json:"message"`
	Files       []string `json:"files"`
}

type stateDTO struct {
	Payload    []string       `json:"payload"`
	Regions    []string       `json:"regions"`
	Connection *connectionDTO `json:"connection"`
	Deploy     *jobState      `json:"deploy"`
	TunnelURL  string         `json:"tunnelUrl"`
	KeyLogin   *keyLoginDTO   `json:"keyLogin"`
}

func (s *Server) getState(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	st := stateDTO{Payload: s.cfg.PayloadArchs, Regions: deploy.Regions, Connection: s.conn, KeyLogin: s.keyLogin}
	if st.Payload == nil {
		st.Payload = []string{}
	}
	if s.job != nil {
		job := *s.job
		job.Steps = append([]stepDTO(nil), s.job.Steps...)
		st.Deploy = &job
	}
	if s.tunnel != nil {
		st.TunnelURL = "http://" + s.tunnel.Addr() + "/"
	}
	// Encoded under the lock: the job goroutine swaps pointers, it never edits what they point to.
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(st)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// connectError turns the SSH layer's typed errors into codes the page has wording for.
func connectError(err error) (int, apiError) {
	var (
		unreachable *deploy.UnreachableError
		changed     *deploy.HostKeyChangedError
		needsRoot   *deploy.NeedsRootError
	)
	switch {
	case errors.Is(err, deploy.ErrAuth):
		return http.StatusUnauthorized, apiError{Code: "auth", Message: err.Error()}
	case errors.As(err, &changed):
		return http.StatusConflict, apiError{Code: "host_key_changed", Message: err.Error(), Known: changed.Known, Presented: changed.Presented}
	case errors.As(err, &unreachable):
		return http.StatusBadGateway, apiError{Code: "unreachable", Message: err.Error()}
	case errors.As(err, &needsRoot):
		return http.StatusForbidden, apiError{Code: "needs_root", Message: err.Error()}
	case errors.Is(err, deploy.ErrPassphraseRequired):
		return http.StatusBadRequest, apiError{Code: "passphrase_required", Message: err.Error(), Field: "passphrase"}
	case errors.Is(err, deploy.ErrPassphraseWrong):
		return http.StatusBadRequest, apiError{Code: "passphrase_wrong", Message: err.Error(), Field: "passphrase"}
	case errors.Is(err, deploy.ErrBadPrivateKey):
		return http.StatusBadRequest, apiError{Code: "bad_key", Message: err.Error(), Field: "privateKey"}
	case errors.Is(err, deploy.ErrNoCredentials):
		return http.StatusBadRequest, apiError{Code: "invalid", Message: err.Error(), Field: "password"}
	}
	return http.StatusInternalServerError, apiError{Code: "error", Message: err.Error()}
}

type connectInput struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`
}

// target validates the form. Host may be a name or an IP; brackets around IPv6 are dropped.
func (in connectInput) target() (deploy.Target, *apiError) {
	host := strings.TrimSpace(in.Host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" || strings.ContainsAny(host, " /@\t") || (net.ParseIP(host) == nil && strings.Contains(host, ":")) {
		return deploy.Target{}, &apiError{Code: "invalid", Field: "host", Message: "enter the server's IP address or domain name"}
	}
	port := in.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return deploy.Target{}, &apiError{Code: "invalid", Field: "port", Message: "port must be between 1 and 65535"}
	}
	user := strings.TrimSpace(in.User)
	if user == "" {
		user = "root"
	}
	t := deploy.Target{Host: host, Port: port, User: user, Password: in.Password, Passphrase: in.Passphrase}
	if key := strings.TrimSpace(in.PrivateKey); key != "" {
		t.PrivateKey = []byte(key + "\n")
	}
	return t, nil
}

func (s *Server) begin(w http.ResponseWriter) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy || (s.job != nil && s.job.Running) {
		writeErr(w, http.StatusConflict, apiError{Code: "busy", Message: "another operation is still running"})
		return false
	}
	s.busy = true
	return true
}

func (s *Server) end() {
	s.mu.Lock()
	s.busy = false
	s.mu.Unlock()
}

func (s *Server) postConnect(w http.ResponseWriter, r *http.Request) {
	var in connectInput
	if !decode(w, r, &in) {
		return
	}
	target, bad := in.target()
	if bad != nil {
		writeErr(w, http.StatusBadRequest, *bad)
		return
	}
	s.mu.Lock()
	leaving := s.holdsPasswordForOtherThan(target.Addr())
	s.mu.Unlock()
	if leaving {
		writeErr(w, http.StatusConflict, errPasswordUnsaved)
		return
	}
	if !s.begin(w) {
		return
	}
	defer s.end()

	ctx, cancel := context.WithTimeout(r.Context(), connectTimeout)
	defer cancel()
	client, err := deploy.Dial(ctx, target, deploy.Options{KnownHosts: s.cfg.KnownHosts})
	if err == nil {
		if err = client.EnsureRoot(ctx); err != nil {
			_ = client.Close()
		}
	}
	if err != nil {
		status, e := connectError(err)
		s.log.Info("connect failed", "host", target.Host, "code", e.Code)
		writeErr(w, status, e)
		return
	}
	conn := &connectionDTO{
		Host: target.Host, Port: target.Port, User: target.User, Root: client.IsRoot(),
		Fingerprint: client.Fingerprint(), FirstSeen: client.FirstSeen(), PasswordLogin: target.Password != "",
	}
	s.mu.Lock()
	// Reconnecting to the server whose password is still unsaved keeps that deploy on the page.
	var keep *jobState
	if s.unsavedPassword != "" && s.unsavedAddr == target.Addr() {
		keep = s.job
	}
	s.disconnectLocked()
	s.client, s.conn, s.job = client, conn, keep
	s.mu.Unlock()
	s.log.Info("connected", "host", target.Host, "user", target.User)
	writeJSON(w, http.StatusOK, conn)
}

func (s *Server) postForgetHost(w http.ResponseWriter, r *http.Request) {
	var in connectInput
	if !decode(w, r, &in) {
		return
	}
	target, bad := in.target()
	if bad != nil {
		writeErr(w, http.StatusBadRequest, *bad)
		return
	}
	if err := s.cfg.KnownHosts.Forget(target.Addr()); err != nil {
		writeErr(w, http.StatusInternalServerError, apiError{Code: "error", Message: err.Error()})
		return
	}
	s.log.Info("forgot host key", "host", target.Host)
	w.WriteHeader(http.StatusNoContent)
}

func deployError(err error) *apiError {
	var (
		unsupported *deploy.UnsupportedError
		panelErr    *deploy.PanelError
		needsRoot   *deploy.NeedsRootError
	)
	e := &apiError{Code: "error", Message: err.Error()}
	switch {
	case errors.As(err, &unsupported):
		e.Code = "unsupported"
	case errors.Is(err, deploy.ErrNoPayload):
		e.Code = "no_payload"
	case errors.Is(err, deploy.ErrNoCoverSite):
		e.Code = "no_cover_site"
	case errors.Is(err, deploy.ErrPanelNotAnswering):
		e.Code = "panel_not_answering"
	case errors.Is(err, deploy.ErrUploadCorrupt):
		e.Code = "upload_corrupt"
	case errors.As(err, &needsRoot):
		e.Code = "needs_root"
	case errors.As(err, &panelErr):
		e.Code = "panel"
	case errors.Is(err, context.DeadlineExceeded):
		e.Code = "timeout"
	}
	return e
}

func (s *Server) postDeploy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Region     string `json:"region"`
		ClientName string `json:"clientName"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Region == "unsure" {
		in.Region = ""
	}
	in.ClientName = strings.TrimSpace(in.ClientName)
	if utf8.RuneCountInString(in.ClientName) > 64 {
		writeErr(w, http.StatusBadRequest, apiError{Code: "invalid", Field: "clientName", Message: "name is too long"})
		return
	}

	s.mu.Lock()
	client := s.client
	switch {
	case client == nil:
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, apiError{Code: "not_connected", Message: "connect to the server first"})
		return
	case s.busy || (s.job != nil && s.job.Running):
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, apiError{Code: "busy", Message: "another operation is still running"})
		return
	}
	addr := net.JoinHostPort(s.conn.Host, strconv.Itoa(s.conn.Port))
	earlier := ""
	if s.unsavedAddr == addr {
		earlier = s.unsavedPassword
	}
	job := &jobState{Running: true}
	for _, id := range deploy.Steps {
		job.Steps = append(job.Steps, stepDTO{ID: id})
	}
	ctx, cancel := context.WithTimeout(context.Background(), deployTimeout)
	s.job, s.cancel = job, cancel
	s.mu.Unlock()

	report := func(id deploy.StepID, status deploy.StepStatus, detail string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i := range job.Steps {
			if job.Steps[i].ID == id {
				job.Steps[i].Status, job.Steps[i].Detail = status, detail
			}
		}
	}
	go func() {
		defer cancel()
		res, err := client.Deploy(ctx, deploy.Request{
			Region: in.Region, ClientName: in.ClientName, PanelBinary: s.cfg.PanelBinary, Report: report,
			AdminPassword: earlier,
		})
		var dto *resultDTO
		if res != nil {
			dto = &resultDTO{
				AlreadyDeployed: res.AlreadyDeployed, Arch: res.Arch, AdminUser: res.AdminUser, AdminPassword: res.AdminPassword,
				Link: res.Link, LineName: res.LineName, Port: res.Port, Firewall: res.Firewall,
			}
			if res.Link != "" {
				dto.QRSVG, _ = qrSVG(res.Link)
			}
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch {
		case dto != nil && dto.AdminPassword != "":
			s.unsavedPassword, s.unsavedAddr = dto.AdminPassword, addr
		case earlier != "" && s.unsavedAddr == addr:
			// The retry failed before it could log in; the password it carried is still the one to keep.
			if dto == nil {
				dto = &resultDTO{}
			}
			dto.AdminUser, dto.AdminPassword = deploy.AdminUser, earlier
		}
		job.Running, job.Result = false, dto
		if err != nil {
			job.Error = deployError(err)
			s.log.Info("deploy failed", "code", job.Error.Code)
		} else {
			s.log.Info("deploy finished", "alreadyDeployed", res.AlreadyDeployed)
		}
	}()
	w.WriteHeader(http.StatusAccepted)
}

// postPasswordSaved forgets the panel password; from here on it exists only where the user put it.
func (s *Server) postPasswordSaved(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	if s.job != nil && s.job.Result != nil && !s.job.Running {
		res := *s.job.Result
		res.AdminPassword = ""
		s.job.Result = &res
	}
	s.unsavedPassword, s.unsavedAddr = "", ""
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postTunnel(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		writeErr(w, http.StatusConflict, apiError{Code: "not_connected", Message: "connect to the server first"})
		return
	}
	if s.tunnel == nil {
		f, err := s.client.Forward(deploy.PanelAddr)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, apiError{Code: "error", Message: err.Error()})
			return
		}
		s.tunnel = f
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": "http://" + s.tunnel.Addr() + "/"})
}

func (s *Server) postKeyLogin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()
	if client == nil {
		writeErr(w, http.StatusConflict, apiError{Code: "not_connected", Message: "connect to the server first"})
		return
	}
	if !s.begin(w) {
		return
	}
	defer s.end()

	// Not tied to the request: a closed browser tab must not interrupt this halfway.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), keyLoginTimeout)
	defer cancel()
	res, err := client.EnableKeyLogin(ctx, deploy.KeyLoginOptions{KeyDir: s.cfg.KeyDir, KnownHosts: s.cfg.KnownHosts})
	out := &keyLoginDTO{Outcome: "done", Files: []string{}}
	if res != nil {
		out.KeyPath, out.PasswordOff = res.KeyPath, res.PasswordOff
	}
	var (
		rolled *deploy.KeyLoginRolledBackError
		still  *deploy.PasswordStillOnError
	)
	switch {
	case err == nil:
	case errors.Is(err, deploy.ErrKeyNeverWorked):
		out.Outcome = "never-worked"
	case errors.As(err, &rolled):
		out.Outcome = "rolled-back"
	case errors.As(err, &still):
		out.Outcome = "still-on"
		out.Files = append(out.Files, still.Files...)
	default:
		out.Outcome = "error"
	}
	if err != nil {
		out.Message = err.Error()
	}
	s.mu.Lock()
	if s.client == client {
		s.keyLogin = out
	}
	s.mu.Unlock()
	s.log.Info("key login", "outcome", out.Outcome, "port", strconv.Itoa(client.Target().Port))
	writeJSON(w, http.StatusOK, out)
}
