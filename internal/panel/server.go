// Package panel is the admin HTTP API, the public subscription endpoint and the static
// frontend, plus the orchestration that keeps the engine in step with the store.
package panel

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ysuhao/mintyx-next/internal/hostcheck"
	"github.com/ysuhao/mintyx-next/internal/reach"
	"github.com/ysuhao/mintyx-next/internal/store"
)

// Engine is what the panel needs from the Xray supervisor.
type Engine interface {
	// Sync rebuilds the Xray config from the store and applies it.
	Sync(ctx context.Context) error
	Restart(ctx context.Context) error
	Status(ctx context.Context) EngineStatus
	// Logs returns the most recent engine output lines, oldest first.
	Logs() []string
}

// EngineStatus is the snapshot behind GET /api/engine; a zero StartedAt means never started.
type EngineStatus struct {
	Running     bool
	PID         int
	StartedAt   time.Time
	LastExit    string
	Restarts    int
	Version     string
	BinaryFound bool
}

// KeyGen produces the random credentials new lines and clients need.
type KeyGen interface {
	NewUUID() string
	NewRealityKeyPair() (private, public string, err error)
	NewShortID() string
	NewPassword() string
}

type Config struct {
	Store  *store.Store
	Engine Engine
	Keys   KeyGen
	// Static holds the built frontend with index.html at its root; nil serves no UI.
	Static fs.FS
	// TrustProxy honours X-Forwarded-For / X-Forwarded-Proto from a reverse proxy in front of the panel.
	TrustProxy bool
	// ReservedPorts cannot be used by lines, e.g. the panel's own port and the engine's API port.
	ReservedPorts []int
	// CoverSite suggests a REALITY cover site reachable from this server, given the region the admin
	// says it is in ("" when not said); nil or "" suggests none.
	CoverSite func(ctx context.Context, region string) string
	// HostCheck answers GET /api/host/ssh; nil inspects the real sshd.
	HostCheck *hostcheck.Checker
	// Reach runs the from-China reachability measurements; nil uses the public Globalping API.
	Reach  reach.Pinger
	Logger *slog.Logger
}

const (
	maxBodyBytes     = 64 << 10
	loginMaxFailures = 5
	loginLockout     = 15 * time.Minute
	sessionTTL       = 7 * 24 * time.Hour
	sessionCookie    = "mintyx_session"
)

const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; " +
	"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

type Server struct {
	st         *store.Store
	eng        Engine
	keys       KeyGen
	static     fs.FS
	trustProxy bool
	reserved   map[int]bool
	coverSite  func(context.Context, string) string
	hostCheck  *hostcheck.Checker
	log        *slog.Logger
	mux        *http.ServeMux
	startedAt  time.Time
	now        func() time.Time
	bcryptCost int

	// mu serialises every store mutation with quota ticks and Sync, so a tick never
	// reconciles from a client row an admin request is halfway through changing.
	mu          sync.Mutex
	syncPending bool

	authMu   sync.Mutex
	sessions map[[32]byte]session

	limiter *loginLimiter

	dummyOnce sync.Once
	dummyHash []byte

	pinger reach.Pinger
	// reachRunning admits one round at a time, whether the loop or the admin started it.
	reachRunning atomic.Bool
}

func New(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Engine == nil || cfg.Keys == nil {
		return nil, errors.New("panel: Store, Engine and Keys are required")
	}
	s := &Server{
		st:         cfg.Store,
		eng:        cfg.Engine,
		keys:       cfg.Keys,
		static:     cfg.Static,
		trustProxy: cfg.TrustProxy,
		reserved:   map[int]bool{},
		coverSite:  cfg.CoverSite,
		hostCheck:  cfg.HostCheck,
		log:        cfg.Logger,
		now:        func() time.Time { return time.Now().UTC() },
		bcryptCost: bcrypt.DefaultCost,
		sessions:   map[[32]byte]session{},
		limiter:    newLoginLimiter(),
	}
	if s.pinger = cfg.Reach; s.pinger == nil {
		s.pinger = reach.NewClient()
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.hostCheck == nil {
		s.hostCheck = hostcheck.New(nil)
	}
	for _, p := range cfg.ReservedPorts {
		s.reserved[p] = true
	}
	s.startedAt = s.now()
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/session", s.getSession)
	m.HandleFunc("POST /api/setup", s.postSetup)
	m.HandleFunc("POST /api/login", s.postLogin)
	m.HandleFunc("POST /api/logout", s.postLogout)
	m.HandleFunc("PUT /api/password", s.authed(s.putPassword))

	m.HandleFunc("GET /api/lines", s.authed(s.listLines))
	m.HandleFunc("POST /api/lines/draft", s.authed(s.draftLine))
	m.HandleFunc("POST /api/lines", s.authed(s.createLine))
	m.HandleFunc("PUT /api/lines/{id}", s.authed(s.updateLine))
	m.HandleFunc("DELETE /api/lines/{id}", s.authed(s.deleteLine))

	m.HandleFunc("GET /api/clients", s.authed(s.listClients))
	m.HandleFunc("POST /api/clients", s.authed(s.createClient))
	m.HandleFunc("PUT /api/clients/{id}", s.authed(s.updateClient))
	m.HandleFunc("DELETE /api/clients/{id}", s.authed(s.deleteClient))
	m.HandleFunc("POST /api/clients/{id}/disable", s.authed(s.disableClient))
	m.HandleFunc("POST /api/clients/{id}/enable", s.authed(s.enableClient))
	m.HandleFunc("POST /api/clients/{id}/reset-traffic", s.authed(s.resetClientTraffic))
	m.HandleFunc("POST /api/clients/{id}/rotate", s.authed(s.rotateClient))
	m.HandleFunc("GET /api/clients/{id}/share", s.authed(s.shareClient))

	m.HandleFunc("GET /api/reach/config", s.authed(s.getReachConfig))
	m.HandleFunc("PUT /api/reach/config", s.authed(s.putReachConfig))
	m.HandleFunc("GET /api/reach/status", s.authed(s.getReachStatus))
	m.HandleFunc("POST /api/reach/check", s.authed(s.postReachCheck))
	m.HandleFunc("POST /api/reach/test-email", s.authed(s.postReachTestEmail))

	m.HandleFunc("GET /api/engine", s.authed(s.getEngine))
	m.HandleFunc("POST /api/engine/restart", s.authed(s.restartEngine))
	m.HandleFunc("GET /api/engine/logs", s.authed(s.getEngineLogs))
	m.HandleFunc("GET /api/status", s.authed(s.getStatus))
	m.HandleFunc("GET /api/audit", s.authed(s.listAudit))
	m.HandleFunc("GET /api/settings", s.authed(s.getSettings))
	m.HandleFunc("PUT /api/settings", s.authed(s.putSettings))
	m.HandleFunc("GET /api/host/ssh", s.authed(s.getHostSSH))

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, codeNotFound, "no such endpoint", "")
	})
	m.HandleFunc("GET /sub/{token}", s.getSubscription)
	m.HandleFunc("/sub/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	s.mux = m
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", contentSecurityPolicy)

	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/api/"):
		h.Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		if !safeMethod(r.Method) {
			if r.Header.Get("X-Mintyx") != "1" {
				writeErr(w, http.StatusForbidden, codeForbidden, "missing X-Mintyx header", "")
				return
			}
			if !s.sameOrigin(r) {
				writeErr(w, http.StatusForbidden, codeForbidden, "cross-origin request", "")
				return
			}
		}
		s.mux.ServeHTTP(w, r)
	case strings.HasPrefix(p, "/sub/"):
		h.Set("Cache-Control", "no-store")
		s.mux.ServeHTTP(w, r)
	default:
		s.serveStatic(w, r)
	}
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// sameOrigin allows a missing Origin (non-browser clients) but otherwise requires the same scheme and host.
func (s *Server) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	scheme := "http"
	if s.isHTTPS(r) {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(stripDefaultPort(u.Host, scheme), stripDefaultPort(r.Host, scheme))
}

func stripDefaultPort(hostport, scheme string) string {
	if scheme == "https" {
		return strings.TrimSuffix(hostport, ":443")
	}
	return strings.TrimSuffix(hostport, ":80")
}

// remoteIP takes the rightmost X-Forwarded-For entry when proxied: that is the one our own proxy appended.
func (s *Server) remoteIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(strings.Join(xff, ","), ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.trustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.static == nil {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" && name != "index.html" && fs.ValidPath(name) {
		if fi, err := fs.Stat(s.static, name); err == nil && !fi.IsDir() {
			http.ServeFileFS(w, r, s.static, name)
			return
		}
		// A missing asset must not come back as HTML, or the browser reports a confusing MIME error.
		if strings.Contains(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
	}
	index, err := fs.ReadFile(s.static, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
}
