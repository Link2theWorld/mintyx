package panel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	settingAdminUser = "admin.username"
	settingAdminHash = "admin.passwordHash"
	minPasswordRunes = 10
	// bcrypt ignores everything past 72 bytes, so longer passwords would silently be truncated.
	maxPasswordBytes = 72
	maxNameRunes     = 64
)

type session struct {
	expires time.Time
}

type ctxKey struct{}

func newToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Sessions are keyed by the token's hash so lookups never compare the secret itself.
func tokenKey(tok string) [32]byte { return sha256.Sum256([]byte(tok)) }

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) {
	tok := newToken()
	now := s.now()
	s.authMu.Lock()
	for k, se := range s.sessions {
		if !now.Before(se.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[tokenKey(tok)] = session{expires: now.Add(sessionTTL)}
	s.authMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/", MaxAge: int(sessionTTL / time.Second),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.isHTTPS(r),
	})
}

func (s *Server) currentSession(r *http.Request) ([32]byte, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return [32]byte{}, false
	}
	k := tokenKey(c.Value)
	s.authMu.Lock()
	defer s.authMu.Unlock()
	se, ok := s.sessions[k]
	if !ok {
		return k, false
	}
	if !s.now().Before(se.expires) {
		delete(s.sessions, k)
		return k, false
	}
	return k, true
}

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k, ok := s.currentSession(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, codeUnauthorized, "login required", "")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, k)))
	}
}

func (s *Server) admin(ctx context.Context) (user string, hash []byte, ok bool, err error) {
	h, found, err := s.st.GetSetting(ctx, settingAdminHash)
	if err != nil || !found {
		return "", nil, false, err
	}
	u, _, err := s.st.GetSetting(ctx, settingAdminUser)
	if err != nil {
		return "", nil, false, err
	}
	return u, []byte(h), true, nil
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	user, _, exists, err := s.admin(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	var name *string
	if _, ok := s.currentSession(r); ok && exists {
		name = &user
	}
	writeJSON(w, http.StatusOK, map[string]any{"needsSetup": !exists, "username": name})
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func validateName(field, v string) error {
	if v == "" {
		return invalid(field, field+" is required")
	}
	if utf8.RuneCountInString(v) > maxNameRunes {
		return invalid(field, field+" is too long")
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return invalid(field, field+" contains control characters")
	}
	return nil
}

func validatePassword(field, pw string) error {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return invalid(field, "password must be at least 10 characters")
	}
	if len(pw) > maxPasswordBytes {
		return invalid(field, "password must be at most 72 bytes")
	}
	return nil
}

func (s *Server) postSetup(w http.ResponseWriter, r *http.Request) {
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := errors.Join(validateName("username", in.Username), validatePassword("password", in.Password)); err != nil {
		s.writeFail(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, exists, err := s.admin(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if exists {
		writeErr(w, http.StatusConflict, codeConflict, "the admin account already exists", "")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), s.bcryptCost)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	// The hash is written last: its presence is what marks setup as done.
	if err := s.st.SetSetting(r.Context(), settingAdminUser, in.Username); err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.SetSetting(r.Context(), settingAdminHash, string(hash)); err != nil {
		s.writeFail(w, err)
		return
	}
	s.startSession(w, r)
	s.audit(r, "setup", in.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// checkPassword runs bcrypt even when there is no admin, so timing does not reveal whether setup happened.
func (s *Server) checkPassword(hash []byte, pw string) bool {
	if hash == nil {
		s.dummyOnce.Do(func() {
			s.dummyHash, _ = bcrypt.GenerateFromPassword([]byte("mintyx-no-admin-yet"), s.bcryptCost)
		})
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(pw))
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil
}

func (s *Server) writeRateLimited(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds()+1)))
	writeErr(w, http.StatusTooManyRequests, codeRateLimited, "too many failed attempts, try again later", "")
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	ip := s.remoteIP(r)
	if wait := s.limiter.blocked(ip, s.now()); wait > 0 {
		s.writeRateLimited(w, wait)
		return
	}
	var in credentials
	if !decodeJSON(w, r, &in) {
		return
	}
	user, hash, exists, err := s.admin(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(in.Username), []byte(user)) == 1
	pwOK := s.checkPassword(hash, in.Password)
	if !exists || !userOK || !pwOK {
		s.limiter.fail(ip, s.now())
		s.audit(r, "login.fail", truncateRunes(in.Username, maxNameRunes), "")
		writeErr(w, http.StatusUnauthorized, codeUnauthorized, "wrong username or password", "")
		return
	}
	s.limiter.reset(ip)
	s.startSession(w, r)
	s.audit(r, "login.ok", user, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if k, ok := s.currentSession(r); ok {
		s.authMu.Lock()
		delete(s.sessions, k)
		s.authMu.Unlock()
		user, _, _, _ := s.admin(r.Context())
		s.audit(r, "logout", user, "")
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.isHTTPS(r),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) putPassword(w http.ResponseWriter, r *http.Request) {
	ip := s.remoteIP(r)
	if wait := s.limiter.blocked(ip, s.now()); wait > 0 {
		s.writeRateLimited(w, wait)
		return
	}
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, hash, _, err := s.admin(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if !s.checkPassword(hash, in.Current) {
		s.limiter.fail(ip, s.now())
		s.writeFail(w, invalid("current", "current password is wrong"))
		return
	}
	if err := validatePassword("new", in.New); err != nil {
		s.writeFail(w, err)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(in.New), s.bcryptCost)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.SetSetting(r.Context(), settingAdminHash, string(newHash)); err != nil {
		s.writeFail(w, err)
		return
	}
	keep, _ := r.Context().Value(ctxKey{}).([32]byte)
	s.authMu.Lock()
	for k := range s.sessions {
		if k != keep {
			delete(s.sessions, k)
		}
	}
	s.authMu.Unlock()
	s.audit(r, "password.change", user, "")
	w.WriteHeader(http.StatusNoContent)
}

func truncateRunes(v string, n int) string {
	if utf8.RuneCountInString(v) <= n {
		return v
	}
	return string([]rune(v)[:n])
}

// loginLimiter locks an IP out for loginLockout after loginMaxFailures failures within that window.
type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*attempts
}

type attempts struct {
	fails int
	last  time.Time
	until time.Time
}

const limiterSweepAt = 4096

func newLoginLimiter() *loginLimiter { return &loginLimiter{m: map[string]*attempts{}} }

func (l *loginLimiter) blocked(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a := l.m[ip]; a != nil && now.Before(a.until) {
		return a.until.Sub(now)
	}
	return 0
}

func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) >= limiterSweepAt {
		for k, a := range l.m {
			if now.Sub(a.last) > loginLockout && !now.Before(a.until) {
				delete(l.m, k)
			}
		}
	}
	a := l.m[ip]
	if a == nil || now.Sub(a.last) > loginLockout {
		a = &attempts{}
		l.m[ip] = a
	}
	a.fails++
	a.last = now
	if a.fails >= loginMaxFailures {
		a.fails = 0
		a.until = now.Add(loginLockout)
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.m, ip)
	l.mu.Unlock()
}
