package panel

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) getEngine(w http.ResponseWriter, r *http.Request) {
	st := s.eng.Status(r.Context())
	var started *time.Time
	if !st.StartedAt.IsZero() {
		t := st.StartedAt.UTC()
		started = &t
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"running": st.Running, "pid": st.PID, "startedAt": started, "lastExit": st.LastExit,
		"restarts": st.Restarts, "version": st.Version, "binaryFound": st.BinaryFound,
	})
}

func (s *Server) restartEngine(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.eng.Restart(context.WithoutCancel(r.Context()))
	detail := ""
	if err != nil {
		detail = "failed"
	}
	s.audit(r, "engine.restart", "xray", detail)
	if err != nil {
		writeErr(w, http.StatusBadGateway, codeEngine, "engine restart failed: "+err.Error(), "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getEngineLogs(w http.ResponseWriter, r *http.Request) {
	lines := s.eng.Logs()
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request) {
	lines, err := s.st.ListLines(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	clients, err := s.st.ListClients(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	active, up, down := 0, int64(0), int64(0)
	for _, c := range clients {
		if c.Enabled() {
			active++
		}
		up += c.UsedUp
		down += c.UsedDown
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"panelStartedAt": s.startedAt, "lineCount": len(lines), "clientCount": len(clients),
		"activeClientCount": active, "totalUp": up, "totalDown": down,
	})
}

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 500
)

type auditDTO struct {
	ID       int64     `json:"id"`
	At       time.Time `json:"at"`
	Action   string    `json:"action"`
	Target   string    `json:"target"`
	Detail   string    `json:"detail"`
	RemoteIP string    `json:"remoteIp"`
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, before := defaultAuditLimit, int64(0)
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxAuditLimit {
			s.writeFail(w, invalid("limit", "limit must be between 1 and 500"))
			return
		}
		limit = n
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			s.writeFail(w, invalid("before", "before must be an entry id"))
			return
		}
		before = n
	}
	entries, err := s.st.ListAudit(r.Context(), limit, before)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]auditDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, auditDTO{ID: e.ID, At: e.At, Action: e.Action, Target: e.Target, Detail: e.Detail, RemoteIP: e.RemoteIP})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

type settingsDTO struct {
	PublicHost          string `json:"publicHost"`
	SubscriptionBaseURL string `json:"subscriptionBaseUrl"`
}

func (s *Server) loadSettings(ctx context.Context) (settingsDTO, error) {
	var d settingsDTO
	var err error
	if d.PublicHost, _, err = s.st.GetSetting(ctx, settingPublicHost); err != nil {
		return d, err
	}
	d.SubscriptionBaseURL, _, err = s.st.GetSetting(ctx, settingSubBaseURL)
	return d, err
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	d, err := s.loadSettings(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func validSubBase(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		u.User == nil && u.RawQuery == "" && u.Fragment == "" && !u.ForceQuery
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in settingsDTO
	if !decodeJSON(w, r, &in) {
		return
	}
	in.PublicHost = strings.TrimSpace(in.PublicHost)
	in.SubscriptionBaseURL = strings.TrimRight(strings.TrimSpace(in.SubscriptionBaseURL), "/")
	if in.PublicHost != "" && !validDialHost(in.PublicHost) {
		s.writeFail(w, invalid("publicHost", "public host must be a domain name or IP address"))
		return
	}
	if in.SubscriptionBaseURL != "" && !validSubBase(in.SubscriptionBaseURL) {
		s.writeFail(w, invalid("subscriptionBaseUrl", "must be an http(s) URL without query or fragment"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, err := s.loadSettings(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	var changed []string
	if prev.PublicHost != in.PublicHost {
		changed = append(changed, "publicHost")
	}
	if prev.SubscriptionBaseURL != in.SubscriptionBaseURL {
		changed = append(changed, "subscriptionBaseUrl")
	}
	if err := s.st.SetSetting(r.Context(), settingPublicHost, in.PublicHost); err != nil {
		s.writeFail(w, err)
		return
	}
	if err := s.st.SetSetting(r.Context(), settingSubBaseURL, in.SubscriptionBaseURL); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "settings.update", "settings", strings.Join(changed, ", "))
	writeJSON(w, http.StatusOK, in)
}
