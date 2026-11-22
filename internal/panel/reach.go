package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/notify"
	"github.com/ysuhao/mintyx-next/internal/reach"
	"github.com/ysuhao/mintyx-next/internal/share"
)

const (
	settingReachConfig = "reach.config"
	// The SMTP password has its own key so that no code path serialising the config can carry it.
	settingReachPassword = "reach.smtpPassword"
	settingReachState    = "reach.state"

	// With the usual one to three lines a round costs 16-32 Globalping tests, so a round every
	// 30 minutes spends about a quarter of the 250 tests/hour an anonymous caller gets.
	reachDefaultInterval = 30
	reachMinInterval     = 10
	reachMaxInterval     = 24 * 60
	reachDefaultConfirm  = 2
	reachMaxConfirm      = 10
	reachDefaultSMTPPort = 587
	reachMaxFieldLen     = 512

	reachManualGap    = time.Minute
	reachRoundTimeout = 3 * time.Minute

	reachErrRateLimited = "rate_limited"
	reachErrTooMany     = "too_many_lines"
	reachErrProbe       = "probe_failed"
)

type reachSMTPDTO struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	Username string `json:"username"`
	// Password is accepted on write and never sent back; PasswordSet tells the UI one is stored.
	Password    string `json:"password,omitempty"`
	PasswordSet bool   `json:"passwordSet"`
	From        string `json:"from"`
	To          string `json:"to"`
}

type reachConfigDTO struct {
	Enabled         bool         `json:"enabled"`
	IntervalMinutes int          `json:"intervalMinutes"`
	ConfirmRounds   int          `json:"confirmRounds"`
	SMTP            reachSMTPDTO `json:"smtp"`
}

// reachRecord is the persisted checker state plus what the last round ran into.
type reachRecord struct {
	reach.State
	LastError       string `json:"lastError,omitempty"`
	LastErrorDetail string `json:"lastErrorDetail,omitempty"`
	AlertError      string `json:"alertError,omitempty"`
}

type reachTargetDTO struct {
	LineID   int64  `json:"lineId"`
	LineName string `json:"lineName"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	// IPOnly: a UDP line, where only the address could be tested, not the port.
	IPOnly bool `json:"ipOnly"`
	// Verdict is the confirmed state; LastResult is the latest round alone, "" before any.
	Verdict         reach.Verdict `json:"verdict"`
	Since           *time.Time    `json:"since"`
	LastResult      reach.Verdict `json:"lastResult"`
	ChinaReached    int           `json:"chinaReached"`
	ChinaAnswered   int           `json:"chinaAnswered"`
	ControlReached  int           `json:"controlReached"`
	ControlAnswered int           `json:"controlAnswered"`
}

type reachStatusDTO struct {
	Enabled bool `json:"enabled"`
	// Configured is false while an enabled line has no address to test.
	Configured      bool             `json:"configured"`
	Running         bool             `json:"running"`
	LastCheckAt     *time.Time       `json:"lastCheckAt"`
	NextCheckAt     *time.Time       `json:"nextCheckAt"`
	LastError       string           `json:"lastError"`
	LastErrorDetail string           `json:"lastErrorDetail"`
	AlertError      string           `json:"alertError"`
	Targets         []reachTargetDTO `json:"targets"`
}

func (s *Server) loadReachConfig(ctx context.Context) (cfg reachConfigDTO, password string, err error) {
	cfg = reachConfigDTO{
		IntervalMinutes: reachDefaultInterval,
		ConfirmRounds:   reachDefaultConfirm,
		SMTP:            reachSMTPDTO{Port: reachDefaultSMTPPort, Security: string(notify.StartTLS)},
	}
	raw, found, err := s.st.GetSetting(ctx, settingReachConfig)
	if err != nil {
		return cfg, "", err
	}
	if found {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return cfg, "", fmt.Errorf("panel: stored reach config: %w", err)
		}
	}
	if password, _, err = s.st.GetSetting(ctx, settingReachPassword); err != nil {
		return cfg, "", err
	}
	cfg.SMTP.Password, cfg.SMTP.PasswordSet = "", password != ""
	return cfg, password, nil
}

func (s *Server) loadReachRecord(ctx context.Context) (reachRecord, error) {
	var rec reachRecord
	raw, found, err := s.st.GetSetting(ctx, settingReachState)
	if err != nil || !found {
		return rec, err
	}
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		// Losing the history only delays the next alert by the confirmation rounds.
		s.log.Warn("panel: stored reach state unreadable, starting over", "err", err)
		return reachRecord{}, nil
	}
	return rec, nil
}

// reachTargets lists what to probe: the address each enabled line's share link points at.
func (s *Server) reachTargets(ctx context.Context) (targets []reach.Target, lines map[int64]model.Line, configured bool, err error) {
	publicHost, _, err := s.st.GetSetting(ctx, settingPublicHost)
	if err != nil {
		return nil, nil, false, err
	}
	all, err := s.st.ListLines(ctx)
	if err != nil {
		return nil, nil, false, err
	}
	lines, configured = map[int64]model.Line{}, true
	for _, l := range all {
		if !l.Enabled {
			continue
		}
		host, port, err := share.DialAddress(l, publicHost)
		if err != nil {
			if publicHost == "" {
				configured = false
			}
			continue
		}
		lines[l.ID] = l
		targets = append(targets, reach.Target{ID: l.ID, Name: l.Name, Host: host, Port: port, IPOnly: l.Protocol == model.Hysteria2})
	}
	return targets, lines, configured, nil
}

func normalizeSMTP(in *reachSMTPDTO) {
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	in.From = strings.TrimSpace(in.From)
	in.To = strings.TrimSpace(in.To)
	in.PasswordSet = false
}

func validateSMTP(in reachSMTPDTO) error {
	for _, f := range [][2]string{{"smtp.username", in.Username}, {"smtp.password", in.Password}} {
		if len(f[1]) > reachMaxFieldLen || strings.ContainsAny(f[1], "\r\n\x00") {
			return invalid(f[0], "must be a single line of at most 512 characters")
		}
	}
	switch {
	case in.Host != "" && !validDialHost(in.Host):
		return invalid("smtp.host", "SMTP host must be a domain name or IP address")
	case !validPort(in.Port):
		return invalid("smtp.port", "SMTP port must be between 1 and 65535")
	case !notify.Security(in.Security).Valid():
		return invalid("smtp.security", `security must be "starttls", "tls" or "none"`)
	case in.Host != "" && notify.Security(in.Security) == notify.None && in.Username != "" && !notify.PlainSignInAllowed(in.Host):
		return invalid("smtp.security", "signing in needs encryption: choose STARTTLS or TLS, or leave the username empty")
	}
	if in.From != "" || in.Host != "" {
		if _, err := mail.ParseAddress(in.From); err != nil || len(in.From) > reachMaxFieldLen {
			return invalid("smtp.from", "sender must be one email address")
		}
	}
	if in.To != "" || in.Host != "" {
		if _, err := mail.ParseAddressList(in.To); err != nil || len(in.To) > reachMaxFieldLen {
			return invalid("smtp.to", "recipient must be an email address, or several separated by commas")
		}
	}
	return nil
}

func (in reachSMTPDTO) server(password string) notify.Server {
	return notify.Server{
		Host: in.Host, Port: in.Port, Security: notify.Security(in.Security),
		Username: in.Username, Password: password,
	}
}

// resolvePassword applies the write-only rule: empty keeps the stored one, no username clears it.
// A stored password is never reused for another server or account, or a hijacked session
// could have it delivered to a host of its choosing.
func resolvePassword(in, prev reachSMTPDTO, stored string) (string, error) {
	switch {
	case in.Username == "":
		return "", nil
	case in.Password != "":
		return in.Password, nil
	case stored != "" && (in.Host != prev.Host || in.Username != prev.Username):
		return "", invalid("smtp.password", "enter the password again after changing the SMTP host or username")
	}
	return stored, nil
}

func (s *Server) getReachConfig(w http.ResponseWriter, r *http.Request) {
	cfg, _, err := s.loadReachConfig(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) putReachConfig(w http.ResponseWriter, r *http.Request) {
	var in reachConfigDTO
	if !decodeJSON(w, r, &in) {
		return
	}
	normalizeSMTP(&in.SMTP)
	switch {
	case in.IntervalMinutes < reachMinInterval || in.IntervalMinutes > reachMaxInterval:
		s.writeFail(w, invalid("intervalMinutes", "interval must be between 10 and 1440 minutes"))
		return
	case in.ConfirmRounds < 1 || in.ConfirmRounds > reachMaxConfirm:
		s.writeFail(w, invalid("confirmRounds", "confirmation rounds must be between 1 and 10"))
		return
	}
	if err := validateSMTP(in.SMTP); err != nil {
		s.writeFail(w, err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	prev, stored, err := s.loadReachConfig(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	password, err := resolvePassword(in.SMTP, prev.SMTP, stored)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	in.SMTP.Password, prev.SMTP.PasswordSet = "", false

	var changed []string
	for _, f := range []struct {
		name string
		diff bool
	}{
		{"enabled", prev.Enabled != in.Enabled},
		{"intervalMinutes", prev.IntervalMinutes != in.IntervalMinutes},
		{"confirmRounds", prev.ConfirmRounds != in.ConfirmRounds},
		{"smtp", prev.SMTP != in.SMTP},
		{"smtp.password", password != stored},
	} {
		if f.diff {
			changed = append(changed, f.name)
		}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	// One transaction: a new host saved next to the old password would mail that password to the new host.
	if err := s.st.SetSettings(r.Context(), map[string]string{
		settingReachConfig: string(raw), settingReachPassword: password,
	}); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "reach.configure", "reach", strings.Join(changed, ", "))
	in.SMTP.PasswordSet = password != ""
	writeJSON(w, http.StatusOK, in)
}

const reachTestBody = "这是一封测试邮件：Mintyx 面板可以通过你填写的 SMTP 服务器发信。线路从中国大陆连不上或恢复时，你会在这个邮箱收到提醒。\n\n" +
	"This is a test message: your Mintyx panel can send mail through the SMTP server you configured. " +
	"You will be notified here when a line becomes unreachable from mainland China, and when it recovers.\n"

// postReachTestEmail tries the SMTP settings in the request, so they can be checked before saving.
func (s *Server) postReachTestEmail(w http.ResponseWriter, r *http.Request) {
	var in reachSMTPDTO
	if !decodeJSON(w, r, &in) {
		return
	}
	normalizeSMTP(&in)
	if in.Host == "" {
		s.writeFail(w, invalid("smtp.host", "SMTP host is required"))
		return
	}
	if err := validateSMTP(in); err != nil {
		s.writeFail(w, err)
		return
	}
	prev, stored, err := s.loadReachConfig(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	password, err := resolvePassword(in, prev.SMTP, stored)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	msg := notify.Message{From: in.From, To: in.To, Subject: "Mintyx 测试邮件 / test message", Body: reachTestBody}
	sendErr := notify.Send(r.Context(), in.server(password), msg)
	out := map[string]any{"sent": sendErr == nil, "error": ""}
	detail := "sent"
	if sendErr != nil {
		out["error"], detail = sendErr.Error(), "failed"
	}
	s.audit(r, "reach.test_email", in.Host, detail)
	writeJSON(w, http.StatusOK, out)
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

// reachNextCheck is when the loop runs next; zero when it will not.
func reachNextCheck(cfg reachConfigDTO, targets []reach.Target, rec reachRecord, now time.Time) time.Time {
	if !cfg.Enabled || len(targets) == 0 {
		return time.Time{}
	}
	if rec.LastCheckAt.IsZero() {
		return now
	}
	every := reach.EffectiveInterval(time.Duration(cfg.IntervalMinutes)*time.Minute, reach.Cost(targets))
	next := rec.LastCheckAt.Add(every)
	if rec.RetryAt.After(next) {
		next = rec.RetryAt
	}
	return next
}

func (s *Server) reachStatus(ctx context.Context) (reachStatusDTO, error) {
	cfg, _, err := s.loadReachConfig(ctx)
	if err != nil {
		return reachStatusDTO{}, err
	}
	targets, lines, configured, err := s.reachTargets(ctx)
	if err != nil {
		return reachStatusDTO{}, err
	}
	rec, err := s.loadReachRecord(ctx)
	if err != nil {
		return reachStatusDTO{}, err
	}
	out := reachStatusDTO{
		Enabled: cfg.Enabled, Configured: configured, Running: s.reachRunning.Load(),
		LastCheckAt: timePtr(rec.LastCheckAt), NextCheckAt: timePtr(reachNextCheck(cfg, targets, rec, s.now())),
		LastError: rec.LastError, LastErrorDetail: rec.LastErrorDetail, AlertError: rec.AlertError,
		Targets: make([]reachTargetDTO, 0, len(targets)),
	}
	for _, t := range targets {
		d := reachTargetDTO{
			LineID: t.ID, LineName: t.Name, Protocol: string(lines[t.ID].Protocol),
			Host: t.Host, Port: t.Port, IPOnly: t.IPOnly, Verdict: reach.Unknown,
		}
		// State recorded for another address says nothing about this one.
		if st, ok := rec.Targets[t.ID]; ok && st.Host == t.Host && st.Port == t.Port {
			if st.Verdict != "" {
				d.Verdict, d.Since = st.Verdict, timePtr(st.Since)
			}
			d.LastResult = st.Last
			d.ChinaReached, d.ChinaAnswered = st.China.Reached, st.China.Answered
			d.ControlReached, d.ControlAnswered = st.Control.Reached, st.Control.Answered
		}
		out.Targets = append(out.Targets, d)
	}
	return out, nil
}

func (s *Server) getReachStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.reachStatus(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

var (
	errReachBusy     = errors.New("a check is already running")
	errReachDisabled = errors.New("the reachability check is turned off")
	errReachNoTarget = errors.New("there is no enabled line with an address to check")
)

func describeReachError(err error) (code, detail string) {
	var limited *reach.RateLimitError
	switch {
	case err == nil:
		return "", ""
	case errors.As(err, &limited):
		return reachErrRateLimited, err.Error()
	case errors.Is(err, reach.ErrTooManyTargets):
		return reachErrTooMany, err.Error()
	}
	return reachErrProbe, err.Error()
}

// runReachRound probes every line once, folds the result into the stored state and mails any
// confirmed change. It never holds s.mu while talking to the network.
func (s *Server) runReachRound(ctx context.Context) error {
	if !s.reachRunning.CompareAndSwap(false, true) {
		return errReachBusy
	}
	defer s.reachRunning.Store(false)

	cfg, password, err := s.loadReachConfig(ctx)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return errReachDisabled
	}
	targets, _, _, err := s.reachTargets(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errReachNoTarget
	}
	rec, err := s.loadReachRecord(ctx)
	if err != nil {
		return err
	}

	parent := ctx
	ctx, cancel := context.WithTimeout(parent, reachRoundTimeout)
	defer cancel()
	round := reach.RunRound(ctx, s.pinger, targets, rec.State.Cursor)
	if err := parent.Err(); err != nil {
		// Shutting down mid-round: half a round's "unknown" is not worth recording.
		return err
	}
	rec.State = rec.State.Apply(targets, round, cfg.ConfirmRounds, s.now())
	rec.LastError, rec.LastErrorDetail = describeReachError(round.Err)
	if round.Err != nil {
		s.log.Warn("panel: reach round incomplete", "err", round.Err)
	}

	switch {
	case len(rec.Unsent) == 0:
	case cfg.SMTP.Host == "":
		rec.Unsent, rec.AlertError = nil, ""
	default:
		subject, body := reach.AlertMail(rec.Unsent)
		msg := notify.Message{From: cfg.SMTP.From, To: cfg.SMTP.To, Subject: subject, Body: body}
		// The round may have used up its own deadline; the mail gets notify's full send timeout.
		if err := notify.Send(parent, cfg.SMTP.server(password), msg); err != nil {
			// Unsent stays, so the next round tries the same alert again.
			rec.AlertError = err.Error()
			s.log.Warn("panel: reach alert mail failed", "err", err)
		} else {
			rec.Unsent, rec.AlertError = nil, ""
		}
	}

	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.SetSetting(context.WithoutCancel(ctx), settingReachState, string(raw))
}

func (s *Server) postReachCheck(w http.ResponseWriter, r *http.Request) {
	rec, err := s.loadReachRecord(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	// Each round spends rate-limited Globalping tests; a double click must not spend two.
	if !rec.LastCheckAt.IsZero() && s.now().Sub(rec.LastCheckAt) < reachManualGap {
		writeErr(w, http.StatusTooManyRequests, codeRateLimited, "checked moments ago; wait a minute before checking again", "")
		return
	}
	// A closed browser tab must not abandon a round halfway through its measurements,
	// but shutting the panel down must.
	ctx, cancel := context.WithCancel(s.life)
	defer cancel()
	err = s.runReachRound(ctx)
	switch {
	case errors.Is(err, errReachBusy), errors.Is(err, errReachDisabled), errors.Is(err, errReachNoTarget):
		writeErr(w, http.StatusConflict, codeConflict, err.Error(), "")
		return
	case err != nil:
		s.writeFail(w, err)
		return
	}
	st, err := s.reachStatus(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	detail := fmt.Sprintf("%d lines", len(st.Targets))
	if st.LastError != "" {
		detail += ", " + st.LastError
	}
	s.audit(r, "reach.check", "reach", detail)
	writeJSON(w, http.StatusOK, st)
}

// ReachRunner runs a round whenever one is due. It wakes far more often than rounds happen,
// so a changed interval or a freshly enabled check takes effect within one wake-up.
type ReachRunner struct {
	s    *Server
	wake time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) NewReachRunner(wake time.Duration) *ReachRunner {
	return &ReachRunner{s: s, wake: wake}
}

// Tick runs a round if the check is enabled and the next one is due; ran reports whether it did.
func (r *ReachRunner) Tick(ctx context.Context) (ran bool, err error) {
	s := r.s
	cfg, _, err := s.loadReachConfig(ctx)
	if err != nil || !cfg.Enabled {
		return false, err
	}
	targets, _, _, err := s.reachTargets(ctx)
	if err != nil {
		return false, err
	}
	rec, err := s.loadReachRecord(ctx)
	if err != nil {
		return false, err
	}
	next := reachNextCheck(cfg, targets, rec, s.now())
	if next.IsZero() || next.After(s.now()) {
		return false, nil
	}
	if err := s.runReachRound(ctx); err != nil && !errors.Is(err, errReachBusy) {
		return false, err
	}
	return true, nil
}

// Start runs Tick every wake until Stop or ctx is done. Starting twice is a no-op.
func (r *ReachRunner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		t := time.NewTicker(r.wake)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := r.Tick(ctx); err != nil && ctx.Err() == nil {
					r.s.log.Warn("panel: reach tick", "err", err)
				}
			}
		}
	}(r.done)
}

// Stop cancels the loop and waits for an in-flight round to finish.
func (r *ReachRunner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
