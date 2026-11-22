package panel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/ysuhao/mintyx-next/internal/attack"
	"github.com/ysuhao/mintyx-next/internal/model"
	"github.com/ysuhao/mintyx-next/internal/rdap"
	"github.com/ysuhao/mintyx-next/internal/store"
)

const (
	settingAttackConfig = "attack.config"
	settingAttackCursor = "attack.sshCursor"

	attackRetention = 30 * 24 * time.Hour
	attackTrendDays = 14
	// The first read goes back a day, so the page has something to show right after an upgrade.
	attackFirstBacklog = 24 * time.Hour
	// After a lost cursor only the last minute is re-read: counting some lines twice is worse than missing a few.
	attackResyncBacklog = time.Minute
	attackPruneEvery    = time.Hour

	// Eight lookups a tick is under a thousand an hour, well inside what the registries allow one client.
	attackLookupsPerTick  = 8
	attackLookupGap       = time.Second
	attackLookupRetry     = 24 * time.Hour
	attackLookupMinPause  = 15 * time.Minute
	attackLookupMaxErrors = 3

	attackDefaultLimit = 50
	attackMaxLimit     = 200
	attackDay          = "2006-01-02"

	sshLogStarting    = "starting"
	sshLogOK          = "ok"
	sshLogUnavailable = "unavailable"
	sshLogError       = "error"

	lookupFailNotFound = "not_found"
	lookupFailError    = "error"
)

// Whois finds the network an address belongs to; the panel uses RDAP.
type Whois interface {
	Lookup(ctx context.Context, ip netip.Addr) (model.Whois, error)
}

// SSHLogReader feeds fn the sshd messages logged after cursor, or within backlog when cursor is
// empty, and returns the cursor to continue from.
type SSHLogReader func(ctx context.Context, cursor string, backlog time.Duration, fn func(at time.Time, msg string)) (string, error)

// attackState is what the collector loop last ran into, for the status the page shows.
type attackState struct {
	mu          sync.Mutex
	sshLog      string
	backlog     time.Duration
	lookupError string
	pausedUntil time.Time
	prunedAt    time.Time
}

type attackConfigDTO struct {
	// Lookup lets the panel ask the address registries where each source is from.
	Lookup bool `json:"lookup"`
}

func (s *Server) loadAttackConfig(ctx context.Context) (attackConfigDTO, error) {
	var cfg attackConfigDTO
	raw, found, err := s.st.GetSetting(ctx, settingAttackConfig)
	if err != nil || !found {
		return cfg, err
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return attackConfigDTO{}, fmt.Errorf("panel: stored attack config: %w", err)
	}
	return cfg, nil
}

func (s *Server) getAttackConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadAttackConfig(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) putAttackConfig(w http.ResponseWriter, r *http.Request) {
	var in attackConfigDTO
	if !decodeJSON(w, r, &in) {
		return
	}
	raw, err := json.Marshal(in)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.SetSetting(r.Context(), settingAttackConfig, string(raw)); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "attack.configure", "attacks", "lookup="+strconv.FormatBool(in.Lookup))
	writeJSON(w, http.StatusOK, in)
}

type attackKindTotalDTO struct {
	Kind    string `json:"kind"`
	Hits    int64  `json:"hits"`
	Sources int64  `json:"sources"`
}

type attackOriginDTO struct {
	Country string `json:"country"`
	Sources int64  `json:"sources"`
	Hits    int64  `json:"hits"`
}

type attackNetworkDTO struct {
	Network    string `json:"network"`
	Country    string `json:"country"`
	AbuseEmail string `json:"abuseEmail"`
	Sources    int64  `json:"sources"`
	Hits       int64  `json:"hits"`
}

type attackDayDTO struct {
	Day  string           `json:"day"`
	Hits map[string]int64 `json:"hits"`
}

type attackLookupDTO struct {
	Enabled  bool  `json:"enabled"`
	LookedUp int64 `json:"lookedUp"`
	Pending  int64 `json:"pending"`
	// Error is the last lookup's failure, "" when it worked; PausedUntil is set while a registry's rate limit is waited out.
	Error       string     `json:"error"`
	PausedUntil *time.Time `json:"pausedUntil"`
}

type attackSummaryDTO struct {
	Sources       int64                `json:"sources"`
	Hits          int64                `json:"hits"`
	RetentionDays int                  `json:"retentionDays"`
	Kinds         []attackKindTotalDTO `json:"kinds"`
	Countries     []attackOriginDTO    `json:"countries"`
	Networks      []attackNetworkDTO   `json:"networks"`
	// Daily has one entry per day of the trend window, oldest first, days without attacks included.
	Daily  []attackDayDTO  `json:"daily"`
	Lookup attackLookupDTO `json:"lookup"`
	// SSHLog: "starting" before the first read, "ok", "unavailable" (no systemd journal) or "error".
	SSHLog string `json:"sshLog"`
}

func (s *Server) getAttackSummary(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadAttackConfig(r.Context())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	today := s.now().UTC()
	first := today.AddDate(0, 0, -(attackTrendDays - 1))
	sum, err := s.st.AttackSummary(r.Context(), first.Format(attackDay))
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := attackSummaryDTO{
		Sources: sum.Sources, Hits: sum.Hits, RetentionDays: int(attackRetention / (24 * time.Hour)),
		Kinds:     make([]attackKindTotalDTO, 0, len(sum.Kinds)),
		Countries: make([]attackOriginDTO, 0, len(sum.Countries)),
		Networks:  make([]attackNetworkDTO, 0, len(sum.Networks)),
		Daily:     make([]attackDayDTO, 0, attackTrendDays),
		Lookup:    attackLookupDTO{Enabled: cfg.Lookup, LookedUp: sum.LookedUp, Pending: sum.Pending},
	}
	for _, k := range sum.Kinds {
		out.Kinds = append(out.Kinds, attackKindTotalDTO(k))
	}
	for _, c := range sum.Countries {
		out.Countries = append(out.Countries, attackOriginDTO(c))
	}
	for _, n := range sum.Networks {
		out.Networks = append(out.Networks, attackNetworkDTO(n))
	}
	days := map[string]map[string]int64{}
	for _, d := range sum.Daily {
		if days[d.Day] == nil {
			days[d.Day] = map[string]int64{}
		}
		days[d.Day][d.Kind] = d.Hits
	}
	for i := range attackTrendDays {
		day := first.AddDate(0, 0, i).Format(attackDay)
		hits := days[day]
		if hits == nil {
			hits = map[string]int64{}
		}
		out.Daily = append(out.Daily, attackDayDTO{Day: day, Hits: hits})
	}

	st := &s.attackState
	st.mu.Lock()
	out.SSHLog = st.sshLog
	if cfg.Lookup {
		out.Lookup.Error = st.lookupError
		if st.pausedUntil.After(s.now()) {
			out.Lookup.PausedUntil = timePtr(st.pausedUntil)
		}
	}
	st.mu.Unlock()
	if out.SSHLog == "" {
		out.SSHLog = sshLogStarting
	}
	writeJSON(w, http.StatusOK, out)
}

type attackerKindDTO struct {
	Kind    string    `json:"kind"`
	Hits    int64     `json:"hits"`
	FirstAt time.Time `json:"firstAt"`
	LastAt  time.Time `json:"lastAt"`
}

type attackerDTO struct {
	IP      string            `json:"ip"`
	FirstAt time.Time         `json:"firstAt"`
	LastAt  time.Time         `json:"lastAt"`
	Hits    int64             `json:"hits"`
	Kinds   []attackerKindDTO `json:"kinds"`
	// LookedUp is false until the registries answered about this address; LookupError is
	// "not_found" or "error" when asking failed, and the origin fields are then empty.
	LookedUp    bool   `json:"lookedUp"`
	LookupError string `json:"lookupError"`
	Country     string `json:"country"`
	Network     string `json:"network"`
	NetRange    string `json:"netRange"`
	AbuseEmail  string `json:"abuseEmail"`
	Registry    string `json:"registry"`
}

func toAttackerDTO(a model.Attacker) attackerDTO {
	d := attackerDTO{
		IP: a.IP, FirstAt: a.FirstAt, LastAt: a.LastAt, Hits: a.Hits, Kinds: make([]attackerKindDTO, 0, len(a.Kinds)),
		LookedUp: a.LookedUpAt != nil && a.LookupError == "", LookupError: a.LookupError,
		Country: a.Country, Network: a.Network, NetRange: a.NetRange, AbuseEmail: a.AbuseEmail, Registry: a.Registry,
	}
	for _, k := range a.Kinds {
		d.Kinds = append(d.Kinds, attackerKindDTO{Kind: k.Kind, Hits: k.Hits, FirstAt: k.FirstAt, LastAt: k.LastAt})
	}
	return d
}

func (s *Server) listAttacks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AttackFilter{Kind: q.Get("kind"), Country: q.Get("country"), Limit: attackDefaultLimit}
	if f.Kind != "" && !attack.Kind(f.Kind).Valid() {
		s.writeFail(w, invalid("kind", "unknown attack kind"))
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > attackMaxLimit {
			s.writeFail(w, invalid("limit", "limit must be between 1 and 200"))
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			s.writeFail(w, invalid("offset", "offset must not be negative"))
			return
		}
		f.Offset = n
	}
	list, total, err := s.st.ListAttackers(r.Context(), f)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	out := make([]attackerDTO, 0, len(list))
	for _, a := range list {
		out = append(out, toAttackerDTO(a))
	}
	writeJSON(w, http.StatusOK, map[string]any{"attackers": out, "total": total})
}

// getAttackReport drafts the complaint for one source. Nothing is sent: the owner mails it themselves.
func (s *Server) getAttackReport(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		writeErr(w, http.StatusNotFound, codeNotFound, "not found", "")
		return
	}
	a, err := s.st.GetAttacker(r.Context(), ip.String())
	if err != nil {
		s.writeFail(w, err)
		return
	}
	target, _, err := s.st.GetSetting(r.Context(), settingPublicHost)
	if err != nil {
		s.writeFail(w, err)
		return
	}
	subject, body := attack.Report(a, target)
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": a.IP, "to": a.AbuseEmail, "network": a.Network, "subject": subject, "body": body,
	})
}

func (s *Server) clearAttacks(w http.ResponseWriter, r *http.Request) {
	if err := s.st.ClearAttacks(r.Context()); err != nil {
		s.writeFail(w, err)
		return
	}
	s.audit(r, "attack.clear", "attacks", "")
	w.WriteHeader(http.StatusNoContent)
}

// AttackRunner reads sshd's log, stores what the collector gathered and, when the owner turned
// lookups on, asks the registries about sources whose network is not known yet.
type AttackRunner struct {
	s        *Server
	interval time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Server) NewAttackRunner(interval time.Duration) *AttackRunner {
	return &AttackRunner{s: s, interval: interval}
}

// Tick runs one pass. Its steps are independent: a failure in one does not skip the others.
func (r *AttackRunner) Tick(ctx context.Context) error {
	s := r.s
	return errors.Join(s.readSSHLog(ctx), s.storeAttacks(ctx), s.pruneAttacks(ctx), s.lookUpAttackers(ctx))
}

func (s *Server) readSSHLog(ctx context.Context) error {
	st := &s.attackState
	st.mu.Lock()
	backlog := st.backlog
	st.mu.Unlock()
	if backlog == 0 {
		backlog = attackFirstBacklog
	}
	cursor, _, err := s.st.GetSetting(ctx, settingAttackCursor)
	if err != nil {
		return err
	}
	next, err := s.sshLog(ctx, cursor, backlog, s.attacks.SSH)

	state := sshLogOK
	switch {
	case errors.Is(err, attack.ErrNoJournal):
		state, err = sshLogUnavailable, nil
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		// Most likely the journal rotated the cursor away; start again from now.
		state, next = sshLogError, ""
	}
	st.mu.Lock()
	st.sshLog = state
	if state == sshLogError {
		st.backlog = attackResyncBacklog
	}
	st.mu.Unlock()
	if next != cursor {
		if serr := s.st.SetSetting(context.WithoutCancel(ctx), settingAttackCursor, next); serr != nil {
			return errors.Join(err, serr)
		}
	}
	return err
}

func (s *Server) storeAttacks(ctx context.Context) error {
	hits, trusted := s.attacks.Drain()
	// Already drained, so a shutdown must not lose them.
	return s.st.RecordAttacks(context.WithoutCancel(ctx), hits, trusted, s.now())
}

func (s *Server) pruneAttacks(ctx context.Context) error {
	st := &s.attackState
	now := s.now()
	st.mu.Lock()
	due := now.Sub(st.prunedAt) >= attackPruneEvery
	if due {
		st.prunedAt = now
	}
	st.mu.Unlock()
	if !due {
		return nil
	}
	cutoff := now.Add(-attackRetention)
	return s.st.PruneAttacks(ctx, cutoff, cutoff.Format(attackDay))
}

func (s *Server) lookUpAttackers(ctx context.Context) error {
	cfg, err := s.loadAttackConfig(ctx)
	if err != nil || !cfg.Lookup {
		return err
	}
	st := &s.attackState
	st.mu.Lock()
	paused := st.pausedUntil.After(s.now())
	st.mu.Unlock()
	if paused {
		return nil
	}
	ips, err := s.st.AttackersToLookUp(ctx, attackLookupsPerTick, s.now().Add(-attackLookupRetry))
	if err != nil {
		return err
	}
	failures, lastError := 0, ""
	for i, text := range ips {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.lookupGap):
			}
		}
		ip, err := netip.ParseAddr(text)
		if err != nil {
			continue
		}
		who, err := s.whois.Lookup(ctx, ip)
		var limited *rdap.RateLimitError
		failure := ""
		switch {
		case err == nil:
			lastError = ""
		case ctx.Err() != nil:
			return ctx.Err()
		case errors.As(err, &limited):
			st.mu.Lock()
			st.pausedUntil = s.now().Add(max(limited.RetryAfter, attackLookupMinPause))
			st.lookupError = err.Error()
			st.mu.Unlock()
			return nil
		case errors.Is(err, rdap.ErrNotFound), errors.Is(err, rdap.ErrNoRegistry):
			failure = lookupFailNotFound
		default:
			failure, lastError = lookupFailError, err.Error()
			failures++
		}
		if err := s.st.SetAttackerWhois(context.WithoutCancel(ctx), text, who, failure, s.now()); err != nil {
			return err
		}
		// The network is probably down; the rest of the batch would only fail the same way.
		if failures >= attackLookupMaxErrors {
			break
		}
	}
	if len(ips) > 0 {
		st.mu.Lock()
		st.lookupError = lastError
		st.mu.Unlock()
	}
	return nil
}

// Start runs Tick every interval until Stop or ctx is done. Starting twice is a no-op.
func (r *AttackRunner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.done = make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		tick := func() {
			if err := r.Tick(ctx); err != nil && ctx.Err() == nil {
				r.s.log.Warn("panel: attack tick", "err", err)
			}
		}
		// Straight away, so the page is not empty for the first interval after a start.
		tick()
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				tick()
			}
		}
	}(r.done)
}

// Stop cancels the loop, waits for an in-flight tick, then stores what was collected meanwhile.
func (r *AttackRunner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
		if err := r.s.storeAttacks(context.Background()); err != nil {
			r.s.log.Warn("panel: storing attacks at shutdown", "err", err)
		}
	}
}
