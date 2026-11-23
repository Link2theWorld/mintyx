package panel

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/attack"
	"github.com/Link2theWorld/mintyx/internal/model"
	"github.com/Link2theWorld/mintyx/internal/rdap"
)

// fakeSSHLog plays the journal: each read hands out the queued messages once.
type fakeSSHLog struct {
	mu       sync.Mutex
	queued   []string
	err      error
	cursors  []string
	backlogs []time.Duration
	at       time.Time
}

func (l *fakeSSHLog) read(_ context.Context, cursor string, backlog time.Duration, fn func(time.Time, string)) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cursors, l.backlogs = append(l.cursors, cursor), append(l.backlogs, backlog)
	if l.err != nil {
		return cursor, l.err
	}
	for _, m := range l.queued {
		fn(l.at, m)
	}
	if len(l.queued) == 0 {
		return cursor, nil
	}
	l.queued = nil
	return cursor + "+", nil
}

type fakeWhois struct {
	mu      sync.Mutex
	answers map[string]model.Whois
	errs    map[string]error
	asked   []string
}

func (f *fakeWhois) Lookup(_ context.Context, ip netip.Addr) (model.Whois, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, ip.String())
	if err := f.errs[ip.String()]; err != nil {
		return model.Whois{}, err
	}
	if w, ok := f.answers[ip.String()]; ok {
		return w, nil
	}
	return model.Whois{}, rdap.ErrNotFound
}

type attackFixture struct {
	*fixture
	log    *fakeSSHLog
	whois  *fakeWhois
	col    *attack.Collector
	runner *AttackRunner
	cookie *http.Cookie
}

func newAttackFixture(t *testing.T) *attackFixture {
	t.Helper()
	a := &attackFixture{
		log:   &fakeSSHLog{},
		whois: &fakeWhois{answers: map[string]model.Whois{}, errs: map[string]error{}},
		col:   attack.NewCollector(),
	}
	a.fixture = newFixture(t, func(c *Config) { c.SSHLog, c.Whois, c.Attacks = a.log.read, a.whois, a.col })
	a.log.at = *a.clock
	a.srv.lookupGap = 0
	a.runner = a.srv.NewAttackRunner(time.Hour)
	a.cookie = a.setup()
	return a
}

func (a *attackFixture) tick() {
	a.t.Helper()
	if err := a.runner.Tick(context.Background()); err != nil {
		a.t.Fatalf("tick: %v", err)
	}
}

func (a *attackFixture) summary() attackSummaryDTO {
	a.t.Helper()
	w := a.do("GET", "/api/attacks/summary", nil, withCookie(a.cookie))
	expectStatus(a.t, w, http.StatusOK)
	return decodeBody[attackSummaryDTO](a.t, w)
}

type attackListBody struct {
	Attackers []attackerDTO `json:"attackers"`
	Total     int64         `json:"total"`
}

func (a *attackFixture) list(query string) attackListBody {
	a.t.Helper()
	w := a.do("GET", "/api/attacks"+query, nil, withCookie(a.cookie))
	expectStatus(a.t, w, http.StatusOK)
	return decodeBody[attackListBody](a.t, w)
}

func TestAttacksAreCollectedFromSSHAndXray(t *testing.T) {
	a := newAttackFixture(t)
	if s := a.summary(); s.SSHLog != sshLogStarting || s.Sources != 0 || len(s.Daily) != attackTrendDays || s.RetentionDays != 30 {
		t.Fatalf("summary before the first tick: %+v", s)
	}

	a.log.queued = []string{
		"Invalid user admin from 203.0.113.5 port 40001",
		"Connection closed by invalid user admin 203.0.113.5 port 40001 [preauth]",
		"Failed password for root from 203.0.113.5 port 40002 ssh2",
		"Connection closed by 198.51.100.9 port 40003 [preauth]",
		"Accepted publickey for ops from 192.0.2.77 port 40004 ssh2: ED25519 SHA256:abc",
		"Connection closed by authenticating user ops 192.0.2.77 port 40005 [preauth]",
	}
	a.col.Xray(*a.clock, "2026/06/01 12:00:00.000000 [Info] transport/internet/tcp: REALITY: processed invalid connection from 198.51.100.9:5000: failed to read client hello")
	a.tick()
	a.tick() // nothing new: the same lines must not be counted again

	s := a.summary()
	if s.SSHLog != sshLogOK || s.Sources != 2 || s.Hits != 4 || s.Lookup.Enabled || s.Lookup.Pending != 2 {
		t.Fatalf("summary = %+v", s)
	}
	kinds := map[string]attackKindTotalDTO{}
	for _, k := range s.Kinds {
		kinds[k.Kind] = k
	}
	for kind, hits := range map[string]int64{"ssh_invalid_user": 1, "ssh_login": 1, "ssh_scan": 1, "line_probe": 1} {
		if kinds[kind].Hits != hits {
			t.Errorf("%s: %d hits, want %d (all: %+v)", kind, kinds[kind].Hits, hits, s.Kinds)
		}
	}
	today := s.Daily[len(s.Daily)-1]
	if today.Day != "2026-06-01" || today.Hits["ssh_login"] != 1 || len(s.Daily[0].Hits) != 0 || s.Daily[0].Day != "2026-05-19" {
		t.Errorf("daily = %+v", s.Daily)
	}

	// The journal is read from the stored cursor, a day back the first time only.
	if got := a.log.cursors; len(got) != 2 || got[0] != "" || got[1] != "+" {
		t.Errorf("cursors = %q", got)
	}
	if a.log.backlogs[0] != attackFirstBacklog {
		t.Errorf("first backlog = %v", a.log.backlogs[0])
	}

	all := a.list("")
	if all.Total != 2 || len(all.Attackers) != 2 {
		t.Fatalf("list = %+v", all)
	}
	for _, at := range all.Attackers {
		if at.IP == "192.0.2.77" {
			t.Errorf("the address that logged in with a key is listed: %+v", at)
		}
		if at.LookedUp || at.Country != "" {
			t.Errorf("lookups are off, yet %+v", at)
		}
	}
	if got := a.list("?kind=ssh_login"); got.Total != 1 || got.Attackers[0].IP != "203.0.113.5" || len(got.Attackers[0].Kinds) != 2 {
		t.Errorf("by kind = %+v", got)
	}
	if len(a.whois.asked) != 0 {
		t.Errorf("registries were asked about %v with lookups off", a.whois.asked)
	}
}

func TestSSHCursorIsNotStoredBeforeTheHits(t *testing.T) {
	a := newAttackFixture(t)
	a.log.queued = []string{"Failed password for root from 203.0.113.5 port 40002 ssh2"}
	a.srv.readSSHLog(context.Background())
	_, found, err := a.st.GetSetting(context.Background(), settingAttackCursor)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("the journal cursor was stored before the hits read from it")
	}
}

func TestAFailedStoreNeitherLosesXrayHitsNorCountsSSHHitsTwice(t *testing.T) {
	a := newAttackFixture(t)
	sshLine := "Failed password for root from 203.0.113.5 port 40002 ssh2"
	a.log.queued = []string{sshLine}
	a.col.Xray(*a.clock, "2026/06/01 12:00:00.000000 [Info] transport/internet/tcp: REALITY: processed invalid connection from 198.51.100.9:5000: failed to read client hello")

	// Make only the attack write fail, while settings reads and later writes keep working.
	raw, err := sql.Open("sqlite", a.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER fail_attack_recording BEFORE INSERT ON attackers BEGIN
		SELECT RAISE(FAIL, 'injected attack store failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := a.runner.Tick(context.Background()); err == nil {
		t.Fatal("tick with a failing attack store returned nil")
	}
	if _, err := raw.Exec(`DROP TRIGGER fail_attack_recording`); err != nil {
		t.Fatal(err)
	}

	// Because the cursor never moved, the journal hands the same line to the next tick.
	a.log.queued = []string{sshLine}
	a.tick()
	s := a.summary()
	if s.Hits != 2 || s.Sources != 2 {
		t.Fatalf("summary after the retry = %+v; want one SSH hit and one Xray hit from two sources", s)
	}
	kinds := map[string]int64{}
	for _, k := range s.Kinds {
		kinds[k.Kind] = k.Hits
	}
	if kinds["ssh_login"] != 1 || kinds["line_probe"] != 1 {
		t.Fatalf("kind totals after the retry = %+v; want one of each, no duplicate SSH hit", kinds)
	}
}

func TestAttackLookupsRunOnlyWhenTurnedOn(t *testing.T) {
	a := newAttackFixture(t)
	a.log.queued = []string{
		"Failed password for root from 203.0.113.5 port 40002 ssh2",
		"Connection closed by 198.51.100.9 port 40003 [preauth]",
		"Connection closed by 198.51.100.10 port 40004 [preauth]",
	}
	nl := model.Whois{Country: "NL", Network: "Example B.V.", NetRange: "203.0.113.0/24", AbuseEmail: "abuse@example.nl", Registry: "RIPE NCC"}
	a.whois.answers["203.0.113.5"] = nl
	a.whois.errs["198.51.100.10"] = errors.New("dial tcp: timeout")
	a.tick()

	w := a.do("PUT", "/api/attacks/config", map[string]any{"lookup": true}, withCookie(a.cookie))
	expectStatus(t, w, http.StatusOK)
	if got := decodeBody[attackConfigDTO](t, a.do("GET", "/api/attacks/config", nil, withCookie(a.cookie))); !got.Lookup {
		t.Fatalf("config = %+v", got)
	}
	a.tick()
	a.tick() // settled and failed lookups are not repeated straight away
	if len(a.whois.asked) != 3 {
		t.Fatalf("asked %v, want each address once", a.whois.asked)
	}

	s := a.summary()
	if !s.Lookup.Enabled || s.Lookup.LookedUp != 1 || s.Lookup.Pending != 0 {
		t.Errorf("lookup status = %+v", s.Lookup)
	}
	if len(s.Countries) != 1 || s.Countries[0] != (attackOriginDTO{Country: "NL", Sources: 1, Hits: 1}) {
		t.Errorf("countries = %+v", s.Countries)
	}
	if len(s.Networks) != 1 || s.Networks[0].AbuseEmail != "abuse@example.nl" {
		t.Errorf("networks = %+v", s.Networks)
	}
	by := map[string]attackerDTO{}
	for _, at := range a.list("").Attackers {
		by[at.IP] = at
	}
	if at := by["203.0.113.5"]; !at.LookedUp || at.Country != "NL" || at.AbuseEmail != "abuse@example.nl" || at.Registry != "RIPE NCC" {
		t.Errorf("looked-up attacker = %+v", at)
	}
	if at := by["198.51.100.9"]; at.LookedUp || at.LookupError != lookupFailNotFound {
		t.Errorf("unregistered attacker = %+v", at)
	}
	if at := by["198.51.100.10"]; at.LookedUp || at.LookupError != lookupFailError {
		t.Errorf("attacker whose lookup failed = %+v", at)
	}
	if got := a.list("?country=NL"); got.Total != 1 {
		t.Errorf("by country = %+v", got)
	}

	// Lookups that failed, for either reason, are tried again a day later; the settled one is not.
	*a.clock = a.clock.Add(attackLookupRetry + time.Minute)
	a.tick()
	if got := strings.Join(a.whois.asked[3:], " "); got != "198.51.100.10 198.51.100.9" {
		t.Errorf("after a day asked %q", got)
	}
}

func TestAttackLookupsPauseWhenRateLimited(t *testing.T) {
	a := newAttackFixture(t)
	a.log.queued = []string{
		"Failed password for root from 203.0.113.5 port 40002 ssh2",
		"Connection closed by 198.51.100.9 port 40003 [preauth]",
	}
	a.whois.errs["203.0.113.5"] = &rdap.RateLimitError{RetryAfter: time.Hour}
	a.whois.errs["198.51.100.9"] = &rdap.RateLimitError{RetryAfter: time.Hour}
	expectStatus(t, a.do("PUT", "/api/attacks/config", map[string]any{"lookup": true}, withCookie(a.cookie)), http.StatusOK)
	a.tick()
	a.tick()
	if len(a.whois.asked) != 1 {
		t.Fatalf("asked %v; a rate limit must stop the batch and the next tick", a.whois.asked)
	}
	s := a.summary()
	if s.Lookup.PausedUntil == nil || !s.Lookup.PausedUntil.Equal(a.clock.Add(time.Hour)) || s.Lookup.Error == "" || s.Lookup.Pending != 2 {
		t.Errorf("lookup status = %+v", s.Lookup)
	}
	*a.clock = a.clock.Add(61 * time.Minute)
	a.tick()
	if len(a.whois.asked) != 2 {
		t.Errorf("after the pause asked %v", a.whois.asked)
	}
}

func TestSSHLogStates(t *testing.T) {
	a := newAttackFixture(t)
	a.log.err = attack.ErrNoJournal
	a.tick()
	if s := a.summary(); s.SSHLog != sshLogUnavailable {
		t.Errorf("without a journal: %q", s.SSHLog)
	}

	a.log.err = nil
	a.log.queued = []string{"Connection closed by 198.51.100.9 port 40003 [preauth]"}
	a.tick()
	// A cursor the journal no longer knows: the error is reported and reading restarts from now.
	a.log.err = errors.New("journalctl: Failed to seek to cursor")
	if err := a.runner.Tick(context.Background()); err == nil {
		t.Fatal("tick with a failing journal returned nil")
	}
	if s := a.summary(); s.SSHLog != sshLogError {
		t.Errorf("failing journal: %q", s.SSHLog)
	}
	a.log.err = nil
	a.tick()
	n := len(a.log.cursors)
	if a.log.cursors[n-1] != "" || a.log.backlogs[n-1] != attackResyncBacklog {
		t.Errorf("after losing the cursor read from %q with backlog %v", a.log.cursors[n-1], a.log.backlogs[n-1])
	}
	if s := a.summary(); s.SSHLog != sshLogOK || s.Hits != 1 {
		t.Errorf("recovered: %+v", s)
	}
}

func TestAttackReport(t *testing.T) {
	a := newAttackFixture(t)
	a.log.queued = []string{"Failed password for root from 2001:db8::5 port 40002 ssh2"}
	a.whois.answers["2001:db8::5"] = model.Whois{Network: "Example Net", AbuseEmail: "abuse@example.net"}
	expectStatus(t, a.do("PUT", "/api/attacks/config", map[string]any{"lookup": true}, withCookie(a.cookie)), http.StatusOK)
	expectStatus(t, a.do("PUT", "/api/settings", map[string]any{"publicHost": "198.51.100.20", "subscriptionBaseUrl": ""}, withCookie(a.cookie)), http.StatusOK)
	a.tick()

	// Any spelling of the address finds it.
	w := a.do("GET", "/api/attacks/2001:0db8::0005/report", nil, withCookie(a.cookie))
	expectStatus(t, w, http.StatusOK)
	got := decodeBody[map[string]string](t, w)
	if got["ip"] != "2001:db8::5" || got["to"] != "abuse@example.net" || got["network"] != "Example Net" {
		t.Errorf("report = %+v", got)
	}
	if got["subject"] != "Abuse report: SSH login attempts (password guessing) from 2001:db8::5" {
		t.Errorf("subject = %q", got["subject"])
	}
	for _, want := range []string{"Destination: 198.51.100.20", "Failed password for root from 2001:db8::5 port 40002 ssh2"} {
		if !strings.Contains(got["body"], want) {
			t.Errorf("body lacks %q:\n%s", want, got["body"])
		}
	}
	expectError(t, a.do("GET", "/api/attacks/203.0.113.99/report", nil, withCookie(a.cookie)), http.StatusNotFound, codeNotFound, "")
	expectError(t, a.do("GET", "/api/attacks/nonsense/report", nil, withCookie(a.cookie)), http.StatusNotFound, codeNotFound, "")
}

func TestAttackEndpointsValidateAndRequireLogin(t *testing.T) {
	a := newAttackFixture(t)
	for _, p := range []string{"/api/attacks", "/api/attacks/summary", "/api/attacks/config", "/api/attacks/203.0.113.5/report"} {
		expectError(t, a.do("GET", p, nil), http.StatusUnauthorized, codeUnauthorized, "")
	}
	expectError(t, a.do("DELETE", "/api/attacks", nil), http.StatusUnauthorized, codeUnauthorized, "")
	expectError(t, a.do("GET", "/api/attacks?kind=nope", nil, withCookie(a.cookie)), http.StatusBadRequest, codeInvalid, "kind")
	expectError(t, a.do("GET", "/api/attacks?limit=0", nil, withCookie(a.cookie)), http.StatusBadRequest, codeInvalid, "limit")
	expectError(t, a.do("GET", "/api/attacks?limit=201", nil, withCookie(a.cookie)), http.StatusBadRequest, codeInvalid, "limit")
	expectError(t, a.do("GET", "/api/attacks?offset=-1", nil, withCookie(a.cookie)), http.StatusBadRequest, codeInvalid, "offset")

	a.log.queued = []string{"Connection closed by 198.51.100.9 port 40003 [preauth]"}
	a.tick()
	expectStatus(t, a.do("DELETE", "/api/attacks", nil, withCookie(a.cookie)), http.StatusNoContent)
	if s := a.summary(); s.Sources != 0 || len(s.Kinds) != 0 {
		t.Errorf("after clearing: %+v", s)
	}
	entries, err := a.st.ListAudit(context.Background(), 10, 0)
	if err != nil || entries[0].Action != "attack.clear" {
		t.Errorf("audit = %+v, %v", entries, err)
	}
}

func TestOldAttacksArePruned(t *testing.T) {
	a := newAttackFixture(t)
	a.log.queued = []string{"Connection closed by 198.51.100.9 port 40003 [preauth]"}
	a.tick()
	*a.clock = a.clock.Add(attackRetention + 26*time.Hour)
	a.tick()
	// The session is long expired by now, so look in the store.
	if sum, err := a.st.AttackSummary(context.Background(), "2026-01-01"); err != nil || sum.Sources != 0 || len(sum.Daily) != 0 {
		t.Errorf("a source last seen over the retention ago is still there: %+v, %v", sum, err)
	}
}
