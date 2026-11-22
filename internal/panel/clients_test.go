package panel

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
)

func itoa(id int64) string { return strconv.FormatInt(id, 10) }

func TestCreateClientSyncsOnceAndHidesSecrets(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("POST", "/api/clients", map[string]any{"name": "phone", "quotaBytes": 1000, "expiresAt": nil}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	if n := f.eng.syncCount(); n != 1 {
		t.Fatalf("syncs = %d, want 1", n)
	}
	stored, err := f.st.ListClients(t.Context())
	if err != nil || len(stored) != 1 {
		t.Fatalf("stored clients = %v, %v", stored, err)
	}
	for _, body := range []string{w.Body.String(), f.do("GET", "/api/clients", nil, withCookie(c)).Body.String()} {
		if strings.Contains(body, stored[0].Secret) || strings.Contains(body, stored[0].SubToken) {
			t.Fatalf("client JSON leaks secret or token: %s", body)
		}
	}
}

func TestClientValidation(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	for _, tc := range []struct {
		name  string
		body  string
		field string
	}{
		{"no name", `{"name":" ","quotaBytes":0}`, "name"},
		{"negative quota", `{"name":"a","quotaBytes":-1}`, "quotaBytes"},
		{"quota wrong type", `{"name":"a","quotaBytes":"lots"}`, "quotaBytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectError(t, f.do("POST", "/api/clients", tc.body, withCookie(c)), http.StatusBadRequest, codeInvalid, tc.field)
		})
	}
	f.createClient(c, "dup", 0)
	expectError(t, f.do("POST", "/api/clients", `{"name":"dup"}`, withCookie(c)), http.StatusConflict, codeConflict, "name")
}

func TestSyncFailureReturns502ButKeepsData(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	f.eng.failSync(errors.New("xray rejected config"))
	w := f.do("POST", "/api/clients", map[string]any{"name": "laptop"}, withCookie(c))
	expectError(t, w, http.StatusBadGateway, codeEngine, "")
	clients, err := f.st.ListClients(t.Context())
	if err != nil || len(clients) != 1 || clients[0].Name != "laptop" {
		t.Fatalf("after 502 stored clients = %+v, %v; want the laptop row", clients, err)
	}
	e, _ := f.st.ListAudit(t.Context(), 1, 0)
	if e[0].Action != "client.create" || e[0].Target != "laptop" {
		t.Fatalf("saved-but-unapplied change not audited: %+v", e[0])
	}
}

func TestBlocksLiftImmediately(t *testing.T) {
	past := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		setup  func(f *fixture, id int64)
		action func(f *fixture, c *http.Cookie, id int64) int
	}{
		{
			"reset traffic lifts quota block",
			func(f *fixture, id int64) { overQuota(f, id) },
			func(f *fixture, c *http.Cookie, id int64) int {
				return f.do("POST", "/api/clients/"+itoa(id)+"/reset-traffic", nil, withCookie(c)).Code
			},
		},
		{
			"raising quota lifts quota block",
			func(f *fixture, id int64) { overQuota(f, id) },
			func(f *fixture, c *http.Cookie, id int64) int {
				return f.do("PUT", "/api/clients/"+itoa(id), map[string]any{"name": "phone", "quotaBytes": 10_000}, withCookie(c)).Code
			},
		},
		{
			"later expiry lifts expired block",
			func(f *fixture, id int64) {
				if err := f.st.SetClientDisabled(f.t.Context(), id, model.DisabledExpired); err != nil {
					f.t.Fatal(err)
				}
			},
			func(f *fixture, c *http.Cookie, id int64) int {
				return f.do("PUT", "/api/clients/"+itoa(id), map[string]any{"name": "phone", "quotaBytes": 100, "expiresAt": future}, withCookie(c)).Code
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			c := f.setup()
			cl := f.createClient(c, "phone", 100)
			tc.setup(f, cl.ID)
			before := f.eng.syncCount()
			if code := tc.action(f, c, cl.ID); code != http.StatusNoContent && code != http.StatusOK {
				t.Fatalf("action status %d", code)
			}
			got, _ := f.st.GetClient(t.Context(), cl.ID)
			if got.Disabled != model.NotDisabled {
				t.Fatalf("disabled = %q, want lifted", got.Disabled)
			}
			if f.eng.syncCount() != before+1 {
				t.Fatalf("syncs went %d -> %d, want one more", before, f.eng.syncCount())
			}
		})
	}

	t.Run("past expiry on create blocks at once", func(t *testing.T) {
		f := newFixture(t, nil)
		c := f.setup()
		w := f.do("POST", "/api/clients", map[string]any{"name": "old", "expiresAt": past}, withCookie(c))
		expectStatus(t, w, http.StatusCreated)
		if got := decodeBody[clientDTO](t, w); got.Disabled != model.DisabledExpired {
			t.Fatalf("disabled = %q, want expired", got.Disabled)
		}
	})

	t.Run("past expiry on update blocks at once", func(t *testing.T) {
		f := newFixture(t, nil)
		c := f.setup()
		cl := f.createClient(c, "phone", 0)
		w := f.do("PUT", "/api/clients/"+itoa(cl.ID), map[string]any{"name": "phone", "expiresAt": past}, withCookie(c))
		expectStatus(t, w, http.StatusOK)
		if got := decodeBody[clientDTO](t, w); got.Disabled != model.DisabledExpired {
			t.Fatalf("disabled = %q, want expired", got.Disabled)
		}
	})
}

// overQuota pushes the client past its quota and lets one quota tick block it.
func overQuota(f *fixture, id int64) {
	f.t.Helper()
	if err := f.st.AddTraffic(f.t.Context(), map[int64]model.Traffic{id: {Up: 60, Down: 60}}); err != nil {
		f.t.Fatal(err)
	}
	if err := f.srv.NewRunner(noTraffic, time.Minute).Tick(f.t.Context()); err != nil {
		f.t.Fatal(err)
	}
	if got, _ := f.st.GetClient(f.t.Context(), id); got.Disabled != model.DisabledQuota {
		f.t.Fatalf("setup: disabled = %q, want quota", got.Disabled)
	}
}

func TestEnableOnlyLiftsManualBlock(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	cl := f.createClient(c, "phone", 100)
	path := "/api/clients/" + itoa(cl.ID)

	expectStatus(t, f.do("POST", path+"/disable", nil, withCookie(c)), http.StatusNoContent)
	if got, _ := f.st.GetClient(t.Context(), cl.ID); got.Disabled != model.DisabledManual {
		t.Fatalf("after disable = %q", got.Disabled)
	}
	expectStatus(t, f.do("POST", path+"/enable", nil, withCookie(c)), http.StatusNoContent)
	if got, _ := f.st.GetClient(t.Context(), cl.ID); got.Disabled != model.NotDisabled {
		t.Fatalf("after enable = %q", got.Disabled)
	}

	// Manually re-enabling a client that is over quota leaves it quota-blocked.
	expectStatus(t, f.do("POST", path+"/disable", nil, withCookie(c)), http.StatusNoContent)
	if err := f.st.AddTraffic(t.Context(), map[int64]model.Traffic{cl.ID: {Down: 500}}); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, f.do("POST", path+"/enable", nil, withCookie(c)), http.StatusNoContent)
	if got, _ := f.st.GetClient(t.Context(), cl.ID); got.Disabled != model.DisabledQuota {
		t.Fatalf("enable over quota = %q, want quota", got.Disabled)
	}
}

func TestClientActionsOnMissingClient(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	for _, p := range []string{"/disable", "/enable", "/reset-traffic", "/rotate"} {
		expectError(t, f.do("POST", "/api/clients/99"+p, nil, withCookie(c)), http.StatusNotFound, codeNotFound, "")
	}
	if n := f.eng.syncCount(); n != 0 {
		t.Fatalf("syncs = %d after failed actions", n)
	}
}

func TestMonthlyQuotaResetsOnceAndLiftsTheBlock(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	// The fixture clock reads 2026-06-01 12:00 UTC: 21:00 on 1 June in Seoul.
	w := f.do("POST", "/api/clients", map[string]any{"name": "monthly", "quotaBytes": 100, "expiresAt": nil, "quotaResetDay": 15}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	created := decodeBody[clientDTO](t, w)
	wantNext := time.Date(2026, 6, 14, 15, 0, 0, 0, time.UTC) // 15 June 00:00 in Seoul
	if created.QuotaResetDay != 15 || created.NextResetAt == nil || !created.NextResetAt.Equal(wantNext) {
		t.Fatalf("created = %+v, want reset day 15 and next reset %v", created, wantNext)
	}
	overQuota(f, created.ID)

	*f.clock = wantNext.Add(time.Minute)
	runner := f.srv.NewRunner(noTraffic, time.Minute)
	for range 2 {
		if err := runner.Tick(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.st.GetClient(t.Context(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedUp+got.UsedDown != 0 || got.Disabled != model.NotDisabled {
		t.Fatalf("after 15 June = used %d, disabled %q; want zero and active", got.UsedUp+got.UsedDown, got.Disabled)
	}
	entries, _ := f.st.ListAudit(t.Context(), 20, 0)
	resets := 0
	for _, e := range entries {
		if e.Action == "client.cycle-reset" && e.Target == "monthly" && e.RemoteIP == "" {
			resets++
		}
	}
	if resets != 1 {
		t.Fatalf("audit has %d cycle resets, want exactly 1: %+v", resets, entries)
	}
}

func TestQuotaResetDayValidationAndTurningItOff(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	for _, day := range []int{-1, 32} {
		w := f.do("POST", "/api/clients", map[string]any{"name": "x", "quotaBytes": 0, "quotaResetDay": day}, withCookie(c))
		expectError(t, w, http.StatusBadRequest, codeInvalid, "quotaResetDay")
	}
	w := f.do("POST", "/api/clients", map[string]any{"name": "x", "quotaBytes": 0, "quotaResetDay": 31}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	id := decodeBody[clientDTO](t, w).ID
	if err := f.st.AddTraffic(t.Context(), map[int64]model.Traffic{id: {Down: 42}}); err != nil {
		t.Fatal(err)
	}
	w = f.do("PUT", fmt.Sprintf("/api/clients/%d", id), map[string]any{"name": "x", "quotaBytes": 0, "quotaResetDay": 0}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if got := decodeBody[clientDTO](t, w); got.QuotaResetDay != 0 || got.NextResetAt != nil || got.UsedDown != 42 {
		t.Fatalf("after turning it off = %+v, want no cycle and the usage untouched", got)
	}
}

func TestTimeZoneSetting(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	if got := decodeBody[settingsDTO](t, f.do("GET", "/api/settings", nil, withCookie(c))); got.TimeZone != "Asia/Seoul" {
		t.Fatalf("default time zone = %q, want Asia/Seoul", got.TimeZone)
	}
	for _, bad := range []string{"", "Local", "Mars/Olympus"} {
		w := f.do("PUT", "/api/settings", map[string]any{"publicHost": "", "subscriptionBaseUrl": "", "timeZone": bad}, withCookie(c))
		expectError(t, w, http.StatusBadRequest, codeInvalid, "timeZone")
	}

	w := f.do("POST", "/api/clients", map[string]any{"name": "m", "quotaBytes": 0, "quotaResetDay": 1}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	id := decodeBody[clientDTO](t, w).ID
	if err := f.st.AddTraffic(t.Context(), map[int64]model.Traffic{id: {Down: 9}}); err != nil {
		t.Fatal(err)
	}
	w = f.do("PUT", "/api/settings", map[string]any{"publicHost": "", "subscriptionBaseUrl": "", "timeZone": "UTC"}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	// The cycle moves onto UTC midnight instead of looking stale and being reset again.
	if err := f.srv.NewRunner(noTraffic, time.Minute).Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetClient(t.Context(), id)
	if got.UsedDown != 9 || got.CycleStart == nil || !got.CycleStart.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("after switching to UTC = used %d from %v; want usage kept from 1 June UTC", got.UsedDown, got.CycleStart)
	}

	// Callers that do not know the field (the deployer) keep the stored zone.
	w = f.do("PUT", "/api/settings", map[string]any{"publicHost": "vpn.example.com", "subscriptionBaseUrl": ""}, withCookie(c))
	expectStatus(t, w, http.StatusOK)
	if got := decodeBody[settingsDTO](t, w); got.TimeZone != "UTC" {
		t.Fatalf("time zone after a PUT without it = %q, want UTC kept", got.TimeZone)
	}
}

// A tick that cannot read the time zone must not read monthly days in some other zone.
func TestMonthlyResetWaitsForAReadableTimeZone(t *testing.T) {
	f := newFixture(t, nil)
	c := f.setup()
	w := f.do("POST", "/api/clients", map[string]any{"name": "m", "quotaBytes": 0, "quotaResetDay": 2}, withCookie(c))
	expectStatus(t, w, http.StatusCreated)
	id := decodeBody[clientDTO](t, w).ID
	if err := f.st.AddTraffic(t.Context(), map[int64]model.Traffic{id: {Down: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetSetting(t.Context(), settingTimeZone, "Mars/Olympus"); err != nil {
		t.Fatal(err)
	}
	*f.clock = time.Date(2026, 6, 3, 0, 0, 0, 0, time.UTC) // past 2 June in any zone
	if err := f.srv.NewRunner(noTraffic, time.Minute).Tick(t.Context()); err == nil {
		t.Fatal("a tick with an unreadable time zone reported no error")
	}
	if got, _ := f.st.GetClient(t.Context(), id); got.UsedDown != 7 {
		t.Fatalf("usage after a tick without a zone = %d, want 7 kept", got.UsedDown)
	}
	if err := f.st.SetSetting(t.Context(), settingTimeZone, "Asia/Seoul"); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.NewRunner(noTraffic, time.Minute).Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.st.GetClient(t.Context(), id); got.UsedDown != 0 {
		t.Fatalf("usage once the zone is readable = %d, want the reset", got.UsedDown)
	}
}
