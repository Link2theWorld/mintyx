package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Link2theWorld/mintyx/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "mintyx.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func realityLine(port int) *model.Line {
	return &model.Line{
		Name: fmt.Sprintf("r%d", port), Protocol: model.VLESSReality, Port: port, Enabled: true,
		Reality: &model.RealityParams{
			PrivateKey: "priv", PublicKey: "pub", ShortID: "0a1b", ServerName: "www.example.com", Target: "www.example.com:443",
		},
	}
}

func newClient(name string) *model.Client {
	return &model.Client{Name: name, Secret: "secret-" + name, SubToken: "tok-" + name}
}

func TestLineParamsRoundTrip(t *testing.T) {
	cases := []model.Line{
		*realityLine(443),
		{
			Name: "x", Protocol: model.VLESSXHTTP, Port: 8443, Enabled: false, Host: "cdn.example.org",
			XHTTP: &model.XHTTPParams{Path: "/p", Domain: "x.example.org", Security: model.XHTTPTLS, CertFile: "/c.pem", KeyFile: "/k.pem"},
		},
		{
			Name: "xp", Protocol: model.VLESSXHTTP, Port: 8080, Enabled: true,
			XHTTP: &model.XHTTPParams{Path: "/q", Domain: "y.example.org", Security: model.XHTTPPlain},
		},
		{
			Name: "h", Protocol: model.Hysteria2, Port: 4443, Enabled: true,
			Hysteria2: &model.Hysteria2Params{Domain: "h.example.org", CertFile: "/c", KeyFile: "/k", ObfsPassword: "salamander"},
		},
	}
	ctx := context.Background()
	s := openTest(t)
	for _, tc := range cases {
		t.Run(string(tc.Protocol)+"/"+tc.Name, func(t *testing.T) {
			in := tc
			if err := s.CreateLine(ctx, &in); err != nil {
				t.Fatalf("CreateLine: %v", err)
			}
			if in.ID == 0 || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC {
				t.Fatalf("CreateLine did not fill ID/CreatedAt in UTC: %+v", in)
			}
			got, err := s.GetLine(ctx, in.ID)
			if err != nil {
				t.Fatalf("GetLine: %v", err)
			}
			if !reflect.DeepEqual(got, in) {
				t.Fatalf("round trip mismatch\n got %+v\nwant %+v", got, in)
			}
		})
	}
}

func TestLineValidation(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	cases := []struct {
		name string
		line model.Line
	}{
		{"unknown protocol", model.Line{Name: "a", Protocol: "vmess", Port: 1, Reality: &model.RealityParams{}}},
		{"missing params", model.Line{Name: "b", Protocol: model.Hysteria2, Port: 2}},
		{"wrong params", model.Line{Name: "c", Protocol: model.VLESSReality, Port: 3, Hysteria2: &model.Hysteria2Params{}}},
		{"extra params", model.Line{Name: "d", Protocol: model.VLESSReality, Port: 4, Reality: &model.RealityParams{}, XHTTP: &model.XHTTPParams{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.CreateLine(ctx, &tc.line); !errors.Is(err, ErrInvalid) {
				t.Fatalf("CreateLine err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLineUpdateAndDelete(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	l := realityLine(443)
	if err := s.CreateLine(ctx, l); err != nil {
		t.Fatal(err)
	}
	l.Protocol = model.Hysteria2
	l.Reality = nil
	l.Hysteria2 = &model.Hysteria2Params{Domain: "h"}
	l.Port = 444
	l.Enabled = false
	if err := s.UpdateLine(ctx, l); err != nil {
		t.Fatalf("UpdateLine: %v", err)
	}
	got, err := s.GetLine(ctx, l.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, *l) {
		t.Fatalf("after update\n got %+v\nwant %+v", got, *l)
	}

	if err := s.DeleteLine(ctx, l.ID); err != nil {
		t.Fatalf("DeleteLine: %v", err)
	}
	if _, err := s.GetLine(ctx, l.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetLine after delete err = %v, want ErrNotFound", err)
	}
	if err := s.DeleteLine(ctx, l.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second DeleteLine err = %v, want ErrNotFound", err)
	}
	missing := realityLine(445)
	missing.ID = 999
	if err := s.UpdateLine(ctx, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateLine missing err = %v, want ErrNotFound", err)
	}
}

func TestDuplicatePortConflict(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	a, b := realityLine(443), realityLine(8443)
	for _, l := range []*model.Line{a, b} {
		if err := s.CreateLine(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	assertConflict := func(t *testing.T, err error, field string) {
		t.Helper()
		var ce *ConflictError
		if !errors.Is(err, ErrConflict) || !errors.As(err, &ce) || ce.Field != field {
			t.Fatalf("err = %v, want ErrConflict on %q", err, field)
		}
	}
	assertConflict(t, s.CreateLine(ctx, realityLine(443)), "port")
	b.Port = 443
	assertConflict(t, s.UpdateLine(ctx, b), "port")

	lines, err := s.ListLines(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0].Port != 443 || lines[1].Port != 8443 {
		t.Fatalf("ListLines = %+v, want ports [443 8443]", lines)
	}
}

func TestClientRoundTripAndUniqueness(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	exp := time.Date(2027, 3, 4, 5, 6, 7, 123456789, time.FixedZone("CST", 8*3600))
	a := &model.Client{Name: "alice", Secret: "s-a", SubToken: "t-a", QuotaBytes: 10 << 30, ExpiresAt: &exp}
	if err := s.CreateClient(ctx, a); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := s.GetClient(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt = %v, want %v in UTC", got.ExpiresAt, exp.UTC())
	}
	want := *a
	utc := exp.UTC()
	want.ExpiresAt = &utc
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip\n got %+v\nwant %+v", got, want)
	}

	b := newClient("bob")
	if err := s.CreateClient(ctx, b); err != nil {
		t.Fatal(err)
	}
	gotB, err := s.GetClientBySubToken(ctx, "tok-bob")
	if err != nil {
		t.Fatal(err)
	}
	if gotB.ID != b.ID || gotB.ExpiresAt != nil {
		t.Fatalf("GetClientBySubToken = %+v, want id %d with nil ExpiresAt", gotB, b.ID)
	}
	if _, err := s.GetClientBySubToken(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown token err = %v, want ErrNotFound", err)
	}

	cases := []struct {
		field string
		c     model.Client
	}{
		{"name", model.Client{Name: "alice", Secret: "x1", SubToken: "y1"}},
		{"secret", model.Client{Name: "n2", Secret: "s-a", SubToken: "y2"}},
		{"sub_token", model.Client{Name: "n3", Secret: "x3", SubToken: "t-a"}},
	}
	for _, tc := range cases {
		t.Run("create dup "+tc.field, func(t *testing.T) {
			var ce *ConflictError
			err := s.CreateClient(ctx, &tc.c)
			if !errors.Is(err, ErrConflict) || !errors.As(err, &ce) || ce.Field != tc.field {
				t.Fatalf("err = %v, want ErrConflict on %q", err, tc.field)
			}
		})
	}
	b.Secret = "s-a"
	var ce *ConflictError
	if err := s.UpdateClient(ctx, b); !errors.As(err, &ce) || ce.Field != "secret" {
		t.Fatalf("UpdateClient dup secret err = %v, want ConflictError on secret", err)
	}
}

func TestUpdateClientLeavesUsageAndDisabled(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	c := newClient("c")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(ctx, map[int64]model.Traffic{c.ID: {Up: 5, Down: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetClientDisabled(ctx, c.ID, model.DisabledQuota); err != nil {
		t.Fatal(err)
	}
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	upd := model.Client{ID: c.ID, Name: "renamed", Secret: "s2", SubToken: "t2", QuotaBytes: 99, ExpiresAt: &exp}
	if err := s.UpdateClient(ctx, &upd); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got, err := s.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := model.Client{
		ID: c.ID, Name: "renamed", Secret: "s2", SubToken: "t2", Disabled: model.DisabledQuota,
		QuotaBytes: 99, ExpiresAt: &exp, UsedUp: 5, UsedDown: 7, CreatedAt: c.CreatedAt,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after update\n got %+v\nwant %+v", got, want)
	}

	upd.ExpiresAt = nil
	if err := s.UpdateClient(ctx, &upd); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetClient(ctx, c.ID); got.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v after clearing, want nil", got.ExpiresAt)
	}
}

func TestClientNotFound(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	ops := map[string]func() error{
		"Get":         func() error { _, err := s.GetClient(ctx, 42); return err },
		"Update":      func() error { return s.UpdateClient(ctx, &model.Client{ID: 42, Name: "a", Secret: "b", SubToken: "c"}) },
		"Delete":      func() error { return s.DeleteClient(ctx, 42) },
		"SetDisabled": func() error { return s.SetClientDisabled(ctx, 42, model.DisabledManual) },
		"Reset":       func() error { return s.ResetTraffic(ctx, 42) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestSetClientDisabled(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	c := newClient("c")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	for _, r := range []model.DisabledReason{model.DisabledExpired, model.NotDisabled, model.DisabledManual} {
		if err := s.SetClientDisabled(ctx, c.ID, r); err != nil {
			t.Fatalf("SetClientDisabled(%q): %v", r, err)
		}
		got, err := s.GetClient(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Disabled != r {
			t.Fatalf("Disabled = %q, want %q", got.Disabled, r)
		}
	}
	if err := s.SetClientDisabled(ctx, c.ID, "banned"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown reason err = %v, want ErrInvalid", err)
	}
}

func TestAddTrafficAccumulatesAndReset(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	a, b := newClient("a"), newClient("b")
	for _, c := range []*model.Client{a, b} {
		if err := s.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	batches := []map[int64]model.Traffic{
		{a.ID: {Up: 10, Down: 20}, 9999: {Up: 1, Down: 1}},
		{a.ID: {Up: 1, Down: 2}, b.ID: {Up: 3, Down: 4}},
	}
	for _, m := range batches {
		if err := s.AddTraffic(ctx, m); err != nil {
			t.Fatalf("AddTraffic: %v", err)
		}
	}
	check := func(id int64, up, down int64) {
		t.Helper()
		got, err := s.GetClient(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.UsedUp != up || got.UsedDown != down {
			t.Fatalf("client %d usage = %d/%d, want %d/%d", id, got.UsedUp, got.UsedDown, up, down)
		}
	}
	check(a.ID, 11, 22)
	check(b.ID, 3, 4)

	if err := s.ResetTraffic(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	check(a.ID, 0, 0)
	check(b.ID, 3, 4)
}

func TestAddTrafficNotClobberedByConcurrentUpdate(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	c := newClient("c")
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- s.AddTraffic(ctx, map[int64]model.Traffic{c.ID: {Up: 1, Down: 2}})
		}()
		go func() {
			defer wg.Done()
			errs <- s.UpdateClient(ctx, &model.Client{ID: c.ID, Name: "c", Secret: "s", SubToken: "t", QuotaBytes: int64(i)})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent op: %v", err)
		}
	}
	got, err := s.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedUp != n || got.UsedDown != 2*n {
		t.Fatalf("usage = %d/%d, want %d/%d", got.UsedUp, got.UsedDown, n, 2*n)
	}
}

func TestDeleteClient(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	a, b := newClient("a"), newClient("b")
	for _, c := range []*model.Client{a, b} {
		if err := s.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteClient(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != b.ID {
		t.Fatalf("ListClients = %+v, want only %d", list, b.ID)
	}
	if err := s.CreateClient(ctx, newClient("a")); err != nil {
		t.Fatalf("recreate deleted name: %v", err)
	}
}

func TestAuditPaging(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	at := time.Date(2026, 11, 21, 10, 0, 0, 0, time.FixedZone("X", -5*3600))
	var ids []int64
	for i := range 5 {
		e := &model.AuditEntry{At: at.Add(time.Duration(i) * time.Second), Action: fmt.Sprintf("act%d", i), Target: "t", Detail: "d", RemoteIP: "203.0.113.7"}
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.ID)
	}
	page := func(limit int, before int64) []string {
		t.Helper()
		es, err := s.ListAudit(ctx, limit, before)
		if err != nil {
			t.Fatal(err)
		}
		var acts []string
		for _, e := range es {
			acts = append(acts, e.Action)
		}
		return acts
	}
	cases := []struct {
		limit  int
		before int64
		want   []string
	}{
		{2, 0, []string{"act4", "act3"}},
		{2, ids[3], []string{"act2", "act1"}},
		{10, ids[1], []string{"act0"}},
		{10, ids[0], nil},
	}
	for _, tc := range cases {
		if got := page(tc.limit, tc.before); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("ListAudit(%d, %d) = %v, want %v", tc.limit, tc.before, got, tc.want)
		}
	}
	es, err := s.ListAudit(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := model.AuditEntry{ID: ids[4], At: at.Add(4 * time.Second).UTC(), Action: "act4", Target: "t", Detail: "d", RemoteIP: "203.0.113.7"}
	if !reflect.DeepEqual(es[0], want) {
		t.Fatalf("entry\n got %+v\nwant %+v", es[0], want)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, ok, err := s.GetSetting(ctx, "theme"); err != nil || ok {
		t.Fatalf("unset GetSetting ok=%v err=%v, want false nil", ok, err)
	}
	for _, v := range []string{"dark", ""} {
		if err := s.SetSetting(ctx, "theme", v); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.GetSetting(ctx, "theme")
		if err != nil || !ok || got != v {
			t.Fatalf("GetSetting = %q %v %v, want %q true nil", got, ok, err, v)
		}
	}
}

func TestSetSettingsWritesAllKeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if err := s.SetSetting(ctx, "a", "old"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSettings(ctx, map[string]string{"a": "new", "b": "x"}); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"a": "new", "b": "x"} {
		if got, ok, err := s.GetSetting(ctx, k); err != nil || !ok || got != want {
			t.Errorf("GetSetting(%q) = %q %v %v, want %q true nil", k, got, ok, err, want)
		}
	}
}

func TestReopenKeepsDataAndSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "mintyx.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l := realityLine(443)
	if err := s.CreateLine(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		s, err = Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		got, err := s.GetLine(ctx, l.ID)
		if err != nil || !reflect.DeepEqual(got, *l) {
			t.Fatalf("after reopen GetLine = %+v, %v", got, err)
		}
		var v, rows int
		if err := s.db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_version`).Scan(&v, &rows); err != nil {
			t.Fatal(err)
		}
		if v != len(migrations) || rows != 1 {
			t.Fatalf("schema_version = %d (%d rows), want %d (1 row)", v, rows, len(migrations))
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mintyx.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE schema_version SET version = ?`, len(migrations)+1); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Open err = %v, want ErrSchemaTooNew", err)
	}
}

func TestOpenSetsPragmas(t *testing.T) {
	s := openTest(t)
	var mode string
	var fk, busy int
	db := s.db
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	q := func(sqlText string, dst any) {
		t.Helper()
		if err := conn.QueryRowContext(context.Background(), sqlText).Scan(dst); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
	}
	q(`PRAGMA journal_mode`, &mode)
	q(`PRAGMA foreign_keys`, &fk)
	q(`PRAGMA busy_timeout`, &busy)
	if mode != "wal" || fk != 1 || busy != busyTimeoutMillis {
		t.Fatalf("pragmas journal_mode=%q foreign_keys=%d busy_timeout=%d", mode, fk, busy)
	}
}

func TestMonthlyCycleFieldsAndStartCycle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	oct := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	c := newClient("monthly")
	c.QuotaResetDay, c.CycleStart = 1, &oct
	if err := s.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := s.AddTraffic(ctx, map[int64]model.Traffic{c.ID: {Up: 5, Down: 7}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.QuotaResetDay != 1 || got.CycleStart == nil || !got.CycleStart.Equal(oct) {
		t.Fatalf("stored cycle = day %d from %v, want day 1 from %v", got.QuotaResetDay, got.CycleStart, oct)
	}

	nov := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i, want := range []bool{true, false} {
		started, err := s.StartCycle(ctx, c.ID, nov, true)
		if err != nil || started != want {
			t.Fatalf("StartCycle #%d = %v, %v; want %v", i+1, started, err, want)
		}
		if i == 0 {
			// Usage after the reset must survive the repeated call.
			if err := s.AddTraffic(ctx, map[int64]model.Traffic{c.ID: {Down: 3}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, _ = s.GetClient(ctx, c.ID)
	if got.UsedUp != 0 || got.UsedDown != 3 || !got.CycleStart.Equal(nov) {
		t.Fatalf("after the reset = %d/%d from %v, want 0/3 from %v", got.UsedUp, got.UsedDown, got.CycleStart, nov)
	}
	if started, err := s.StartCycle(ctx, c.ID, oct, true); started || err != nil {
		t.Fatalf("StartCycle with an older start = %v, %v; want ignored", started, err)
	}

	got.QuotaResetDay, got.CycleStart = 0, nil
	if err := s.UpdateClient(ctx, &got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.GetClient(ctx, c.ID); again.QuotaResetDay != 0 || again.CycleStart != nil || again.UsedDown != 3 {
		t.Fatalf("after turning the cycle off = %+v, want no cycle and usage kept", again)
	}
}
