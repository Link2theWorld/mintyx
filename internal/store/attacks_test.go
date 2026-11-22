package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ysuhao/mintyx-next/internal/model"
)

var attackT0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func hit(ip, kind string, at time.Time, count int64, lines ...string) model.AttackHit {
	h := model.AttackHit{IP: ip, Kind: kind, Day: at.Format("2006-01-02"), Count: count, First: at, Last: at}
	for _, l := range lines {
		h.Samples = append(h.Samples, model.AttackSample{At: at, Line: l})
	}
	return h
}

func TestRecordAttacksAccumulates(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	day2 := attackT0.Add(24 * time.Hour)
	if err := s.RecordAttacks(ctx, []model.AttackHit{
		hit("203.0.113.5", "ssh_login", attackT0, 3, "a", "b"),
		hit("203.0.113.5", "ssh_scan", attackT0, 1, "s"),
		hit("198.51.100.9", "line_probe", attackT0, 2, "p"),
	}, nil, attackT0); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAttacks(ctx, []model.AttackHit{hit("203.0.113.5", "ssh_login", day2, 4, "c", "d")}, nil, day2); err != nil {
		t.Fatal(err)
	}

	a, err := s.GetAttacker(ctx, "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	if a.Hits != 8 || !a.FirstAt.Equal(attackT0) || !a.LastAt.Equal(day2) || a.LookedUpAt != nil {
		t.Errorf("attacker = %+v", a)
	}
	if len(a.Kinds) != 2 || a.Kinds[0].Kind != "ssh_login" || a.Kinds[0].Hits != 7 || !a.Kinds[0].FirstAt.Equal(attackT0) || !a.Kinds[0].LastAt.Equal(day2) {
		t.Fatalf("kinds = %+v", a.Kinds)
	}
	var lines []string
	for _, sm := range a.Kinds[0].Samples {
		lines = append(lines, sm.Line)
	}
	if !reflect.DeepEqual(lines, []string{"b", "c", "d"}) {
		t.Errorf("samples = %v, want the newest three", lines)
	}

	sum, err := s.AttackSummary(ctx, "2026-11-01")
	if err != nil {
		t.Fatal(err)
	}
	if sum.Sources != 2 || sum.Hits != 10 || sum.Pending != 2 || sum.LookedUp != 0 {
		t.Errorf("summary totals = %+v", sum)
	}
	wantKinds := []model.AttackKindTotal{{Kind: "ssh_login", Hits: 7, Sources: 1}, {Kind: "line_probe", Hits: 2, Sources: 1}, {Kind: "ssh_scan", Hits: 1, Sources: 1}}
	if !reflect.DeepEqual(sum.Kinds, wantKinds) {
		t.Errorf("kinds = %+v", sum.Kinds)
	}
	wantDaily := []model.AttackDay{
		{Day: "2026-11-20", Kind: "line_probe", Hits: 2}, {Day: "2026-11-20", Kind: "ssh_login", Hits: 3},
		{Day: "2026-11-20", Kind: "ssh_scan", Hits: 1}, {Day: "2026-11-21", Kind: "ssh_login", Hits: 4},
	}
	if !reflect.DeepEqual(sum.Daily, wantDaily) {
		t.Errorf("daily = %+v", sum.Daily)
	}
	if later, _ := s.AttackSummary(ctx, "2026-11-21"); len(later.Daily) != 1 {
		t.Errorf("daily since the 21st = %+v", later.Daily)
	}
}

func TestTrustedAddressIsForgottenAndStaysOut(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	if err := s.RecordAttacks(ctx, []model.AttackHit{hit("198.51.100.7", "ssh_login", attackT0, 5, "x")}, nil, attackT0); err != nil {
		t.Fatal(err)
	}
	// The same batch that trusts an address may still carry its earlier failed attempts.
	if err := s.RecordAttacks(ctx, []model.AttackHit{
		hit("198.51.100.7", "ssh_login", attackT0, 1, "y"), hit("203.0.113.5", "ssh_scan", attackT0, 1, "z"),
	}, []string{"198.51.100.7"}, attackT0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAttacker(ctx, "198.51.100.7"); !errors.Is(err, ErrNotFound) {
		t.Errorf("trusted address: %v, want ErrNotFound", err)
	}
	list, total, err := s.ListAttackers(ctx, AttackFilter{Limit: 10})
	if err != nil || total != 1 || len(list) != 1 || list[0].IP != "203.0.113.5" {
		t.Errorf("list = %+v, total %d, err %v", list, total, err)
	}
	sum, _ := s.AttackSummary(ctx, "2026-11-01")
	if sum.Sources != 1 || sum.Hits != 1 || len(sum.Kinds) != 1 || sum.Kinds[0].Kind != "ssh_scan" {
		t.Errorf("summary still counts the trusted address: %+v", sum)
	}
	if ips, _ := s.AttackersToLookUp(ctx, 10, attackT0); len(ips) != 1 || ips[0] != "203.0.113.5" {
		t.Errorf("to look up = %v", ips)
	}
}

func TestWhoisLookupQueueAndOrigins(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	if err := s.RecordAttacks(ctx, []model.AttackHit{
		hit("203.0.113.1", "ssh_login", attackT0, 9, "a"),
		hit("203.0.113.2", "ssh_login", attackT0.Add(time.Minute), 5, "b"),
		hit("203.0.113.3", "line_probe", attackT0.Add(2*time.Minute), 1, "c"),
		hit("2001:db8::4", "ssh_scan", attackT0.Add(3*time.Minute), 7, "d"),
	}, nil, attackT0); err != nil {
		t.Fatal(err)
	}
	if ips, _ := s.AttackersToLookUp(ctx, 2, attackT0); !reflect.DeepEqual(ips, []string{"203.0.113.1", "2001:db8::4"}) {
		t.Fatalf("busiest two = %v", ips)
	}

	nl := model.Whois{Country: "NL", Network: "Example B.V.", NetRange: "203.0.113.0/24", AbuseEmail: "abuse@example.nl", Registry: "RIPE NCC"}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if err := s.SetAttackerWhois(ctx, ip, nl, "", attackT0); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetAttackerWhois(ctx, "203.0.113.3", model.Whois{}, "error", attackT0); err != nil {
		t.Fatal(err)
	}

	// A failed lookup waits for the retry time; a successful one is never repeated.
	if ips, _ := s.AttackersToLookUp(ctx, 10, attackT0.Add(-time.Hour)); !reflect.DeepEqual(ips, []string{"2001:db8::4"}) {
		t.Errorf("before the retry time: %v", ips)
	}
	if ips, _ := s.AttackersToLookUp(ctx, 10, attackT0.Add(time.Hour)); !reflect.DeepEqual(ips, []string{"2001:db8::4", "203.0.113.3"}) {
		t.Errorf("after the retry time: %v", ips)
	}

	a, _ := s.GetAttacker(ctx, "203.0.113.1")
	if a.Whois != nl || a.LookedUpAt == nil || !a.LookedUpAt.Equal(attackT0) || a.LookupError != "" {
		t.Errorf("attacker after lookup = %+v", a)
	}
	if a, _ := s.GetAttacker(ctx, "203.0.113.3"); a.LookupError != "error" || a.LookedUpAt == nil {
		t.Errorf("attacker after a failed lookup = %+v", a)
	}

	sum, err := s.AttackSummary(ctx, "2026-11-01")
	if err != nil {
		t.Fatal(err)
	}
	if sum.LookedUp != 2 || sum.Pending != 1 {
		t.Errorf("looked up %d pending %d", sum.LookedUp, sum.Pending)
	}
	if !reflect.DeepEqual(sum.Countries, []model.AttackOrigin{{Country: "NL", Sources: 2, Hits: 14}}) {
		t.Errorf("countries = %+v", sum.Countries)
	}
	if !reflect.DeepEqual(sum.Networks, []model.AttackNetwork{{Network: "Example B.V.", Country: "NL", AbuseEmail: "abuse@example.nl", Sources: 2, Hits: 14}}) {
		t.Errorf("networks = %+v", sum.Networks)
	}

	ips := func(f AttackFilter) (out []string) {
		t.Helper()
		list, total, err := s.ListAttackers(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range list {
			out = append(out, a.IP)
		}
		if f.Offset == 0 && int(total) < len(out) {
			t.Fatalf("total %d < page %d", total, len(out))
		}
		return out
	}
	if got := ips(AttackFilter{Limit: 10}); !reflect.DeepEqual(got, []string{"2001:db8::4", "203.0.113.3", "203.0.113.2", "203.0.113.1"}) {
		t.Errorf("newest first = %v", got)
	}
	if got := ips(AttackFilter{Limit: 2, Offset: 1}); !reflect.DeepEqual(got, []string{"203.0.113.3", "203.0.113.2"}) {
		t.Errorf("second page = %v", got)
	}
	if got := ips(AttackFilter{Limit: 10, Kind: "ssh_login"}); !reflect.DeepEqual(got, []string{"203.0.113.2", "203.0.113.1"}) {
		t.Errorf("by kind = %v", got)
	}
	if got := ips(AttackFilter{Limit: 10, Country: "NL", Kind: "ssh_login"}); len(got) != 2 {
		t.Errorf("by country and kind = %v", got)
	}
	if got := ips(AttackFilter{Limit: 10, Country: "JP"}); len(got) != 0 {
		t.Errorf("by another country = %v", got)
	}
	if _, _, err := s.ListAttackers(ctx, AttackFilter{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("zero limit: %v, want ErrInvalid", err)
	}
}

func TestPruneAndClearAttacks(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	old, recent := attackT0.Add(-40*24*time.Hour), attackT0
	if err := s.RecordAttacks(ctx, []model.AttackHit{
		hit("203.0.113.1", "ssh_login", old, 2, "a"), hit("203.0.113.2", "ssh_login", recent, 3, "b"),
	}, nil, recent); err != nil {
		t.Fatal(err)
	}
	cutoff := attackT0.Add(-30 * 24 * time.Hour)
	if err := s.PruneAttacks(ctx, cutoff, cutoff.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
	sum, _ := s.AttackSummary(ctx, "2026-01-01")
	if sum.Sources != 1 || sum.Hits != 3 || len(sum.Daily) != 1 || len(sum.Kinds) != 1 || sum.Kinds[0].Hits != 3 {
		t.Errorf("after pruning: %+v", sum)
	}
	if err := s.ClearAttacks(ctx); err != nil {
		t.Fatal(err)
	}
	if sum, _ := s.AttackSummary(ctx, "2026-01-01"); sum.Sources != 0 || len(sum.Daily) != 0 || len(sum.Kinds) != 0 {
		t.Errorf("after clearing: %+v", sum)
	}
}
