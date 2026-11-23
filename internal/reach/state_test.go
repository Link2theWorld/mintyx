package reach

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestAdvance(t *testing.T) {
	type step struct {
		observed Verdict
		verdict  Verdict
		pending  Verdict
		streak   int
	}
	for _, tc := range []struct {
		name    string
		confirm int
		steps   []step
	}{
		{"first good round is confirmed at once", 2, []step{{OK, OK, "", 0}}},
		{"one bad round is only pending", 2, []step{{OK, OK, "", 0}, {PortBlocked, OK, PortBlocked, 1}}},
		{"second bad round in a row confirms", 2, []step{{OK, OK, "", 0}, {PortBlocked, OK, PortBlocked, 1}, {PortBlocked, PortBlocked, "", 0}}},
		{"a good round in between starts the count over", 2, []step{
			{OK, OK, "", 0}, {IPBlocked, OK, IPBlocked, 1}, {OK, OK, "", 0}, {IPBlocked, OK, IPBlocked, 1},
		}},
		{"a round without data neither counts nor resets", 2, []step{
			{OK, OK, "", 0}, {IPBlocked, OK, IPBlocked, 1}, {Unknown, OK, IPBlocked, 1}, {IPBlocked, IPBlocked, "", 0},
		}},
		{"bad rounds of different kinds still count, the latest kind wins", 2, []step{
			{OK, OK, "", 0}, {PortBlocked, OK, PortBlocked, 1}, {IPBlocked, IPBlocked, "", 0},
		}},
		{"recovery needs as many rounds as trouble", 2, []step{
			{Down, "", Down, 1}, {Down, Down, "", 0}, {OK, Down, OK, 1}, {OK, OK, "", 0},
		}},
		{"a bad round in the middle of recovery starts it over", 2, []step{
			{Down, "", Down, 1}, {Down, Down, "", 0}, {OK, Down, OK, 1}, {Down, Down, "", 0}, {OK, Down, OK, 1},
		}},
		{"a different kind of trouble after confirmed trouble also waits", 2, []step{
			{OK, OK, "", 0}, {Down, OK, Down, 1}, {Down, Down, "", 0}, {IPBlocked, Down, IPBlocked, 1}, {IPBlocked, IPBlocked, "", 0},
		}},
		{"confirm 1 trusts a single round either way", 1, []step{{OK, OK, "", 0}, {Down, Down, "", 0}, {OK, OK, "", 0}}},
		{"confirm 3 waits for the third", 3, []step{
			{OK, OK, "", 0}, {Down, OK, Down, 1}, {Down, OK, Down, 2}, {Down, Down, "", 0},
		}},
		{"unknown before anything is known stays unconfirmed", 2, []step{{Unknown, "", "", 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s TargetState
			for i, st := range tc.steps {
				s = s.advance(Observation{Verdict: st.observed}, tc.confirm, t0)
				if s.Verdict != st.verdict || s.Pending != st.pending || s.Streak != st.streak || s.Last != st.observed {
					t.Fatalf("after step %d (%s): verdict %q pending %q streak %d last %q, want %q %q %d %q",
						i, st.observed, s.Verdict, s.Pending, s.Streak, s.Last, st.verdict, st.pending, st.streak, st.observed)
				}
			}
		})
	}
}

func round(v map[int64]Verdict) Round {
	r := Round{Results: map[int64]Observation{}}
	for id, verdict := range v {
		r.Results[id] = Observation{Verdict: verdict}
	}
	return r
}

func TestApplyAlertsOncePerTransition(t *testing.T) {
	targets := []Target{{ID: 1, Name: "tokyo", Host: "a.example", Port: 443}, {ID: 2, Name: "osaka", Host: "a.example", Port: 8443}}
	var st State
	var sent [][]Change
	// flush stands in for the mail going out after every round.
	flush := func() {
		if len(st.Unsent) > 0 {
			sent = append(sent, st.Unsent)
		}
		st.Unsent = nil
	}
	for i, v := range []map[int64]Verdict{
		{1: OK, 2: OK},
		{1: IPBlocked, 2: OK},
		{1: IPBlocked, 2: OK},
		{1: IPBlocked, 2: OK},
		{1: IPBlocked, 2: OK},
		{1: OK, 2: OK},
		{1: OK, 2: OK},
		{1: OK, 2: OK},
	} {
		st = st.Apply(targets, round(v), 2, t0.Add(time.Duration(i)*time.Hour))
		flush()
	}
	want := [][]Change{
		{{Name: "tokyo", Host: "a.example", Port: 443, From: OK, To: IPBlocked}},
		{{Name: "tokyo", Host: "a.example", Port: 443, From: IPBlocked, To: OK}},
	}
	if !reflect.DeepEqual(sent, want) {
		t.Errorf("alerts = %+v\nwant     %+v", sent, want)
	}
	if got := st.Targets[1].Since; !got.Equal(t0.Add(6 * time.Hour)) {
		t.Errorf("Since = %s, want the round that confirmed recovery", got)
	}
}

func TestApplyKeepsUnsentAlertsUntilCleared(t *testing.T) {
	targets := []Target{{ID: 1, Name: "tokyo", Host: "a.example", Port: 443}}
	var st State
	for _, v := range []Verdict{OK, Down, Down, OK, OK} {
		st = st.Apply(targets, round(map[int64]Verdict{1: v}), 2, t0)
	}
	want := []Change{
		{Name: "tokyo", Host: "a.example", Port: 443, From: OK, To: Down},
		{Name: "tokyo", Host: "a.example", Port: 443, From: Down, To: OK},
	}
	if !reflect.DeepEqual(st.Unsent, want) {
		t.Errorf("Unsent = %+v, want both transitions kept for the next mail attempt: %+v", st.Unsent, want)
	}
}

func TestApplyFlappingLineDoesNotMailEveryRound(t *testing.T) {
	targets := []Target{{ID: 1, Name: "tokyo", Host: "a.example", Port: 443}}
	var st State
	sent := 0
	for i, v := range []Verdict{OK, Down, Down, OK, Down, OK, Down, OK, Down, OK} {
		st = st.Apply(targets, round(map[int64]Verdict{1: v}), 2, t0.Add(time.Duration(i)*time.Hour))
		sent += len(st.Unsent)
		st.Unsent = nil
	}
	if sent != 1 {
		t.Errorf("a line flapping every round after going down sent %d alerts, want only the first", sent)
	}
	if st.Targets[1].Verdict != Down {
		t.Errorf("verdict = %q, want down: recovery never held for two rounds", st.Targets[1].Verdict)
	}
}

func TestApplyForgetsHistoryWhenAddressChanges(t *testing.T) {
	st := State{}.Apply([]Target{{ID: 1, Host: "a.example", Port: 443}}, round(map[int64]Verdict{1: Down}), 1, t0)
	if st.Targets[1].Verdict != Down {
		t.Fatalf("setup: verdict %q", st.Targets[1].Verdict)
	}
	moved := []Target{{ID: 1, Host: "a.example", Port: 8443}, {ID: 2, Host: "b.example", Port: 443}}
	st = st.Apply(moved, Round{Results: map[int64]Observation{2: {Verdict: OK}}}, 1, t0)
	if got := st.Targets[1]; got != (TargetState{Host: "a.example", Port: 8443}) {
		t.Errorf("moved line kept old state: %+v", got)
	}
	st = st.Apply(moved[1:], round(map[int64]Verdict{2: OK}), 1, t0)
	if _, kept := st.Targets[1]; kept {
		t.Error("state of a deleted line was kept")
	}
}

func TestApplyRecordsRateLimitRetryTime(t *testing.T) {
	r := Round{Results: map[int64]Observation{}, Err: &RateLimitError{Reset: 20 * time.Minute}}
	st := State{}.Apply(nil, r, 2, t0)
	if want := t0.Add(20 * time.Minute); !st.RetryAt.Equal(want) {
		t.Errorf("RetryAt = %s, want %s", st.RetryAt, want)
	}
	st = st.Apply(nil, Round{}, 2, t0.Add(time.Hour))
	if !st.RetryAt.IsZero() {
		t.Errorf("RetryAt = %s after a clean round, want zero", st.RetryAt)
	}
}

func TestAlertMail(t *testing.T) {
	subject, body := AlertMail([]Change{
		{Name: "东京直连", Host: "203.0.113.9", Port: 443, From: OK, To: PortBlocked},
		{Name: "hy2", Host: "2001:db8::1", From: Down, To: OK},
	})
	if want := "Mintyx：有线路从中国大陆连不上了 / lines unreachable from mainland China"; subject != want {
		t.Errorf("subject = %q, want %q", subject, want)
	}
	for _, want := range []string{
		"- 东京直连（203.0.113.9:443）端口可能被墙",
		"- 东京直连 (203.0.113.9:443) port looks blocked",
		"- hy2（2001:db8::1）已恢复",
		"- hy2 (2001:db8::1) is reachable from mainland China again.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	subject, _ = AlertMail([]Change{{Name: "a", Host: "h", Port: 1, From: IPBlocked, To: OK}})
	if want := "Mintyx：线路已恢复 / lines reachable again"; subject != want {
		t.Errorf("recovery subject = %q, want %q", subject, want)
	}
}

func TestApplyKeepsRotationCursorAndSkippedLines(t *testing.T) {
	targets := []Target{{ID: 1, Host: "a.example", Port: 443}, {ID: 2, Host: "a.example", Port: 8443}}
	st := State{}.Apply(targets, round(map[int64]Verdict{1: OK, 2: Down}), 1, t0)
	// A capped round left line 2 out: it keeps its verdict and last result.
	st = st.Apply(targets, Round{Results: map[int64]Observation{1: {Verdict: OK}}, Err: ErrTooManyTargets, Next: 7}, 1, t0)
	if st.Cursor != 7 {
		t.Errorf("Cursor = %d, want the round's Next 7", st.Cursor)
	}
	if got := st.Targets[2]; got.Verdict != Down || got.Last != Down {
		t.Errorf("skipped line = %+v, want its earlier down kept", got)
	}
	// A rate-limited round measured little or nothing, so it must not move the rotation on.
	st = st.Apply(targets, Round{Results: map[int64]Observation{}, Err: &RateLimitError{Reset: time.Minute}, Next: 9}, 1, t0)
	if st.Cursor != 7 {
		t.Errorf("Cursor = %d after a rate-limited round, want 7 kept", st.Cursor)
	}
}
