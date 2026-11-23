package reach

import (
	"errors"
	"time"
)

// TargetState is what the checker remembers about one line between rounds and restarts.
type TargetState struct {
	// Host and Port are what was measured; when the line's address changes the history is void.
	Host string `json:"host"`
	Port int    `json:"port"`
	// Verdict is the confirmed state, "" until the first conclusive round.
	Verdict Verdict   `json:"verdict"`
	Since   time.Time `json:"since"`
	// Pending is a new verdict still waiting for Streak to reach the confirmation count.
	Pending Verdict `json:"pending,omitempty"`
	Streak  int     `json:"streak,omitempty"`
	// Last is the latest round's own verdict, confirmed or not.
	Last    Verdict `json:"last"`
	China   Tally   `json:"china"`
	Control Tally   `json:"control"`
}

// Change is a confirmed transition worth telling the owner about.
type Change struct {
	Name string  `json:"name"`
	Host string  `json:"host"`
	Port int     `json:"port"`
	From Verdict `json:"from"`
	To   Verdict `json:"to"`
}

// State is persisted as one JSON value.
type State struct {
	LastCheckAt time.Time `json:"lastCheckAt"`
	// RetryAt is set after a rate-limit refusal: no round before it.
	RetryAt time.Time `json:"retryAt"`
	// Cursor is where the next round's rotation starts when not every line fits in one round.
	Cursor  int                   `json:"cursor,omitempty"`
	Targets map[int64]TargetState `json:"targets"`
	// Unsent holds alerts whose email has not gone out yet, so a mail failure does not lose them.
	Unsent []Change `json:"unsent,omitempty"`
}

const maxUnsent = 50

// advance folds one observation in. Any change of verdict, trouble and recovery alike, must
// repeat confirm rounds in a row, so a line flapping between bad and ok does not mail on every
// round; bad rounds of different kinds count together and the latest kind wins. The only change
// taken at once is a first-ever ok, which is not news. A round without data neither counts
// toward a change nor interrupts it.
func (s TargetState) advance(o Observation, confirm int, now time.Time) TargetState {
	s.Last, s.China, s.Control = o.Verdict, o.China, o.Control
	switch {
	case o.Verdict == Unknown:
		return s
	case o.Verdict == s.Verdict:
		s.Pending, s.Streak = "", 0
		return s
	case s.Verdict == "" && o.Verdict == OK:
	default:
		if s.Pending == "" || s.Pending.Bad() != o.Verdict.Bad() {
			s.Streak = 0
		}
		s.Pending = o.Verdict
		s.Streak++
		if s.Streak < confirm {
			return s
		}
	}
	s.Verdict, s.Since, s.Pending, s.Streak = o.Verdict, now, "", 0
	return s
}

// alertWorthy: going bad, changing kind of bad, or recovering. A first-ever "ok" is not news.
func alertWorthy(from, to Verdict) bool {
	return from != to && (to.Bad() || (to == OK && from.Bad()))
}

// Apply returns the state after a round. Lines that no longer exist are forgotten, and lines
// the round did not cover (absent from r.Results) keep what they had.
func (st State) Apply(targets []Target, r Round, confirm int, now time.Time) State {
	next := State{LastCheckAt: now, Targets: map[int64]TargetState{}, Unsent: st.Unsent, Cursor: r.Next}
	var limited *RateLimitError
	if errors.As(r.Err, &limited) {
		next.RetryAt = now.Add(limited.Reset)
		// The refusal stopped the round partway: start the same lines again next time.
		next.Cursor = st.Cursor
	}
	for _, t := range targets {
		prev := st.Targets[t.ID]
		if prev.Host != t.Host || prev.Port != t.Port {
			prev = TargetState{Host: t.Host, Port: t.Port}
		}
		o, ok := r.Results[t.ID]
		if !ok {
			next.Targets[t.ID] = prev
			continue
		}
		cur := prev.advance(o, confirm, now)
		next.Targets[t.ID] = cur
		if alertWorthy(prev.Verdict, cur.Verdict) {
			next.Unsent = append(next.Unsent, Change{Name: t.Name, Host: t.Host, Port: t.Port, From: prev.Verdict, To: cur.Verdict})
		}
	}
	if over := len(next.Unsent) - maxUnsent; over > 0 {
		next.Unsent = next.Unsent[over:]
	}
	return next
}
