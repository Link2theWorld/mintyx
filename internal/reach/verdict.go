// Package reach checks, through Globalping probes inside and outside mainland China,
// whether the server's address and each line's port can still be reached from China.
package reach

// Verdict is the conclusion about one line after a round of probing.
type Verdict string

const (
	OK Verdict = "ok"
	// PortBlocked: the port is closed to China while probes elsewhere still reach it.
	PortBlocked Verdict = "port_blocked"
	// IPBlocked: nothing from China gets through to the address, yet probes elsewhere do.
	IPBlocked Verdict = "ip_blocked"
	// Down: probes outside China cannot reach it either, so this is not a block.
	Down    Verdict = "down"
	Unknown Verdict = "unknown"
)

// Bad reports whether the verdict means users in China cannot connect.
func (v Verdict) Bad() bool { return v == PortBlocked || v == IPBlocked || v == Down }

// Outcome is what one probe saw.
type Outcome int

const (
	// NoData covers a probe that went offline or failed for reasons unrelated to the target.
	NoData Outcome = iota
	Reached
	Unreached
)

// Reach is what one group of probes agrees on; Unsure means too few answered or they split evenly.
type Reach int

const (
	Unsure Reach = iota
	Yes
	No
)

// Quorum is how many probes of a group must report before their majority counts.
const Quorum = 2

// Tally counts the probes of one group that produced data.
type Tally struct {
	Reached  int `json:"reached"`
	Answered int `json:"answered"`
}

func (t *Tally) add(o Outcome) {
	switch o {
	case Reached:
		t.Reached++
		t.Answered++
	case Unreached:
		t.Answered++
	}
}

// Reach needs a strict majority of the probes that answered, and at least Quorum of them.
func (t Tally) Reach() Reach {
	switch missed := t.Answered - t.Reached; {
	case t.Answered < Quorum:
		return Unsure
	case t.Reached > missed:
		return Yes
	case missed > t.Reached:
		return No
	}
	return Unsure
}

// Channel is one measurement (ICMP, or TCP to one port) seen from both groups.
type Channel struct {
	China   Reach
	Control Reach
}

// Evidence is everything one round learned about a single host.
type Evidence struct {
	ICMP Channel
	TCP  map[int]Channel
	// Partial: the round skipped some of this host's ports to stay under its cap. Any one of
	// them might still get through from China, so the address cannot be called blocked.
	Partial bool
}

// channels lists ping first, then every TCP port.
func (ev Evidence) channels() []Channel {
	out := []Channel{ev.ICMP}
	for _, c := range ev.TCP {
		out = append(out, c)
	}
	return out
}

// chinaReachesIP is Yes when any channel gets through from China. No takes more than one
// closed port, because single ports do get blocked: either ping is closed too, or two ports are.
func (ev Evidence) chinaReachesIP() Reach {
	closed, pingClosed, inconclusive := 0, false, false
	for i, c := range ev.channels() {
		switch {
		case c.China == Yes:
			return Yes
		case c.Control == No:
			// Nobody gets through here (e.g. the server drops ping), so it says nothing about China.
		case c.Control == Yes && c.China == No:
			closed++
			pingClosed = pingClosed || i == 0
		default:
			inconclusive = true
		}
	}
	if !inconclusive && !ev.Partial && (pingClosed || closed >= 2) {
		return No
	}
	return Unsure
}

// deadEverywhere needs a TCP port to say so: many servers drop ping on purpose.
func (ev Evidence) deadEverywhere() bool {
	if len(ev.TCP) == 0 || ev.ICMP.Control == Yes {
		return false
	}
	for _, c := range ev.TCP {
		if c.Control != No {
			return false
		}
	}
	return true
}

// Judge decides the verdict for a TCP port on the host, or for the address alone when port is 0.
func Judge(ev Evidence, port int) Verdict {
	if port == 0 {
		switch ev.chinaReachesIP() {
		case Yes:
			return OK
		case No:
			return IPBlocked
		}
		if ev.deadEverywhere() {
			return Down
		}
		return Unknown
	}
	c, measured := ev.TCP[port]
	switch {
	case !measured || c.China == Unsure:
		return Unknown
	case c.China == Yes:
		return OK
	case c.Control == No:
		return Down
	case c.Control == Unsure:
		return Unknown
	}
	// The port is proven closed to China; without proof the whole address is, blame the port.
	if ev.chinaReachesIP() == No {
		return IPBlocked
	}
	return PortBlocked
}
