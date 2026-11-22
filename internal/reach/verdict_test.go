package reach

import "testing"

func TestTallyReach(t *testing.T) {
	for _, tc := range []struct {
		name string
		t    Tally
		want Reach
	}{
		{"all reach", Tally{Reached: 5, Answered: 5}, Yes},
		{"none reach", Tally{Reached: 0, Answered: 5}, No},
		{"bare majority reaches", Tally{Reached: 3, Answered: 5}, Yes},
		{"bare majority fails", Tally{Reached: 2, Answered: 5}, No},
		{"even split is no agreement", Tally{Reached: 2, Answered: 4}, Unsure},
		{"one probe is below quorum even when it fails", Tally{Reached: 0, Answered: 1}, Unsure},
		{"one probe is below quorum even when it reaches", Tally{Reached: 1, Answered: 1}, Unsure},
		{"two agreeing probes are enough", Tally{Reached: 0, Answered: 2}, No},
		{"nobody answered", Tally{}, Unsure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.t.Reach(); got != tc.want {
				t.Errorf("%+v.Reach() = %v, want %v", tc.t, got, tc.want)
			}
		})
	}
}

func TestTallyIgnoresProbesWithoutData(t *testing.T) {
	var got Tally
	for _, o := range []Outcome{Reached, NoData, Unreached, NoData, Reached} {
		got.add(o)
	}
	if want := (Tally{Reached: 2, Answered: 3}); got != want {
		t.Errorf("tally = %+v, want %+v", got, want)
	}
}

func TestJudge(t *testing.T) {
	var (
		open     = Channel{China: Yes, Control: Yes}
		blocked  = Channel{China: No, Control: Yes}
		dead     = Channel{China: No, Control: No}
		noChina  = Channel{China: Unsure, Control: Yes}
		noCtrl   = Channel{China: No, Control: Unsure}
		onlyCN   = Channel{China: Yes, Control: No}
		silent   = Channel{}
		tcp      = func(m map[int]Channel) map[int]Channel { return m }
		port443  = 443
		portNone = 0
	)
	for _, tc := range []struct {
		name string
		ev   Evidence
		port int
		want Verdict
	}{
		{"port and ping both fine", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: open})}, port443, OK},
		{"china reaches the port though the server ignores ping", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: open})}, port443, OK},
		{"china reaches the port even if the control probes do not", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: onlyCN})}, port443, OK},

		{"port closed to china, ping still answers", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: blocked})}, port443, PortBlocked},
		{"port closed to china, another port still open", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked, 8443: open})}, port443, PortBlocked},
		{"port closed to china, ping from china inconclusive", Evidence{ICMP: noChina, TCP: tcp(map[int]Channel{443: blocked})}, port443, PortBlocked},

		{"port and ping both closed to china only", Evidence{ICMP: blocked, TCP: tcp(map[int]Channel{443: blocked})}, port443, IPBlocked},
		{"every port closed to china, server ignores ping", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked, 8443: blocked})}, port443, IPBlocked},
		{"one closed port alone cannot condemn the address when the server ignores ping", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked})}, port443, PortBlocked},
		{"ping measurement missing: a closed port is only a closed port", Evidence{ICMP: silent, TCP: tcp(map[int]Channel{443: blocked})}, port443, PortBlocked},
		{"ping measurement missing even with two closed ports", Evidence{ICMP: silent, TCP: tcp(map[int]Channel{443: blocked, 8443: blocked})}, port443, PortBlocked},

		{"nobody reaches the port", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: dead})}, port443, Down},
		{"nobody reaches anything", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: dead})}, port443, Down},
		{"service down wins over a simultaneous ip block", Evidence{ICMP: blocked, TCP: tcp(map[int]Channel{443: dead})}, port443, Down},

		{"too few china probes on the port", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: noChina})}, port443, Unknown},
		{"too few control probes cannot tell block from outage", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: noCtrl})}, port443, Unknown},
		{"port was never measured", Evidence{ICMP: open, TCP: tcp(map[int]Channel{8443: open})}, port443, Unknown},
		{"no evidence at all", Evidence{}, port443, Unknown},

		{"udp line: ping answers from china", Evidence{ICMP: open}, portNone, OK},
		{"udp line: ping ignored but a tcp port proves the address open", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: open})}, portNone, OK},
		{"udp line: ping closed to china only", Evidence{ICMP: blocked}, portNone, IPBlocked},
		{"udp line: ping and every tcp port closed to china only", Evidence{ICMP: blocked, TCP: tcp(map[int]Channel{443: blocked})}, portNone, IPBlocked},
		{"udp line: one channel still inconclusive", Evidence{ICMP: noChina, TCP: tcp(map[int]Channel{443: blocked})}, portNone, Unknown},
		{"udp line: ping measurement missing, one tcp port closed", Evidence{ICMP: silent, TCP: tcp(map[int]Channel{443: blocked})}, portNone, Unknown},
		{"udp line: server ignores ping, its one tcp port closed to china", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked})}, portNone, Unknown},
		{"udp line: server ignores ping, both tcp ports closed to china", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked, 8443: blocked})}, portNone, IPBlocked},
		{"udp line: unanswered ping alone may just be a firewall", Evidence{ICMP: dead}, portNone, Unknown},
		{"udp line: ping and every tcp port dead everywhere", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: dead})}, portNone, Down},
		{"udp line: tcp dead but ping answers from china", Evidence{ICMP: open, TCP: tcp(map[int]Channel{443: dead})}, portNone, OK},
		{"udp line: nothing measured", Evidence{ICMP: silent}, portNone, Unknown},

		{"partial round: a skipped port may be open, so blame the port", Evidence{ICMP: blocked, TCP: tcp(map[int]Channel{443: blocked}), Partial: true}, port443, PortBlocked},
		{"partial round: two closed ports are still not the whole address", Evidence{ICMP: dead, TCP: tcp(map[int]Channel{443: blocked, 8443: blocked}), Partial: true}, port443, PortBlocked},
		{"partial round: an open channel still proves the address open", Evidence{ICMP: blocked, TCP: tcp(map[int]Channel{443: open}), Partial: true}, portNone, OK},
		{"partial round: udp line cannot be called blocked", Evidence{ICMP: blocked, Partial: true}, portNone, Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Judge(tc.ev, tc.port); got != tc.want {
				t.Errorf("Judge = %q, want %q", got, tc.want)
			}
		})
	}
}
